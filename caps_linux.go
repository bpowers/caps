package caps

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	LINUX_CAPABILITY_VERSION_3 = 0x20080522
	LINUX_CAPABILITY_U32S_3    = 2
)

type Capability int

const (
	CapChown Capability = iota
	CapDacOverride
	CapDacReadSearch
	CapFowner
	CapFsetid
	CapKill
	CapSetgid
	CapSetuid
	CapSetpcap
	CapLinuxImmutable
	CapNetBindService
	CapNetBroadcast
	CapNetAdmin
	CapNetRaw
	CapIPCLock
	CapIPCOwner
	CapSysModule
	CapSysRawIO
	CapSysChroot
	CapSysPtrace
	CapSysPacct
	CapSysAdmin
	CapSysBoot
	CapSysNice
	CapSysResource
	CapSysTime
	CapSysTTYConfig
	CapMknod
	CapLease
	CapAuditWrite
	CapAuditControl
	CapSetfcap
	CapMACOverride
	CapMACAdmin
	CapSyslog
	CapWakeAlarm
	CapBlockSuspend
)

var (
	CapMin Capability = 0
	CapMax Capability // determined on process init
)

func init() {
	capMax, err := lastCap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: lastCap: %s\n", err)
		return
	}
	CapMax = Capability(capMax)
}

type capHeader struct {
	Version uint32
	Pid     int32
}

type capData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

type Cap struct {
	Header capHeader
	Data   [LINUX_CAPABILITY_U32S_3]capData
}

// DropRoot is a convienence function around DropRootTo, calling
// caps.Lookup on the username provided, and passing the result to
// DropRootTo.
func DropRoot(username string) (err error) {
	var u *user.User
	if u, err = Lookup(username); err != nil {
		return
	}

	return DropRootTo(u)
}

// DropRootTo calls setresgid(2) and setresuid(2) to permenently
// revoke root privileges.  The USER, LOGNAME and HOME environmental
// variables are updated to match.
func DropRootTo(u *user.User) (err error) {
	var uid, gid int
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return
	}

	if err = syscall.Setresgid(gid, gid, gid); err != nil {
		return
	}
	if err = syscall.Setresuid(uid, uid, uid); err != nil {
		return
	}

	// based on what Avahi does.
	os.Setenv("USER", u.Name)
	os.Setenv("LOGNAME", u.Name)
	os.Setenv("HOME", u.HomeDir)

	return nil
}

// gets the capabilities of the current process
func capget(pid int) (*Cap, error) {
	caps := new(Cap)
	caps.Header.Version = LINUX_CAPABILITY_VERSION_3
	caps.Header.Pid = int32(pid)

	_, _, e1 := syscall.Syscall(syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&caps.Header)),
		uintptr(unsafe.Pointer(&caps.Data[0])),
		0)
	if e1 != 0 {
		return nil, e1
	}
	return caps, nil
}

func capset(caps ...int) (err error) {
	var capabilities Cap
	capabilities.Header.Version = LINUX_CAPABILITY_VERSION_3
	capabilities.Header.Pid = int32(os.Getpid())

	// TODO: actually support anything except dropping all caps.

	_, _, e1 := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&capabilities.Header)),
		uintptr(unsafe.Pointer(&capabilities.Data[0])),
		0)
	if e1 != 0 {
		err = e1
	}
	return
}

// prctl(2) syscall
func prctl(option, arg2, arg3, arg4, arg5 int) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_PRCTL,
		uintptr(option),
		uintptr(arg2),
		uintptr(arg3),
		uintptr(arg4),
		uintptr(arg5),
		uintptr(0))
	if e1 != 0 {
		err = e1
	}
	return
}

// lastCap returns the integer corresponding to the highest known
// capability on this system.
func lastCap() (last int, err error) {
	// contains a single integer followed by a newline
	f, err := os.Open("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return
	}
	defer f.Close()
	buf := make([]byte, 16)
	l, err := f.Read(buf)
	if err != nil {
		return
	}
	if l >= 16 {
		return 0, fmt.Errorf("cap_last_cap too long: %d", l)
	}
	return strconv.Atoi(strings.TrimSpace(string(buf[:l])))
}

// drop a capability from the current processes bounding set
func BoundingSetDrop(c Capability) error {
	if err := prctl(syscall.PR_CAPBSET_DROP, int(c), 0, 0, 0); err != nil {
		return err
	}
	return nil
}

func BoundingSetEmpty() (err error) {
	// don't bother trying to empty the capability bounding set if
	// we're not root, as we won't have the permissions.

	// FIXME: instead of checking for root, we should be checking
	// for the permission
	if syscall.Geteuid() != 0 {
		return
	}
	for i := CapMin; i <= CapMax; i++ {
		BoundingSetDrop(i)
	}
	return nil
}

func DropAllCapabilities() error {
	 return capset()
}
