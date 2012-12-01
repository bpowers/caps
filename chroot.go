package caps

import (
	"fmt"
	"os"
	"path"
	"syscall"
)

// EnterChroot changes the current directory to the path specified,
// and then calls chroot(2) with the same path.  This must be called
// while the process has CAP_SYS_CHROOT.
func EnterChroot(path string) (err error) {
	if err = syscall.Chdir(path); err != nil {
		return
	}
	if err = syscall.Chroot(path); err != nil {
		return
	}
	if err = syscall.Chdir("/"); err != nil {
		return
	}
	return
}

// SetupChroot bind mounts /proc, /dev into the chroot specified at
// newRoot.  In addition /etc/resolv.conf is hard-linked into
// newRoot/etc/resolv.conf.  Because it is hard linked, the chroot has
// to be on the same partition as /etc.  This is simply an
// implementation detail that will be fixed eventually.
// newRoot/{proc,dev,etc} are assumed to exist.
func SetupChroot(newRoot string) error {
	// os.Hostname() and various other go internals require access
	// to the /proc pseudo-filesystem.
	//
	// XXX: this will only mount /proc, not any sub-mounts like
	// binfmt_misc or selinux.  If we wanted that we would need to
	// or syscall.MS_REC to MS_BIND in flags.
	err := syscall.Mount("/proc", path.Join(newRoot, "proc"), "",
		syscall.MS_BIND, "")
	if err != nil {
		return err
	}
	err = syscall.Mount("/dev", path.Join(newRoot, "dev"), "",
		syscall.MS_BIND, "")
	if err != nil {
		return err
	}
	err = os.Link("/etc/resolv.conf", path.Join(newRoot, "etc", "resolv.conf"))
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// DropRootAndChroot chroots to the path specified in newRoot, and
// changes the real, effective and saved user IDs to the given user.
// In addition, SetupChroot is called to ensure that several files and
// pseudo-filesystems are bind mounted/hard-linked into the chroot, as
// necessitated by the go runtime.
//
// FIXME: drop root won't fully work until this bug is closed:
// http://code.google.com/p/go/issues/detail?id=1435
func DropRootAndChroot(newRoot, user string) error {
	u, err := Lookup(user)
	if err != nil {
		return fmt.Errorf("EtcPasswdLookup(%s): %s", user, err)
	}

	if err = BoundingSetEmpty(); err != nil {
		return fmt.Errorf("BoundingSetEmpty: %s", err)
	}
	if newRoot != "" {
		if err = SetupChroot(newRoot); err != nil {
			return err
		}
		if err = EnterChroot(newRoot); err != nil {
			return fmt.Errorf("EnterChroot(%s): %s", newRoot, err)
		}
	}
	// XXX: this won't work completely until
	// http://code.google.com/p/go/issues/detail?id=1435 is
	// fixed.
	if err = DropRootTo(u); err != nil {
		return fmt.Errorf("DropRootTo(%v): %s", u, err)
	}
	return nil
}
