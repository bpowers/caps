package caps

import (
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
	if err = syscall.Chroot("/"); err != nil {
		return
	}
	return
}