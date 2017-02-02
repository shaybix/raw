// +build windows

package raw

import (
	"fmt"
	"syscall"
	"unsafe"
)

var procSetsockopt = ws232.NewProc("setsockopt")

func setsockopt(fd syscall.Handle, level, name int, v unsafe.Pointer, l uint32) error {

	errno, _, _ := procSetsockopt.Call(
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(v),
		uintptr(l))

	if errno != 0 {
		return fmt.Errorf("")
	}
	return nil
}
