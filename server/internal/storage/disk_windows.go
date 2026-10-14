//go:build windows

package storage

import (
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
)

func getDiskSpace(dir string) (freeBytes, totalBytes uint64, err error) {
	dirPtr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}

	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes int64
	r1, _, errSys := getDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	if r1 == 0 {
		return 0, 0, errSys
	}
	return uint64(freeBytesAvailable), uint64(totalNumberOfBytes), nil
}
