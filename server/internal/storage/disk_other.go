//go:build !windows

package storage

import (
	"syscall"
)

func getDiskSpace(dir string) (freeBytes, totalBytes uint64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, 0, err
	}
	// Available blocks * size per block
	freeBytes = stat.Bavail * uint64(stat.Bsize)
	totalBytes = stat.Blocks * uint64(stat.Bsize)
	return freeBytes, totalBytes, nil
}
