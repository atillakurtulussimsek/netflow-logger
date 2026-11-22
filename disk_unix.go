//go:build unix

package main

import "syscall"

// diskUsage, path'in bulunduğu dosya sisteminin toplam ve boş alanını döndürür.
func diskUsage(path string) (total, free uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	bsize := uint64(st.Bsize)
	return st.Blocks * bsize, st.Bavail * bsize, true
}
