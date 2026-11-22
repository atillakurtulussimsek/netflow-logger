package main

import (
	"os"
	"path/filepath"
)

// DiskStatus, log dizininin bulunduğu diskin doluluğunu ve log dizininin
// (tüm dosyalarıyla) kapladığı alanı gösterir.
type DiskStatus struct {
	Total        uint64 `json:"total"`
	Free         uint64 `json:"free"`
	Used         uint64 `json:"used"`
	LogRootBytes int64  `json:"log_root_bytes"`
}

func buildDiskStatus(logRoot string) *DiskStatus {
	st := &DiskStatus{LogRootBytes: dirSize(logRoot)}
	if total, free, ok := diskUsage(logRoot); ok {
		st.Total, st.Free = total, free
		if total > free {
			st.Used = total - free
		}
	}
	return st
}

// dirSize, dizindeki tüm dosyaların toplam boyutudur (yalnız .log değil).
func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
