//go:build !unix

package main

func diskUsage(string) (total, free uint64, ok bool) { return 0, 0, false }
