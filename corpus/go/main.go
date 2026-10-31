package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

func main() {
	directory, err := os.MkdirTemp("", "sentrycheck-go-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(directory)
	data := []byte("sentrycheck")
	path := filepath.Join(directory, "data")
	if err = os.WriteFile(path, data, 0600); err != nil {
		panic(err)
	}
	loaded, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(loaded) != sha256.Sum256(data) {
		panic("filesystem assertion failed")
	}
	var wait sync.WaitGroup
	var results [8]int
	for i := range results {
		wait.Add(1)
		go func(i int) { defer wait.Done(); results[i] = i * i }(i)
	}
	wait.Wait()
	for i, result := range results {
		if result != i*i {
			panic("goroutine assertion failed")
		}
	}
	fmt.Println("sentrycheck-go-ok")
}
