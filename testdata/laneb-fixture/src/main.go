// Package main is planted for Lane B's fixture. Never built.
package main

import (
	"os"
	"os/exec"
)

type runner struct{}

func (runner) run(name string) error {
	return exec.Command("sh", "-c", name).Run()
}

func main() {
	_ = runner{}.run(os.Args[1])
}
