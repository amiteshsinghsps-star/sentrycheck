// A real cilium/ebpf program-load attempt. The portable scanner intentionally
// grants no capabilities; a failed native load is not sandbox incompatibility.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func main() {
	required := flag.Bool("require-load", false, "Require successful BPF_PROG_LOAD; native failure makes the experiment incomplete")
	flag.Parse()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "sentrycheck", Type: ebpf.SocketFilter, License: "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "cilium/ebpf load attempt:", err)
		if *required { os.Exit(42) }
	} else if err = program.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(70)
	}
	fmt.Println("sentrycheck-ebpf-probe-complete")
}
