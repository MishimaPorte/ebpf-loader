package main

import (
	_ "embed"
	"fmt"

	"github.com/MishimaPorte/ebpf-loader/loader"
)

// int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

//go:embed ebpf/program.o
var ObjectFile []byte

func main() {

	progFd, err := loader.LoadProgram(
		"GPL", ObjectFile,
		loader.OverrideInt("print_value", 10),
		loader.OverrideString("print_string", "kek"),
	)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("loaded the program: %d\n", progFd)

	linkFd, err := loader.AttachProgramToInterface(progFd, "lo")
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("attached the program: %d\n", linkFd)

	loader.Close(progFd)
	fmt.Println("closing the program reference")

	select {}

	// syscall.Syscall(syscall.BPF_A)
	// fmt.Printf("Hello, World, %+v\n", ebpf.Program)
}
