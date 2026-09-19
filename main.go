package main

import (
	"ebpf/loader"
	_ "embed"
	"fmt"
)

// int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

//go:embed ebpf/program.o
var Object []byte

func main() {
	// reader := bytes.NewReader(ebpf.Program)
	// elfFile, err := elf.NewFile(reader)
	// if err != nil {
	// 	panic(err.Error())
	// }
	//
	// for _, sec := range elfFile.Sections {
	// 	fmt.Println("section", sec.Name, "of size", sec.Size)
	// }
	//
	// section := elfFile.Section("tc")
	// program, err := section.Data()
	// if err != nil {
	// 	panic(err.Error())
	// }
	//
	// fmt.Println(program)

	progFd, err := loader.LoadProgram("GPL", Object)
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
