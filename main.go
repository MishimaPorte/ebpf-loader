package main

import (
	"bytes"
	"debug/elf"
	"ebpf/ebpf"
	"fmt"
)

// int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

func main() {
	reader := bytes.NewReader(ebpf.Program)
	elfFile, err := elf.NewFile(reader)
	if err != nil {
		panic(err.Error())
	}

	for _, sec := range elfFile.Sections {
		fmt.Println("section", sec.Name, "of size", sec.Size)
	}

	section := elfFile.Section("tc")
	program, err := section.Data()
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(program)

	fd, err := ebpf.LoadProgram("GPL", program)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(fd)

	// syscall.Syscall(syscall.BPF_A)
	// fmt.Printf("Hello, World, %+v\n", ebpf.Program)
}
