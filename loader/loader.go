// Package ebpf is package
package loader

import (
	"fmt"
	"unsafe"
)

// #include "loader.h"
// #include <stdlib.h>
// #include <unistd.h>
// #include <errno.h>
// #include <string.h>
import "C"

type ProgramFd int
type LinkFd int

func LoadProgram(license string, elfFile []byte) (ProgramFd, error) {
	sectionCstr := C.CString("tc")
	defer C.free(unsafe.Pointer(sectionCstr))

	cstr := C.CString(license)
	defer C.free(unsafe.Pointer(cstr))

	elfFileContent := unsafe.SliceData(elfFile)
	elfFileContentSize := len(elfFile)

	var program unsafe.Pointer
	var programSize C.uint32_t
	cErr := C.loader_link_program(unsafe.Pointer(elfFileContent), C.size_t(elfFileContentSize), sectionCstr, &program, &programSize)
	if cErr != nil {
		cErrLen := C.strlen(cErr)
		return 0, fmt.Errorf("could not link the program: %s (%s)", unsafe.String((*byte)(unsafe.Pointer(cErr)), int(cErrLen)), getLastError())
	}

	fd := C.loader_load_bpf_program(cstr, program, programSize)
	if fd == -1 {
		return 0, fmt.Errorf("bad ebpf program, could not load: %s", getLastError())
	}

	return ProgramFd(fd), nil
}

func AttachProgramToInterface(progFd ProgramFd, interfaceName string) (LinkFd, error) {
	cstr := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(cstr))

	link := C.loader_attach_program(C.int(progFd), cstr)
	if link == -1 {
		return 0, fmt.Errorf("bad ebpf program, could not attach: %s", getLastError())
	}

	return LinkFd(link), nil
}

func Close[F ProgramFd | LinkFd](fd F) {
	C.close(C.int(fd))
}

func getLastError() string {
	cstr := C.loader_last_error()
	cstrLen := C.strlen(cstr)

	return unsafe.String((*byte)(unsafe.Pointer(cstr)), int(cstrLen))
}
