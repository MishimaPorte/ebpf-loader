// Package ebpf is package
package ebpf

import (
	_ "embed"
	"fmt"
	"unsafe"
)

// #include "loader.h"
// #include <stdlib.h>
import "C"

//go:embed program.o
var Program []byte

type EbpfFD int

func LoadProgram(license string, program []byte) (EbpfFD, error) {
	cstr := C.CString(license)
	defer C.free(unsafe.Pointer(cstr))

	fd := C.load_bpf_program(cstr, unsafe.Pointer(unsafe.SliceData(program)), C.uint(len(program)/8))
	if fd == -1 {
		return 0, fmt.Errorf("bad ebpf program, could not load")
	}

	return EbpfFD(fd), nil
}
