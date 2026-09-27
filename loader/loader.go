// Package ebpf is package
package loader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
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

type Override struct {
	c C.global_override
}

func OverrideInt(name string, i int) Override {
	override := C.global_override{
		name:      (*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		name_size: C.uint32_t(len(name)),
		kind:      2,
	}
	binary.NativeEndian.PutUint32(override.value[:], uint32(i))
	return Override{override}
}

func OverrideString(name string, val string) Override {
	override := C.global_override{
		name:      (*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		name_size: C.uint32_t(len(name)),
		kind:      1,
	}
	cstr := C.CString(val)
	binary.NativeEndian.PutUint64(override.value[:], uint64(uintptr(unsafe.Pointer(cstr))))
	return Override{override}
}

func OverrideBool(name string, val bool) Override {
	override := C.global_override{
		name:      (*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		name_size: C.uint32_t(len(name)),
		kind:      3,
	}
	if val {
		override.value[0] = 1
	} else {
		override.value[0] = 0
	}
	return Override{override}
}

func OverrideMemory(name string, val []byte) Override {
	override := C.global_override{
		name:      (*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		name_size: C.uint32_t(len(name)),
		kind:      4,
	}
	memory := C.malloc(C.size_t(len(val)))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(memory)), len(val)), val)

	binary.NativeEndian.PutUint64(override.value[:], uint64(uintptr(unsafe.Pointer(memory))))
	binary.NativeEndian.PutUint64(override.value[8:], uint64(len(val)))
	return Override{override}
}

func OverrideMap(name string, mapFd int) Override {
	override := C.global_override{
		name:      (*C.char)(unsafe.Pointer(unsafe.StringData(name))),
		name_size: C.uint32_t(len(name)),
		kind:      5,
	}
	binary.NativeEndian.PutUint32(override.value[:], uint32(mapFd))
	return Override{override}
}

func LoadProgram(license string, elfFile []byte, programType int, overrides ...Override) (ProgramFd, error) {
	sectionCstr := C.CString("tc")
	defer C.free(unsafe.Pointer(sectionCstr))

	cstr := C.CString(license)
	defer C.free(unsafe.Pointer(cstr))

	elfFileContent := unsafe.SliceData(elfFile)
	elfFileContentSize := len(elfFile)

	var program unsafe.Pointer
	var programSize C.uint32_t
	var coverrides = (*C.global_override)(unsafe.Pointer(unsafe.SliceData(overrides)))

	cErr := C.loader_link_program(unsafe.Pointer(elfFileContent), C.size_t(elfFileContentSize), sectionCstr, &program, &programSize, coverrides, C.size_t(len(overrides)))
	if cErr != nil {
		cErrLen := C.strlen(cErr)
		return 0, fmt.Errorf("could not link the program: %s (%s)", unsafe.String((*byte)(unsafe.Pointer(cErr)), int(cErrLen)), getLastError())
	}

	runtime.KeepAlive(overrides)

	fd := C.loader_load_bpf_program(cstr, program, programSize, C.int(programType))
	if fd == -1 {
		return 0, fmt.Errorf("bad ebpf program, could not load: %s", getLastError())
	}

	return ProgramFd(fd), nil
}

func PinObject(fd int, path string) error {
	cstr := C.CString(path)
	defer C.free(unsafe.Pointer(cstr))

	err := C.loader_pin_object(C.int(fd), cstr)
	if err == -1 {
		return fmt.Errorf("could not pin the object object: %s", C.loader_last_error())
	}

	return nil
}

func GetPinnedObject(path string) (fd int, err error) {
	cstr := C.CString(path)
	defer C.free(unsafe.Pointer(cstr))

	cFd := C.loader_get_pinned_object(cstr)
	if cFd < 0 {
		return 0, fmt.Errorf("could not get the pinned object: %s", C.GoString(C.strerror(-C.int(cFd))))
	}

	return int(cFd), nil
}

func CreateAndPinOrGet(pinPath string, f func() (int, error)) (int, error) {
	_, err := os.Stat(pinPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		fd, err := f()
		if err != nil {
			return 0, err
		}
		err = PinObject(fd, pinPath)
		if err != nil {
			return 0, err
		}
		return fd, nil
	} else if err != nil {
		return 0, err
	} else {
		fd, err := GetPinnedObject(pinPath)
		if err != nil {
			return 0, err
		}
		return fd, nil
	}
}

func AttachProgramToInterface(progFd ProgramFd, interfaceName string, attachType int) (LinkFd, error) {
	cstr := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(cstr))

	link := C.loader_attach_program(C.int(progFd), cstr, C.int(attachType))
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
