//go:build windows
// +build windows

package main

//#include <windows.h>
import "C"
import (
	"unsafe"

	"github.com/nanitefactory/winmb"
	"golang.org/x/sys/windows"
)

//export goPayloadFunc
func goPayloadFunc(filename C.LPCWSTR) {
	fn := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(filename)))
	winmb.MessageBoxPlain("File deleted", fn)
}
