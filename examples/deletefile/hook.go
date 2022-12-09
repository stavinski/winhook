//go:build windows
// +build windows

package main

//#include <windows.h>
import "C"
import (
	"unsafe"

	"golang.org/x/sys/windows"
)

//export goPayloadFunc
func goPayloadFunc(filename C.LPCWSTR) {
	cap, _ := windows.UTF16PtrFromString("File Deleted")
	windows.MessageBox(0, (*uint16)(unsafe.Pointer(filename)), cap, 0)
}
