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
func goPayloadFunc(username C.LPWSTR, usernameLen C.LPDWORD) {
	// make up a username and place into the username buffer
	// a more complete version would check the buffer size is big enough
	usr, _ := windows.UTF16FromString("johndoe")
	*usernameLen = C.ulong(len(usr)) // includes the null
	charUsername := *((*[]uint16)(unsafe.Pointer(&username)))
	copy(charUsername, usr)
}
