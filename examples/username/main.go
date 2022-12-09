//go:build windows
// +build windows

package main

/*
#include <windows.h>

extern void goPayloadFunc(LPWSTR lpBuffer, LPDWORD pcbBuffer);
typedef BOOL GETUSERNAMEW(LPWSTR lpBuffer, LPDWORD pcbBuffer);
GETUSERNAMEW *trampoline = NULL;

BOOL GetUsernameGateway(LPWSTR lpBuffer, LPDWORD pcbBuffer)
{
	BOOL success;
	success = trampoline(lpBuffer,pcbBuffer);
	goPayloadFunc(lpBuffer,pcbBuffer);
	return success;
}
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"

	"github.com/stavinski/winhook"
	"golang.org/x/sys/windows"
)

func main() {
	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procGetUserNameW := modadvapi32.NewProc("GetUserNameW")

	// install hook to GetUserNameW here
	// winhook.DebugEnabled = true
	trampolineFunc, err := winhook.InstallHook64(procGetUserNameW.Addr(), uintptr(unsafe.Pointer(C.GetUsernameGateway)), 7)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not install hook: %q", err)
		return
	}
	C.trampoline = (*C.GETUSERNAMEW)(unsafe.Pointer(trampolineFunc))
	buf := make([]uint16, 255, 255)
	len := uint32(255)

	res, _, err := procGetUserNameW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&len)))
	if res == 0 {
		fmt.Fprintf(os.Stderr, "could get username: %q", err)
		return
	}

	fmt.Printf("username: %v, len: %v\n", windows.UTF16ToString(buf), len)
	fmt.Print("Press Enter to exit")
	fmt.Scanln()
}
