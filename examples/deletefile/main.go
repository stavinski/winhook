//go:build windows
// +build windows

package main

/*
#include <windows.h>

extern void goPayloadFunc(LPCWSTR lpFilename);
typedef BOOL DELETEFILE(LPCWSTR lpFilename);
DELETEFILE *trampoline = NULL;

BOOL DeleteFileGateway(LPCWSTR lpFilename)
{
	goPayloadFunc(lpFilename);
	return trampoline(lpFilename);
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
	modKernel32 := windows.NewLazySystemDLL("kernelbase.dll")
	procDeleteFileW := modKernel32.NewProc("DeleteFileW")

	// install hook to DeleteFileW here
	// winhook.DebugEnabled = true
	trampolineFunc, err := winhook.InstallHook64(procDeleteFileW.Addr()+5, uintptr(unsafe.Pointer(C.DeleteFileGateway)), 6)
	C.trampoline = (*C.DELETEFILE)(unsafe.Pointer(trampolineFunc))

	f, err := os.Create("foo.txt")
	if err != nil {
		fmt.Printf("Error creating file: %q", err)
		return
	}
	f.WriteString("foo")
	err = f.Close()
	if err != nil {
		fmt.Printf("Error closing file: %q", err)
		return
	}

	err = os.Remove(f.Name())
	if err != nil {
		fmt.Printf("Error removing file: %q", err)
		return
	}

	fmt.Print("Press Enter to exit")
	fmt.Scanln()
}
