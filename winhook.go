//go:build windows
// +build windows

// Hooking library for windows, can be used to divert calls made to functions in executables/DLLs at runtime
//
// To use you must know the address to hook and also the signature of the function.
//
// A C function should then be declared with the matching sigature, for example:
//
// extern HANDLE goPayloadFunc(DWORD, HANDLE);
//
// HANDLE HookSetClipboard(DWORD uFormat, HANDLE hMem)
//
//	{
//			goPayloadFunc(uFormat, hMem);
//			return trampoline(uFormat, hMem);
//	}
//
// The goPayloadFunc should be an exported Go func:
//
// //export goPayloadFunc
//
//	func goPayloadFunc(uFormat C.DWORD, hMem C.HANDLE) {
//			// do stuff...
//		}
//
// The trampoline should be a declared C pointer that also matches the signature of the hooked function:
//
// typedef HANDLE SETCLIPBOARDDATA(DWORD, HANDLE);
//
// SETCLIPBOARDDATA *trampoline = NULL;
//
// When the call to InstallHook is made the returned uintptr should then be casted back to the trampoline variable:
//
// trampolineFunc, err := winhook.InstallHook64(hookAddr, uintptr(C.HookSetClipboard), 5)
// // handle err
//
// C.trampoline = (*C.SETCLIPBOARDDATA)(unsafe.Pointer(trampolineFunc))
package winhook

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/nanitefactory/winmb"
	"golang.org/x/sys/windows"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go syscall_windows.go

const (
	MIN_STEAL_LEN         = 5
	MAX_STEAL_LEN         = 32
	x64_ABS_JMP_INSTR_LEN = 13
	x64_REL_JMP_INSTR_LEN = 5
)

// Enable to help with diagnosing issues, writes debug info in messageboxes
var DebugEnabled = false

// write to messagebox if DebugEnabled is turned on
func writeDebug(val string) {
	if DebugEnabled {
		winmb.MessageBoxPlain("~~Winhook Debug~~", val)
	}
}

// Find min of two uint64
func minUint64(fst, snd uint64) uint64 {
	if fst < snd {
		return fst
	}
	return snd
}

// Find max of two uint64
func maxUint64(fst, snd uint64) uint64 {
	return minUint64(snd, fst)
}

// Finds and allocates a memory page close to the provided targetAddr
func allocatePageNearAddress(targetAddr uintptr) (uintptr, error) {
	info := LPSYSTEM_INFO{}
	GetSystemInfo(&info)
	pageSize := uint64(info.dwPageSize)

	startAddr := uint64(targetAddr) & ^(pageSize - 1) //round down to nearest page boundary
	minAddr := minUint64(startAddr-0x7FFFFF00, uint64(info.lpMinimumApplicationAddress))
	maxAddr := maxUint64(startAddr+0x7FFFFF00, uint64(info.lpMaximumApplicationAddress))
	startPage := (startAddr - (startAddr % pageSize))

	writeDebug(fmt.Sprintf("startAddr: 0x%x", startAddr))
	writeDebug(fmt.Sprintf("minAddr: 0x%x", minAddr))
	writeDebug(fmt.Sprintf("maxAddr: 0x%x", maxAddr))
	writeDebug(fmt.Sprintf("startPage 0x%x", startPage))

	var byteOffset, highAddr, lowAddr uint64
	needsExit := false

	for pageOffset := uint64(1); ; pageOffset++ {
		byteOffset = pageOffset * pageSize
		highAddr = startPage + byteOffset
		if startPage > byteOffset {
			lowAddr = uint64(startPage) - byteOffset
		} else {
			lowAddr = 0
		}

		needsExit = highAddr > maxAddr && lowAddr < minAddr

		if highAddr < maxAddr {
			outAddr, _ := windows.VirtualAlloc(uintptr(highAddr), uintptr(pageSize), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
			if outAddr != 0 {
				return outAddr, nil
			}
		}

		if lowAddr > minAddr {
			outAddr, _ := windows.VirtualAlloc(uintptr(lowAddr), uintptr(pageSize), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
			if outAddr != 0 {
				return outAddr, nil
			}
		}

		if needsExit {
			break
		}
	}

	return uintptr(0), errors.New("could not allocate a page near the target address provided")
}

// Write an x64 abs jmp instruction to an address
func writeAbsJmp64(writeAddr, jmpToAddr uintptr) error {
	var bytesWritten uintptr
	x64JmpInstr := []byte{
		0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into r10
		0x41, 0xFF, 0xE2, //jmp r10
	}
	// place the to addr bytes after the movabs abs instruction
	binary.LittleEndian.PutUint64(x64JmpInstr[2:], uint64(jmpToAddr))
	writeDebug(fmt.Sprintf("x64 abs instructions: %v", x64JmpInstr))
	// write the jmp instructions into the writeAddr
	return windows.WriteProcessMemory(windows.CurrentProcess(), writeAddr, &x64JmpInstr[0], uintptr(len(x64JmpInstr)), &bytesWritten)
}

// Create the relay func to be jumped to first from the hookedFunc, will then jump to the absolute address of the payloadFunc
func createRelayFunc(hookedFunc, payloadFunc uintptr) (uintptr, error) {
	// allocate an address near the hook func
	relayFunc, err := allocatePageNearAddress(hookedFunc)
	if err != nil {
		return uintptr(0), err
	}
	// write a jmp instruction to the payload func in there
	if err := writeAbsJmp64(relayFunc, payloadFunc); err != nil {
		return uintptr(0), err
	}
	return relayFunc, nil
}

// Create a trampoline func this contains the stolen bytes from the hookedFunc and a jumb back to the hookedFunc after the stolen bytes
func createTrampolineFunc(hookedFunc uintptr, stealLength int) (uintptr, error) {
	requiredSize := stealLength + x64_ABS_JMP_INSTR_LEN
	proc := windows.CurrentProcess()

	// allocate memory for the trampoline to exec, set to write for now
	trampolineFunc, err := windows.VirtualAlloc(0, uintptr(requiredSize), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return uintptr(0), err
	}

	// read the bytes to steal from the hookedFunc
	stolenBytes := make([]byte, stealLength)
	bytesRead := uintptr(0)
	err = windows.ReadProcessMemory(proc, hookedFunc, &stolenBytes[0], uintptr(stealLength), &bytesRead)
	if err != nil {
		return uintptr(0), err
	}

	// write the stolen bytes into the trampolineFunc
	bytesWritten := uintptr(0)
	err = windows.WriteProcessMemory(proc, trampolineFunc, &stolenBytes[0], uintptr(stealLength), &bytesWritten)
	if err != nil {
		return uintptr(0), err
	}
	// write the 64bit jmp instruction to the trampoline pointing to the hookedFunc after the stolen bytes
	writeAbsJmp64(trampolineFunc+uintptr(stealLength), hookedFunc+uintptr(stealLength))

	// set trampolineFunc to be read/exec
	oldProtect := uint32(windows.PAGE_READWRITE)
	err = windows.VirtualProtect(trampolineFunc, uintptr(requiredSize), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return uintptr(0), err
	}

	return trampolineFunc, nil
}

// Write a relative jump instruction at the hookedFunc to the relayFunc
//
// If the stolen bytes are larger than 5 then the remaining bytes will be set to NOPs
func writeRelativeJmp(hookedFunc, relayFunc uintptr, stealLength int) error {
	// create NOP instructions
	relJmpInstructions := bytes.Repeat([]byte{0x90}, stealLength)
	relJmpAddr := relayFunc - hookedFunc - uintptr(x64_REL_JMP_INSTR_LEN)
	// place the jmp instruction at the start
	relJmpInstructions[0] = 0xE9

	// write the relJmpAddr address into the instructions
	binary.LittleEndian.PutUint32(relJmpInstructions[1:], uint32(relJmpAddr))
	writeDebug(fmt.Sprintf("Relative jmp instructions: %v", relJmpInstructions))

	oldProtect := uint32(0)
	// set the hookedFunc memory to be writeable
	err := windows.VirtualProtect(hookedFunc, uintptr(stealLength), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	bytesWritten := uintptr(0)
	// write the full instrctions into the baseFunc
	err = windows.WriteProcessMemory(windows.CurrentProcess(), hookedFunc, &relJmpInstructions[0], uintptr(stealLength), &bytesWritten)
	if err != nil {
		return err
	}

	// set the hookedFunc memory back to read / exec
	err = windows.VirtualProtect(hookedFunc, uintptr(stealLength), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// Installs hook instructions into the hookedFunc address that will redirect calls to the payloadFunc provided instead.
//
// stealLength is the number of instrucitons that need to be taken from the hookedFunc and then moved into the trampoline, this needs to be at least 5
// and can be a maximum of 32, to determine this length you need to investigate the instructions in the hookedFunc to know which instructions can be used
// without leaving part instructions.
//
// payloadFunc should be a C declared function that forwards the call to a Go func and then returns a call to the returned trampoline address
//
// This implementation does not do any disasm to work out if relative positioning needs to be performed, so if your hookedFunc has instructions at the beginning
// that refer to relative location this will not work!
func InstallHook64(hookedFunc, payloadFunc uintptr, stealLength int) (uintptr, error) {
	// check stealLength is valid
	if stealLength < MIN_STEAL_LEN || stealLength > MAX_STEAL_LEN {
		return uintptr(0), fmt.Errorf("stealLength must be between %d and %d", MIN_STEAL_LEN, MAX_STEAL_LEN)
	}

	writeDebug(fmt.Sprintf("Hooked func address: 0x%x", hookedFunc))
	writeDebug(fmt.Sprintf("Payload func address: 0x%x", payloadFunc))

	// create relay func
	relayFunc, err := createRelayFunc(uintptr(hookedFunc), uintptr(payloadFunc))
	if err != nil {
		return uintptr(0), err
	}
	writeDebug(fmt.Sprintf("Relay func address: 0x%x", relayFunc))

	// create trampoline
	trampolineFunc, err := createTrampolineFunc(uintptr(hookedFunc), stealLength)
	if err != nil {
		return uintptr(0), err
	}
	writeDebug(fmt.Sprintf("Trampoline func address: 0x%x", trampolineFunc))

	// write the relative jmp
	err = writeRelativeJmp(uintptr(hookedFunc), relayFunc, stealLength)
	if err != nil {
		return uintptr(0), err
	}

	return trampolineFunc, nil
}
