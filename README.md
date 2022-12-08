# winhook

## Background

This module came about after looking into performing inline hooking and reading some great material on the subject and also watching several videos on how it is performed in C/C++. What I tended to find was that alot focused on 32bit rather than 64bit and lets be honest when was the last time you worked with 32bit architecture! 

Finally I found a fantastic article http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html which went through from a simple hook but destructive right through to making a generic hook in 64bit without destroying the original hooked function.

Having this in C/C++ is good however it would be great to be able to have this option and be able to write it in Go to have all the available standard libs available, cross compilation and a single deployed executable not too mention the other numerous reasons using Go for malicous deployments is a [great](https://www.youtube.com/watch?v=3RQb05ITSyk) [option](https://www.youtube.com/watch?v=AGLunpPtOgM). I had a good look round to see if anyone else had written any Go module to perform this but was out of luck either they wrapped other hooking libs or used the [SetWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa) which allows certain events to be hooked such as mouse, keyboard but is very limited.

So fast forward and I managed to find a workable solution written mostly in Go but with some interop pieces requiring C. If anyone is able to point me in the right direction on how to make it work 100% Go I'm all ears!

## Pre-requisites for hooking

In order to use the package you will need to gather some info on the function you want to hook from the executable or library, I would recommend a decent debugger for this such as [x64dbg](https://x64dbg.com/):

1. Find the address in memory of where the function resides
2. Determine if the instructions used by the function are valid to be hooked, cases were hooking is not possible with this library would be if the instructions are less than 5 bytes (relative jmp requires this) or if the instructions include relative positions.
3. The next step is to work out the signature used by the function, some cases will be easier than other for instance hooking Win32 API functions given the vast amount of MSDN docs out there with how to make calls in C/C++.

## Usage

### Defining a Go Payload func

This will be the Go func that will be called instead of the hooked func AKA the payload func, it can be named whatever you like and you should define the args of the hooked func as C args:

~~~go
// typedef unsigned int UINT;
// typedef void* HANDLE;
import "C"

//export goPayloadFunc
func goPayloadFunc(arg1 C.UINT, arg2 C.HANDLE){
    // do actual hooking code here...
}
~~~

### Defining the C Interop 

This is required to capture the hooked call and forward to the Go payload func, then make a call back to the trampoline address:

~~~go
//
// // required to allow C to make calls into the exported Go func
// extern goPayloadFunc(UINT, HANDLE);
//
// // declare a typedef for the hooked function to be used by the trampoline
// typedef HANDLE HOOKEDFUNC(UINT, HANDLE)
//
// HANDLE Gateway(UINT arg1, HANDLE arg2)
// {
//   // call into the Go func
//   goPayload(arg1, arg2);
//   // then call the trampoline which will in turn return back to the hooked function
//   return trampoline(arg1, arg2);   
// }
//
// // is set against the returned trampoline address
// HOOKEDFUNC *trampoline = NULL;
//
//
import "C"
~~~

### Making the Hook Call

Finally the hook call can be made with the address of the hooked function, the adress of the C gateway function and finally the number of bytes to steal from the hooked function:

~~~go
trampolineFunc, err := winhook.InstallHook64(hookedFunc, uintptr(C.Gateway), 5)
if err != nil{
    // handle err
}

// set the C trampoline variable
C.trampoline = (*C.HOOKEDFUNC)(unsafe.Pointer(trampolineFunc))
~~~

## Debugging

As this can require a bit of knowledge of address locations and instructions being written into memory there is a `winhook.DebugEnabled` flag that can be enabled that will provide diagnostic information in Message Boxes and hopefully help track down why something is not working.