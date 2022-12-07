package winhook

type LPSYSTEM_INFO struct {
	dwOemId                     uint32
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       *uint32
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

//sys GetSystemInfo(lpSystemInfo *LPSYSTEM_INFO) = kernel32.GetSystemInfo
