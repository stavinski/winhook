package winsys

type LPSYSTEM_INFO struct {
	DwOemId                     uint32
	WProcessorArchitecture      uint16
	WReserved                   uint16
	DwPageSize                  uint32
	LpMinimumApplicationAddress uintptr
	LpMaximumApplicationAddress uintptr
	DwActiveProcessorMask       *uint32
	DwNumberOfProcessors        uint32
	DwProcessorType             uint32
	DwAllocationGranularity     uint32
	WProcessorLevel             uint16
	WProcessorRevision          uint16
}

//sys GetSystemInfo(lpSystemInfo *LPSYSTEM_INFO) = kernel32.GetSystemInfo
