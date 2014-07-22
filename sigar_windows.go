// Copyright (c) 2012 VMware, Inc.

package sigar

/*
 #cgo LDFLAGS: -lpsapi -lntdll
 #define _WIN32_WINNT 0x0600
 #include <stdlib.h>
 #include <windows.h>
 #include <psapi.h>
 #include <winternl.h>
 #include <ntstatus.h>
 #include <Shellapi.h>


typedef struct NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
        LARGE_INTEGER   IdleTime;
        LARGE_INTEGER   KernelTime;
        LARGE_INTEGER   UserTime;
        LARGE_INTEGER   DpcTime;
        LARGE_INTEGER   InterruptTime;
        LONG            InterruptCount;
} NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

 typedef struct _SYSTEM_THREAD_INFORMATION
 {
     LARGE_INTEGER KernelTime;
     LARGE_INTEGER UserTime;
     LARGE_INTEGER CreateTime;
     ULONG WaitTime;
     PVOID StartAddress;
     CLIENT_ID ClientId;
     KPRIORITY Priority;
     LONG BasePriority;
     ULONG ContextSwitches;
     ULONG ThreadState;
     KWAIT_REASON WaitReason;
 } SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct NT_SYSTEM_PROCESS_INFORMATION
 {
     ULONG NextEntryOffset;
     ULONG NumberOfThreads;
     LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
     ULONG HardFaultCount; // since WIN7
     ULONG NumberOfThreadsHighWatermark; // since WIN7
     ULONGLONG CycleTime; // since WIN7
     LARGE_INTEGER CreateTime;
     LARGE_INTEGER UserTime;
     LARGE_INTEGER KernelTime;
     UNICODE_STRING ImageName;
     KPRIORITY BasePriority;
     HANDLE UniqueProcessId;
     HANDLE InheritedFromUniqueProcessId;
     ULONG HandleCount;
     ULONG SessionId;
     ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
     SIZE_T PeakVirtualSize;
     SIZE_T VirtualSize;
     ULONG PageFaultCount;
     SIZE_T PeakWorkingSetSize;
     SIZE_T WorkingSetSize;
     SIZE_T QuotaPeakPagedPoolUsage;
     SIZE_T QuotaPagedPoolUsage;
     SIZE_T QuotaPeakNonPagedPoolUsage;
     SIZE_T QuotaNonPagedPoolUsage;
     SIZE_T PagefileUsage;
     SIZE_T PeakPagefileUsage;
     SIZE_T PrivatePageCount;
     LARGE_INTEGER ReadOperationCount;
     LARGE_INTEGER WriteOperationCount;
     LARGE_INTEGER OtherOperationCount;
     LARGE_INTEGER ReadTransferCount;
     LARGE_INTEGER WriteTransferCount;
     LARGE_INTEGER OtherTransferCount;
     SYSTEM_THREAD_INFORMATION Threads[1];
} NT_SYSTEM_PROCESS_INFORMATION;
*/
import "C"

import (
	"fmt"
	//"github.com/StackExchange/wmi"
	//"strings"
	"unsafe"
)

type Win32_Process struct {
	ProcessId   uint32
	Name        string
	VirtualSize uint64
	CommandLine *string
}

func init() {
	enableTokenPrivilege()
}

var winCounter *WinCounter = NewWinCounter()

//enableing SeDebugPrivilege
//needed for reading processes that are not owned by the current user
func enableTokenPrivilege() {
	var tokenH C.HANDLE
	defer C.CloseHandle(tokenH)
	var tkp C.TOKEN_PRIVILEGES
	succeedOpenToken := C.OpenProcessToken(C.GetCurrentProcess(), C.TOKEN_ADJUST_PRIVILEGES|C.TOKEN_QUERY, &tokenH)

	if succeedOpenToken == C.FALSE {
		lastError := C.GetLastError()
		panic(fmt.Sprintf("OpenProcess failed with error: %d", int(lastError)))
	}

	seDebugPrivilege := (*C.CHAR)(unsafe.Pointer(C.CString("SeDebugPrivilege")))
	succedLookupPrivilege := C.LookupPrivilegeValue(nil, seDebugPrivilege, &tkp.Privileges[0].Luid)

	if succedLookupPrivilege == C.FALSE {
		lastError := C.GetLastError()
		panic(fmt.Sprintf("LookupPrivilegeValue failed with error: %d", int(lastError)))
	}
	tkp.PrivilegeCount = 1
	tkp.Privileges[0].Attributes = C.SE_PRIVILEGE_ENABLED

	succeedAdjustToken := C.AdjustTokenPrivileges(tokenH, C.FALSE, &tkp, C.DWORD(0), nil, nil)
	if succeedAdjustToken == C.FALSE {
		lastError := C.GetLastError()
		panic(fmt.Sprintf("AdjustTokenPrivileges failed with error: %d", int(lastError)))
	}
}

func (self *LoadAverage) Get() error {

	self.One = 0
	self.Five = 0
	self.Fifteen = 0
	return nil
}

func (self *Uptime) Get() error {
	var upcount C.ULONGLONG

	upcount = C.GetTickCount64()

	// Retrieved information is in millisecounds we need to convert to seconds
	self.Length = float64(upcount / 1000)

	return nil
}

func (self *Mem) Get() error {
	var statex C.MEMORYSTATUSEX
	statex.dwLength = C.DWORD(unsafe.Sizeof(statex))

	succeeded := C.GlobalMemoryStatusEx(&statex)
	if succeeded == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("GlobalMemoryStatusEx failed with error: %d", int(lastError))
	}
	self.Total = uint64(statex.ullTotalPhys)
	self.Free = uint64(winCounter.FreeMem)
	self.Used = self.Total - self.Free
	self.ActualFree = uint64(winCounter.ZeroFreeMem)
	self.ActualUsed = self.Total - self.ActualFree

	return nil
}

func (self *Swap) Get() error {
	var statex C.MEMORYSTATUSEX
	statex.dwLength = C.DWORD(unsafe.Sizeof(statex))

	succeeded := C.GlobalMemoryStatusEx(&statex)
	if succeeded == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("GlobalMemoryStatusEx failed with error: %d", int(lastError))
	}
	self.Total = uint64(statex.ullTotalPageFile)
	self.Free = uint64(statex.ullAvailPageFile)
	self.Used = self.Total - self.Free

	return nil
}

func (self *Cpu) Get() error {

	cpuCount := getCPUCount()
	cpuList := CpuList{}
	err := cpuList.Get()
	if err != nil {
		return fmt.Errorf("Error retrieving CPUs :%d", err)
	}
	self.User = 0
	self.Nice = 0
	self.Sys = 0
	self.Idle = 0
	self.Wait = 0
	self.Irq = 0
	self.SoftIrq = 0
	self.Stolen = 0
	for i := uint64(0); i < cpuCount; i++ {
		cpu := cpuList.List[i]
		self.User += cpu.User
		self.Nice += cpu.Nice
		self.Sys += cpu.Sys
		self.Idle += cpu.Idle
		self.Wait += cpu.Wait
		self.Irq += cpu.Irq
		self.SoftIrq += cpu.SoftIrq
		self.Stolen += cpu.Stolen
	}
	return nil
}

func (self *CpuList) Get() error {
	var status C.NTSTATUS

	//TODO Improve this
	cpuCount := getCPUCount()
	var perfSize C.NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION

	performanceInformation := make([]C.NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, cpuCount)
	sizeofPerformanceInformation := C.ULONG(unsafe.Sizeof(perfSize)) * C.ULONG(cpuCount)

	status = C.NtQuerySystemInformation(C.SystemProcessorPerformanceInformation,
		(C.PVOID)(&performanceInformation[0]), sizeofPerformanceInformation, nil)

	if status != C.STATUS_SUCCESS {
		return fmt.Errorf("NtQuerySystemInformation failed with error :%d", status)
	}
	list := make([]Cpu, cpuCount)

	for i := uint64(0); i < cpuCount; i++ {
		cpu := Cpu{}
		parseCpuStat(&cpu, performanceInformation[i])
		list[i] = cpu
	}
	self.List = list

	return nil
}

func (self *FileSystemList) Get() error {
	return notImplemented()
}

func (self *ProcList) Get() error {

	var cbNeeded C.DWORD
	var processCount int
	aProcesses := make([]C.DWORD, 1024)

	// retrieve DWORD size
	dwordSize := C.size_t(unsafe.Sizeof(cbNeeded))
	succeeded := C.EnumProcesses(&aProcesses[0], 4048*4, &cbNeeded)
	if succeeded == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("EnumProcesses failed with error: %d", int(lastError))
	}

	processCount = int(cbNeeded) / int(dwordSize)
	list := make([]int, processCount)

	for i := 0; i < processCount; i++ {
		list[i] = int(aProcesses[i])
	}

	self.List = list
	return nil
}

func (self *ProcState) Get(pid int) error {

	hProcess := C.OpenProcess(C.PROCESS_QUERY_INFORMATION|C.PROCESS_VM_READ, C.FALSE, C.DWORD(pid))
	defer C.CloseHandle(hProcess)
	if hProcess == nil {
		lastError := C.GetLastError()
		return fmt.Errorf("OpenProcess failed with error: %d", int(lastError))
	}

	var hMod C.HMODULE
	var newcbNeeded C.DWORD
	var hModSize C.DWORD
	var charSize C.CHAR
	var nameLength C.DWORD

	szProcessName := make([]C.CHAR, C.MAX_PATH)
	hModSize = C.DWORD(unsafe.Sizeof(hMod))
	//Get process name
	succeesProcesModule := C.EnumProcessModulesEx(hProcess, &hMod, hModSize, &newcbNeeded, C.LIST_MODULES_DEFAULT)
	if succeesProcesModule == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("EnumProcessModulesEx failed with error: %d", int(lastError))
	}

	nameLength = C.DWORD(C.size_t(unsafe.Sizeof(szProcessName)) / C.size_t(unsafe.Sizeof(charSize)))
	successGetModules := C.GetModuleBaseName(hProcess, hMod, &szProcessName[0], nameLength)
	if successGetModules == C.DWORD(0) {
		lastError := C.GetLastError()
		return fmt.Errorf("GetModuleBaseName failed with error: %d", int(lastError))
	}

	//Cast from CHAR to char
	processName := (*C.char)(unsafe.Pointer(&szProcessName[0]))

	pbi, successGetPBI := GetProcessBasicInformation(hProcess)
	if successGetPBI != nil {
		return successGetPBI
	}
	self.Name = C.GoString(processName)
	self.Ppid = int(pbi.InheritedFromUniqueProcessId)
	self.Priority = int(pbi.BasePriority)
	//self.State = nil
	self.Tty = 0       //not applicable
	self.Nice = 0      //not applicable
	self.Processor = 0 //not applicable CPU number last executed on.
	return nil
}

func (self *ProcMem) Get(pid int) error {

	err, processInformation := getProcessInformation(pid)
	if err != nil {
		return err
	}
	self.Size = *(*uint64)(unsafe.Pointer(&processInformation.VirtualSize))
	self.Resident = *((*uint64)(unsafe.Pointer(&processInformation.WorkingSetSize)))
	self.Share = *((*uint64)(unsafe.Pointer(&processInformation.PagefileUsage)))
	self.MinorFaults = 0 // not applicable
	self.MajorFaults = 0 // not applicable
	self.PageFaults = *((*uint64)(unsafe.Pointer(&processInformation.PageFaultCount)))

	return nil
}

func (self *ProcTime) Get(pid int) error {

	var creationTime C.FILETIME
	var exitTime C.FILETIME
	var kernelTime C.FILETIME
	var userTime C.FILETIME

	hProcess := C.OpenProcess(C.PROCESS_QUERY_INFORMATION|C.PROCESS_VM_READ, C.FALSE, C.DWORD(pid))
	defer C.CloseHandle(hProcess)
	if hProcess == nil {
		lastError := C.GetLastError()
		return fmt.Errorf("OpenProcess failed with error: %d", int(lastError))
	}
	success := C.GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)
	if success == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("GetProcessTimes failed with error: %d", int(lastError))
	}

	//Convert FILETIME to milisecounds
	self.StartTime = uint64((((C.ULONGLONG(creationTime.dwHighDateTime)) << 32) + C.ULONGLONG(creationTime.dwLowDateTime)) / 10000)
	self.User = uint64((((C.ULONGLONG(userTime.dwHighDateTime)) << 32) + C.ULONGLONG(userTime.dwLowDateTime)) / 10000)
	self.Sys = uint64((((C.ULONGLONG(kernelTime.dwHighDateTime)) << 32) + C.ULONGLONG(kernelTime.dwLowDateTime)) / 10000)
	self.Total = self.User + self.Sys
	return nil
}

func (self *ProcExe) Get(pid int) error {
	processArgs := ProcArgs{}
	err := processArgs.Get(pid)
	if err != nil {
		return err
	}
	self.Name = processArgs.List[0]
	self.Cwd = ""
	self.Root = "" //not applicable
	return nil
}

func (self *FileSystemUsage) Get(path string) error {
	var availableBytes C.ULARGE_INTEGER
	var totalBytes C.ULARGE_INTEGER
	var totalFreeBytes C.ULARGE_INTEGER

	pathChars := C.CString(path)
	defer C.free(unsafe.Pointer(pathChars))

	succeeded := C.GetDiskFreeSpaceEx((*C.CHAR)(pathChars), &availableBytes, &totalBytes, &totalFreeBytes)
	if succeeded == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("GetDiskFreeSpaceEx failed with error: %d", int(lastError))
	}

	self.Total = *(*uint64)(unsafe.Pointer(&totalBytes))
	return nil
}
func (self *ProcArgs) Get(pid int) error {
	var userProcParamAddress C.PEB
	var upp C.RTL_USER_PROCESS_PARAMETERS
	var args []string

	hProcess := C.OpenProcess(C.PROCESS_QUERY_INFORMATION|C.PROCESS_VM_READ, C.FALSE, C.DWORD(pid))
	defer C.CloseHandle(hProcess)
	if hProcess == nil {
		lastError := C.GetLastError()
		return fmt.Errorf("OpenProcess failed with error: %d", int(lastError))
	}

	pbi, err := GetProcessBasicInformation(hProcess)
	if err != nil {
		return err
	}

	//Get the address of the ProcessParameters
	readSuccess := C.ReadProcessMemory(hProcess, C.LPCVOID(pbi.PebBaseAddress),
		C.LPVOID(&userProcParamAddress), C.SIZE_T(unsafe.Sizeof(userProcParamAddress)), nil)
	if readSuccess == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("ReadProcessMemory parameter address failed with error: %d", int(lastError))
	}

	readSuccess = C.ReadProcessMemory(hProcess, C.LPCVOID(userProcParamAddress.ProcessParameters),
		C.LPVOID(&upp), C.SIZE_T(unsafe.Sizeof(upp)), nil)
	if readSuccess == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("ReadProcessMemory command line fill failed with error: %d", int(lastError))
	}

	pwszBuffer := make([]C.WCHAR, upp.CommandLine.Length)

	readSuccess = C.ReadProcessMemory(hProcess, C.LPCVOID(upp.CommandLine.Buffer),
		C.LPVOID(&pwszBuffer[0]), C.SIZE_T(upp.CommandLine.Length), nil)

	if readSuccess == C.FALSE {
		lastError := C.GetLastError()
		return fmt.Errorf("ReadProcessMemory command line arguments failed with error: %d", int(lastError))
	}

	var lpszArgv *C.LPWSTR
	var nArgc C.int
	lpszArgv = C.CommandLineToArgvW(&pwszBuffer[0], &nArgc)

	lpszTemp := (*[8192]*[8192]uint16)(unsafe.Pointer(lpszArgv))

	for i := 0; i < int(nArgc); i++ {

		size := int(C.wcslen((*C.wchar_t)(unsafe.Pointer(lpszTemp[i]))))
		arg := wCharToString((*C.WCHAR)(unsafe.Pointer(lpszTemp[i])), size)
		args = append(args, arg)
	}

	self.List = args
	return nil
}

func parseCpuStat(self *Cpu, performanceInformation C.NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) {
	self.Idle = *((*uint64)(unsafe.Pointer(&performanceInformation.IdleTime)))
	self.User = *((*uint64)(unsafe.Pointer(&performanceInformation.UserTime)))
	self.Nice = 0 //not applicable to windows
	//windows kenel metric time contain kernel + idle
	self.Sys = *((*uint64)(unsafe.Pointer(&performanceInformation.KernelTime))) - self.Idle
	self.Wait = 0 //unavailable
	self.Irq = *((*uint64)(unsafe.Pointer(&performanceInformation.InterruptTime)))
	self.SoftIrq = 0 //unavailable
	self.Stolen = 0  //unavailable
}

func getCPUCount() uint64 {
	var sysinfo C.SYSTEM_INFO
	C.GetSystemInfo(&sysinfo)

	cpuCount := uint64(sysinfo.dwNumberOfProcessors)
	return cpuCount
}

func getProcessInformation(pid int) (error, *C.NT_SYSTEM_PROCESS_INFORMATION) {
	var firstProcessInformation *C.NT_SYSTEM_PROCESS_INFORMATION
	procList := ProcList{}
	err := procList.Get()
	if err != nil {
		return err, firstProcessInformation
	}
	nrProcesses := len(procList.List) * 16

	var sizeOfProcessInformation C.NT_SYSTEM_PROCESS_INFORMATION

	var processInformationArray = make([]C.NT_SYSTEM_PROCESS_INFORMATION, C.ULONG(unsafe.Sizeof(sizeOfProcessInformation))*C.ULONG(nrProcesses))

	status := C.NtQuerySystemInformation(C.SystemProcessInformation,
		(C.PVOID)(&processInformationArray[0]), C.ULONG(unsafe.Sizeof(sizeOfProcessInformation))*C.ULONG(nrProcesses), nil)

	if status != C.STATUS_SUCCESS {
		return fmt.Errorf("NtQuerySystemInformation failed with error :%d", status), firstProcessInformation
	}

	firstProcessInformation = &processInformationArray[0]
	for {

		currentPid := *((*uint32)(unsafe.Pointer(&firstProcessInformation.UniqueProcessId)))

		if currentPid == uint32(pid) {
			break
		}

		if firstProcessInformation.NextEntryOffset == 0 {
			break
		}
		pointerValue := (uintptr(unsafe.Pointer(firstProcessInformation)) + uintptr(firstProcessInformation.NextEntryOffset))
		firstProcessInformation = (*C.NT_SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(pointerValue))

	}

	return nil, firstProcessInformation
}

func wCharToString(wChar *C.WCHAR, size int) string {
	var cCHARSize C.CHAR
	if size < 1 {
		return ""
	}

	szBuffer := make([]C.CHAR, size)
	succeded := C.WideCharToMultiByte(C.CP_ACP, 0, wChar,
		-1, &szBuffer[0], C.int(size/int(unsafe.Sizeof(cCHARSize))), nil, nil)
	if succeded == 0 {
		lastError := C.GetLastError()
		fmt.Errorf("WideCharToMultiByte failed with error: %d", int(lastError))
	}
	return C.GoString((*C.char)(unsafe.Pointer(&szBuffer[0])))

}

func GetProcessBasicInformation(hProcess C.HANDLE) (C.PROCESS_BASIC_INFORMATION, error) {

	var pbi C.PROCESS_BASIC_INFORMATION

	pbiSize := C.ULONG(unsafe.Sizeof(pbi))
	successNtQueryProcess := C.NtQueryInformationProcess(hProcess, C.ProcessBasicInformation, (C.PVOID)(&pbi), pbiSize, nil)
	if successNtQueryProcess != C.STATUS_SUCCESS {
		return pbi, fmt.Errorf("NtQueryInformationProcess failed with error :%d", successNtQueryProcess)
	}

	return pbi, nil
}

func notImplemented() error {
	panic("Not Implemented")
	return nil
}
