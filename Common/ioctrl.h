#pragma once
#ifndef _NTDDK_
#include <winioctl.h>
#endif

static const auto DRV_DEVICE_CODE = 0x8000ul;
static const auto DRV_IOCTL_PROTECT = CTL_CODE(DRV_DEVICE_CODE, 0x0800, /* 0x0800-0x0FFF */METHOD_BUFFERED, FILE_ANY_ACCESS);
static const auto DRV_IOCTL_HELLO2 = CTL_CODE(DRV_DEVICE_CODE, 0x0801, /* 0x0800-0x0FFF */METHOD_BUFFERED, FILE_ANY_ACCESS);
static const auto DRV_IOCTL_AVM = CTL_CODE(DRV_DEVICE_CODE, 0x0802, /* 0x0800-0x0FFF */METHOD_BUFFERED, FILE_ANY_ACCESS);


#pragma pack(1)
typedef struct _PROTECT_MEM_
{
	DWORD64 ProcessId;
	DWORD64 ProtectAddr64;
	DWORD64 ProtectAddrSize64;
}PROTECT_MEM,*PPROTECT_MEM;
typedef struct _PROCESS_AVM
{
	DWORD64 ProcessId;
	DWORD64 AllocateSize;
	DWORD64 AllocateAddr;
}PROCESS_AVM,*PPROCESS_AVM;
typedef struct _AVM_RET
{
	DWORD64 RetAddress;
}AVM_RET,*PAVM_RET;
#pragma pack()