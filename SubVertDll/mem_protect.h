#pragma once
#include "../Common/common.h"
#include "../Common/ioctrl.h"

namespace inject
{
	static void protect_mem(DWORD ProcessId,
			PVOID Address,
			SIZE_T MemSize)
		{
			PROTECT_MEM mem = { 0 };
			mem.ProcessId = DWORD64(ProcessId);
			mem.ProtectAddr64 = DWORD64(Address);
			mem.ProtectAddrSize64 = DWORD64(MemSize);

			const auto handle = std::experimental::make_unique_resource(
				CreateFile(TEXT("\\\\.\\Subvert"), GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
				&CloseHandle);

			auto returned = DWORD(0);
			auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_PROTECT, &mem, sizeof(mem), NULL, 0,
				&returned, nullptr);
		}
	static PVOID allocate_mem(DWORD ProcessId, SIZE_T AllocateSize)
		{
			const auto handle = std::experimental::make_unique_resource(
				CreateFile(TEXT("\\\\.\\Subvert"), GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
				&CloseHandle);
			PROCESS_AVM avm = { 0 };
			avm.ProcessId = ProcessId;
			avm.AllocateSize = AllocateSize;
			avm.AllocateAddr = 0x120000;
			AVM_RET ret = { 0 };
			auto returned = DWORD(0);
			auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_AVM, &avm, sizeof(avm), &ret, sizeof(ret),
				&returned, nullptr);

			auto base = ret.RetAddress;
			if (ret.RetAddress)
			{
				return (PVOID)ret.RetAddress;
			}
			return nullptr;
		}
};