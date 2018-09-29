#pragma once
#include "../Common/common.h"
#include "mem_protect.h"
namespace inject
{
	static unsigned long GetMainThreadId(unsigned long ProcessId)
	{
		unsigned long cbBuffer = 0x5000;  //Initial Buffer Size
		void* Buffer = (void*)LocalAlloc(0, cbBuffer);
		if (Buffer == 0) return 0;
		bool x = false;
		bool error = false;
		while (x == false)
		{
			int ret = NTDLL::NtQuerySystemInformation(NTDLL::SystemExtendedProcessInformation, Buffer, cbBuffer, 0);
			if (ret < 0)
			{
				if (ret == STATUS_INFO_LENGTH_MISMATCH)
				{
					cbBuffer = cbBuffer + cbBuffer;
					LocalFree(Buffer);
					Buffer = (void*)LocalAlloc(0, cbBuffer);
					if (Buffer == 0) return 0;
					x = false;
				}
				else
				{
					x = true;
					error = true;
				}
			}
			else x = true;
		}
		if (error == false)
		{
			NTDLL::SYSTEM_PROCESSES_INFORMATION* p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)Buffer;
			while (1)
			{
				if (p->UniqueProcessId == (HANDLE)ProcessId)
				{
					//for (ULONG i=0;i<p->ThreadCount;i++)
					{
						unsigned long ThreadId = (unsigned long)p->Threads[0].ClientId.UniqueThread;
						//auto Base = p->Threads[0].StartAddress;
						//DBG_PRINT(_T("秘密通信  秘密通信秘密通信 线程ID=%d 地址=%p\r\n"), ThreadId, Base);
						//GetModuleFileNameEx()
						LocalFree(Buffer);
						return ThreadId;
					}

				}
				if (p->NextEntryDelta == 0) break;
				p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)p + (p->NextEntryDelta));
			}
		}
		LocalFree(Buffer);
		return 0;
	}

	static bool allocate_shellcode(HANDLE ProcessHandle, PVOID *out_mem)
	{
		DWORD ShellCodeSize = sizeof(shellcode_nn);
		PVOID shellcode = nullptr;
		SIZE_T AllocSize = ShellCodeSize*4;
		auto Pid = GetProcessId(ProcessHandle);
		DBG_PRINT(_T("秘密通信 进程id=%d\r\n"), Pid);
		shellcode = inject::allocate_mem(Pid, AllocSize);
		//allocate_mem通过驱动分配神秘内存
		if (!shellcode)
		{
			DBG_PRINT(_T("秘密通信 与驱动通信失败，将不能保护菊花\r\n"));
			auto ns3= ZwAllocateVirtualMemory(
				ProcessHandle,
				&shellcode,
				0,
				&AllocSize,
				MEM_COMMIT,
				PAGE_EXECUTE_READWRITE
			);
			if (!NT_SUCCESS(ns3))
			{
				return false;
			}
		}
		DWORD old = 0;
		VirtualProtectEx(ProcessHandle, shellcode, AllocSize, PAGE_EXECUTE_READWRITE, &old);
		DBG_PRINT(_T("秘密通信 shellcode2 %p %d %p\r\n"), shellcode, AllocSize,(DWORD_PTR)shellcode+AllocSize);
		ULONG ReturnLength = 0;
		auto ns = ZwWriteVirtualMemory(ProcessHandle, shellcode, shellcode_nn, ShellCodeSize, &ReturnLength);
		if (!NT_SUCCESS(ns))
		{
			return false;
		}
		//protect_mem将内存的VAD从Tree上移动
		//这个方法比用EPT或者NPT保护内存兼容性更好一些
		//驱动暂时不提供
		inject::protect_mem(GetProcessId(ProcessHandle), shellcode, AllocSize);
		if (out_mem)
		{
			*out_mem = shellcode;
		}
		return true;
	}
	static PVOID WriteStubEx(HANDLE hProcess, LPCWSTR lpszDllFilePath)
	{
		ULONG_PTR stublen;
		PVOID LoadLibAddr, mem;
		allocate_shellcode(hProcess, &LoadLibAddr);
		stublen = sizeof(shellcode_basecode);
		mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		DBG_PRINT(_T("秘密通信 Allocate mem =%p\r\n"), mem);
		//printf("Memory allocated at %p\nAbout to write stub code...\n", mem);
		WriteProcessMemory(hProcess, mem, &LoadLibAddr, sizeof(PVOID), NULL);
		WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)mem + 4), shellcode_basecode, stublen, NULL);
		WriteProcessMemory(hProcess, (LPVOID)((LPBYTE)mem + 4 + stublen), lpszDllFilePath, MAX_PATH * sizeof(WCHAR), NULL);
		return (PVOID)((LPBYTE)mem + 4);
	}
	static bool create_thread(IN HANDLE ProcessHanlde, IN PVOID Routine, IN PVOID Param)
	{
		const auto THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;
		const auto THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002;
		const auto THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004;

		HANDLE hThread = nullptr;
		OBJECT_ATTRIBUTES ob = { 0 };
		auto flags = THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH;

		InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		auto status = ZwCreateThreadEx(
			&hThread,
			THREAD_ALL_ACCESS,
			&ob,
			ProcessHanlde,
			Routine,
			Param,
			flags,
			0,
			0x10000,
			0x100000,
			NULL
		);
		auto exit_3 = std::experimental::make_scope_exit([&]() {if (hThread)
			ZwClose(hThread); });

		if (!NT_SUCCESS(status))
		{
		//	_tprintf(_T("ZwCreateThreadEx failed\r\n"));
			return false;
		}
		return true;
	}
	static BOOL inject_apc_dll(DWORD dwProcessId, LPCWSTR lpszDllFilePath)
	{
		using NT_QUEUE_APC_THREAD = NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, PVOID, PVOID);
		auto MainThreadId = GetMainThreadId(dwProcessId);
		auto ret = FALSE;
		auto h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (h_process && h_process != INVALID_HANDLE_VALUE)
		{
			WCHAR szName[MAX_PATH] = { 0 };
			wcscpy_s(szName, sizeof(szName), lpszDllFilePath);
			auto h_Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, MainThreadId);
			if (h_Thread && h_Thread != INVALID_HANDLE_VALUE)
			{
				auto  NtQueueApcThread = (NT_QUEUE_APC_THREAD)(GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueueApcThread"));

				//printf("Attempting Injection using NtQueueApcThread...\n");

				auto mem = WriteStubEx(h_process, szName);

				NtQueueApcThread(h_Thread, mem, NULL, NULL, NULL);
				//printf("NtQueueApcThread called: %d\n", GetLastError());
				ret = TRUE;
				CloseHandle(h_Thread);
			}
			CloseHandle(h_process);
		}
		return ret;
	}

	DWORD get_proc_address32(
		HANDLE hProcess, 
		HMODULE Module, 
		LPCSTR lpszApiName)
	{
		std::unique_ptr<IMAGE_EXPORT_DIRECTORY, decltype(&free)> expData(nullptr, &free);
		auto baseAddress = (ULONG_PTR)Module;

		IMAGE_DOS_HEADER hdrDos = { 0 };
		uint8_t hdrNt32[sizeof(IMAGE_NT_HEADERS64)] = { 0 };
		auto phdrNt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(hdrNt32);
		auto phdrNt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(hdrNt32);
		DWORD expSize = 0;
		uintptr_t expBase = 0;

		ReadProcessMemory(
			hProcess,
			reinterpret_cast<LPCVOID>(Module),
			&hdrDos,
			sizeof(hdrDos),
			nullptr);

		if (hdrDos.e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		ReadProcessMemory(hProcess,
			reinterpret_cast<LPCVOID>((ULONG_PTR)Module + hdrDos.e_lfanew),
			&hdrNt32,
			sizeof(IMAGE_NT_HEADERS64),
			nullptr);
		if (phdrNt32->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		if (phdrNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			expBase = phdrNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		else
			expBase = phdrNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		if (expBase)
		{
			if (phdrNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				expSize = phdrNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			else
				expSize = phdrNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

			expData.reset(reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(malloc(expSize)));
			IMAGE_EXPORT_DIRECTORY* pExpData = expData.get();

			ReadProcessMemory(hProcess,
				reinterpret_cast<LPCVOID>((ULONG_PTR)Module + expBase),
				pExpData,
				expSize,
				nullptr);

			WORD *pAddressOfOrds = reinterpret_cast<WORD*> (
				pExpData->AddressOfNameOrdinals + reinterpret_cast<uintptr_t>(pExpData) - expBase);

			DWORD *pAddressOfNames = reinterpret_cast<DWORD*>(
				pExpData->AddressOfNames + reinterpret_cast<uintptr_t>(pExpData) - expBase);

			DWORD *pAddressOfFuncs = reinterpret_cast<DWORD*>(
				pExpData->AddressOfFunctions + reinterpret_cast<uintptr_t>(pExpData) - expBase);

			for (DWORD i = 0; i < pExpData->NumberOfFunctions; ++i)
			{
				WORD OrdIndex = 0xFFFF;
				char *pName = nullptr;

				// Find by index
				if (reinterpret_cast<uintptr_t>(lpszApiName) <= 0xFFFF)
				{
					OrdIndex = static_cast<WORD>(i);
				}
				// Find by name
				else if (reinterpret_cast<uintptr_t>(lpszApiName) > 0xFFFF && i < pExpData->NumberOfNames)
				{
					pName = (char*)(pAddressOfNames[i] + reinterpret_cast<uintptr_t>(pExpData) - expBase);
					OrdIndex = static_cast<WORD>(pAddressOfOrds[i]);
				}
				else
					return 0;

				if ((reinterpret_cast<uintptr_t>(lpszApiName) <= 0xFFFF
					&& (WORD)((uintptr_t)lpszApiName) == (OrdIndex + pExpData->Base)) ||
					(reinterpret_cast<uintptr_t>(lpszApiName) > 0xFFFF
						&& strcmp(pName, lpszApiName) == 0))
				{
					auto procAddress = pAddressOfFuncs[OrdIndex] + baseAddress;
					return (DWORD)procAddress;
				}
			}
		}
		return 0;
	}

	static bool inject_code_context(
		DWORD ProcessId,
		LPCWSTR lpszFileName,
		HANDLE ProcessHandle)
	{
		bool ret = false;
		WCHAR szName[MAX_PATH] = { 0 };
		wcscpy_s(szName, sizeof(szName), lpszFileName);
		auto MainThreadId = inject::GetMainThreadId(ProcessId);
		auto h_Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, MainThreadId);
		if (h_Thread && h_Thread != INVALID_HANDLE_VALUE)
		{

			auto dwRet = Wow64SuspendThread(h_Thread);
			if (dwRet != (DWORD)-1)
			{
				auto mem = inject::WriteStubEx(ProcessHandle, szName);
				WOW64_CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_FULL;
				if (Wow64GetThreadContext(h_Thread, &ctx))
				{
					ctx.Esp -= 4;
					WriteProcessMemory(ProcessHandle, reinterpret_cast<PVOID>(ctx.Esp), &ctx.Eip, sizeof(PVOID), NULL);
					ctx.Eip = reinterpret_cast<DWORD>(mem);
					if (Wow64SetThreadContext(h_Thread, &ctx))
						ret = true;
				}
				ResumeThread(h_Thread);
			}
			CloseHandle(h_Thread);
		}
		return ret;
	}
	static bool inject_code_thread(HANDLE ProcessHandle)
	{
		PVOID thread_code = nullptr;
		auto b = inject::allocate_shellcode(ProcessHandle, &thread_code);
		if (!b)
		{
			DBG_PRINT(_T("秘密通信  Allocate ShellCode Failed\r\n"));
			return false;
		}
		DBG_PRINT(_T("秘密通信  开始注射线程\r\n"));
		DWORD dwTid = 0;
		auto hThread = CreateRemoteThread(
			ProcessHandle,
			nullptr,
			0,
			(LPTHREAD_START_ROUTINE)thread_code,
			nullptr,
			0,
			&dwTid);
		DBG_PRINT(_T("秘密通信  注射线程结束 线程 = %p  tid = %d\r\n"), hThread, dwTid);
		NtWaitForSingleObject(hThread, FALSE, NULL);
		DWORD exit_code = -1;
		GetExitCodeThread(hThread, &exit_code);
		if (exit_code != -1 && exit_code != 0)
		{
			//本来要兼容一些奇怪的代码，还是算了。
			auto new_shellcode = PVOID(DWORD64(exit_code));
			DBG_PRINT(_T("秘密通信 new shellcode =%p\r\n"), new_shellcode);
			inject::protect_mem(
				GetProcessId(ProcessHandle),
				new_shellcode,
				PAGE_SIZE);
		}
		CloseHandle(hThread);
		return true;
	}

}