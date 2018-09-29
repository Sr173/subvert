#pragma once
#include "common.h"
namespace native
{
	static const auto THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;
	static const auto THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002;
	static const auto THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004;

	typedef VOID(NTAPI *pLdrSetDllManifestProber)(PVOID, PVOID, PVOID);
	typedef NTSTATUS(NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
	typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
	typedef DWORD(WINAPI *pGetTempPathW)(_In_ DWORD, LPWSTR);
	typedef UINT(WINAPI* pGetSystemDirectoryW)(LPWSTR, UINT);
	typedef BOOL(WINAPI *pGetVolumeInformationW)(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
	typedef struct _THREAD_DATA {
		pRtlInitUnicodeString fnRtlInitUnicodeString;
		pLdrLoadDll fnLdrLoadDll;
		pGetTempPathW fnGetTempPathW;
		pGetSystemDirectoryW fnGetSystemDirectoryW;
		pGetVolumeInformationW fnGetVolumeInformationW;
		pLdrSetDllManifestProber fnLdrSetDllManifestProber;
		wchar_t dllpath[MAX_PATH];
	}THREAD_DATA, *PTHREAD_DATA;

	static HANDLE WINAPI ShellcodeBegin(PTHREAD_DATA parameter) {
		if (parameter->fnRtlInitUnicodeString != nullptr&&parameter->fnLdrLoadDll != nullptr) {
			UNICODE_STRING UnicodeString;
			parameter->fnRtlInitUnicodeString(&UnicodeString, parameter->dllpath);
			HANDLE module_handle = nullptr;
			parameter->fnLdrSetDllManifestProber(nullptr, nullptr, nullptr);
			auto ns = parameter->fnLdrLoadDll(nullptr, nullptr, &UnicodeString, &module_handle);
			if (!module_handle)
			{
				__debugbreak();
			}
			return HANDLE(ns);
		}
		else {
			return (HANDLE)-3;
		}
	}
	static DWORD WINAPI ShellcodeEnd() {
		return 0;
	}

	class inject :public Singleton<inject>
	{
	private:
		bool ProcessInternalExecute(PTHREAD_DATA parameter, DWORD process_id) {
			HANDLE hProcess = nullptr;
			NTDLL::CLIENT_ID cid = { (HANDLE)process_id, nullptr };
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
			if (!NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid))) {
				_tprintf(_T("ZwOpenProcess failed\r\n"));
				return false;
			}
			PVOID data = VirtualAllocEx(hProcess, NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			PVOID code = VirtualAllocEx(hProcess, NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!data || !code) {
				NtClose(hProcess);
				_tprintf(_T("VirtualAllocEx failed\r\n"));
				return false;
			}
			ZwWriteVirtualMemory(hProcess, data, parameter, sizeof(THREAD_DATA), NULL);
			ZwWriteVirtualMemory(hProcess, code, (PVOID)ShellcodeBegin, (ULONG)((LPBYTE)0x1000), NULL);
			HANDLE hThread = nullptr;
			if (!NT_SUCCESS(RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, code, data, &hThread, NULL))) {
				NtClose(hProcess);
				_tprintf(_T("RtlCreateUserThread failed\r\n"));
				return false;
			}
			NtWaitForSingleObject(hThread, FALSE, NULL);
			DWORD exit_code = -1;
			GetExitCodeThread(hThread, &exit_code);
			_tprintf(_T("ret= %x\r\n"), exit_code);
			NtClose(hThread);
			VirtualFreeEx(hProcess, data, 0, MEM_RELEASE);
			VirtualFreeEx(hProcess, code, 0, MEM_RELEASE);
			NtClose(hProcess);
			return (exit_code == 0);
		}
		std::wstring GetAbsolutePath(const std::wstring& name) {
			wchar_t fileName[MAX_PATH] = { 0 };
			GetModuleFileNameW(NULL, fileName, MAX_PATH);
			PathRemoveFileSpec(fileName);
			auto ret= std::wstring(fileName).append(name);
			_tprintf(_T("%ws\r\n"), ret.c_str());
			return ret;
		}
		void SetShellcodeLdrModulePath(PTHREAD_DATA parameter, const std::wstring& srcfile) {
			wcscpy_s(parameter->dllpath, srcfile.c_str());
		}
	public:
		void inject_dll_ex(DWORD ProcessId, const std::wstring dll_path)
		{
			THREAD_DATA parameter = { 0 };
			parameter.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
			parameter.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll");
			parameter.fnGetTempPathW = (pGetTempPathW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTempPathW");
			parameter.fnGetSystemDirectoryW = (pGetSystemDirectoryW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetSystemDirectoryW");
			parameter.fnGetVolumeInformationW = (pGetVolumeInformationW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetVolumeInformationW");
			parameter.fnLdrSetDllManifestProber = (pLdrSetDllManifestProber)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrSetDllManifestProber");
			SetShellcodeLdrModulePath(&parameter, GetAbsolutePath(dll_path));
			ProcessInternalExecute(&parameter, ProcessId);
		}
	public:
		bool inject_dll(HANDLE ProcessId, wchar_t *dll_path)
		{
			auto csrssProcess = std::experimental::make_unique_resource(
				OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)ProcessId), &CloseHandle);
			auto handle = csrssProcess.get();
			auto pNtDllBase = GetModuleHandle(_T("ntdll.dll"));
			UNICODE_STRING dllPath;
			RtlInitUnicodeString(&dllPath, dll_path);
			if (!pNtDllBase)
			{
				_tprintf(_T("GetModuleHandle failed\r\n"));
				return false;
			}
			auto pfnLdrLoadDll = GetProcAddress(pNtDllBase, "LdrLoadDll");
			if (!pfnLdrLoadDll)
			{
				_tprintf(_T("GetProcAddress failed\r\n"));
				return false;
			}
			_tprintf(_T("LdrLoadDll = %p\r\n"), pfnLdrLoadDll);

			if (!handle ||
				handle==INVALID_HANDLE_VALUE)
			{
				_tprintf(_T("OpenProcess failed\r\n"));
				return false;
			}
			const UCHAR ldr_code64[] =
			{
				0x90,
				0x48, 0x83, 0xEC, 0x48,							// sub rsp, 0x48
				0x48, 0x31, 0xC9,								// xor rcx, rcx
				0x48, 0x31, 0xD2,								// xor rdx, rdx
				0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,				// mov r9, pModuleHandle //offset+12
				0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,				// mov r8, pModulePath   //offset+22
				0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,				// mov rax, LdrLoadDll  //offset+32
				0xFF, 0xD0,										// call rax
				0x48, 0x83, 0xC4, 0x48,							// add rsp, 0x48
				0xCC											// ret
			};
			INJECT_BUFFER Buffer = { 0 };
			auto pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(handle, (PVOID)pNtDllBase, PAGE_SIZE);
			if (!pBuffer)
			{
				_tprintf(_T("AllocateInjectMemory failed\r\n"));
				return false;
			}
			Buffer.path64.Length = min(dllPath.Length, sizeof(Buffer.buffer));
			Buffer.path64.MaximumLength = min(dllPath.MaximumLength, sizeof(Buffer.buffer));
			Buffer.path64.Buffer = (DWORD64)pBuffer->buffer;
			memcpy(Buffer.buffer, dllPath.Buffer, Buffer.path64.Length);
			memcpy(Buffer.code, ldr_code64, sizeof(ldr_code64));

			// Fill stubs
			*(ULONGLONG*)((PUCHAR)Buffer.code + 12+1) = (ULONGLONG)&pBuffer->module;
			*(ULONGLONG*)((PUCHAR)Buffer.code + 22+1) = (ULONGLONG)&pBuffer->path64;
			*(ULONGLONG*)((PUCHAR)Buffer.code + 32+1) = (ULONGLONG)pfnLdrLoadDll;

			auto ns = ZwWriteVirtualMemory(handle, pBuffer, &Buffer, sizeof(Buffer), NULL);
			if (!NT_SUCCESS(ns))
			{
				_tprintf(_T("ZwWriteVirtualMemory failed\r\n"));
				return false;
			}
			HANDLE hThread = nullptr;
			OBJECT_ATTRIBUTES ob = { 0 };
			PVOID param = nullptr;
			auto flags = THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
			InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			auto status = ZwCreateThreadEx(
				&hThread, 
				THREAD_ALL_ACCESS, 
				&ob,
				handle, 
				pBuffer,
				param, 
				flags,
				0, 
				0x1000, 
				0x100000,
				NULL
			);
			auto exit_3 = std::experimental::make_scope_exit([&]() {if (hThread)
				ZwClose(hThread); });

			if (!NT_SUCCESS(status))
			{
				_tprintf(_T("ZwCreateThreadEx failed\r\n"));
				return false;
			}
			return true;
		}
		PVOID AllocateInjectMemory(IN HANDLE ProcessHandle, IN PVOID DesiredAddress, IN SIZE_T DesiredSize)
		{
			MEMORY_BASIC_INFORMATION mbi;
			SIZE_T AllocateSize = DesiredSize;

			if ((ULONG_PTR)DesiredAddress >= 0x70000000 && (ULONG_PTR)DesiredAddress < 0x80000000)
				DesiredAddress = (PVOID)0x70000000;

			while (1)
			{
				if (!NT_SUCCESS(ZwQueryVirtualMemory(
					ProcessHandle, 
					DesiredAddress, 
					NTDLL::MEMORY_INFORMATION_CLASS::MemoryBasicInformation, 
					&mbi, 
					sizeof(mbi),
					NULL)))
				{
					DBG_PRINT(_T("faield QueryVirtualMemory\r\n"));
					return NULL;
				}
				if (DesiredAddress != mbi.AllocationBase)
				{
					DesiredAddress = mbi.AllocationBase;
				}
				else
				{
					DesiredAddress = (PVOID)((ULONG_PTR)mbi.AllocationBase - 0x10000);
				}

				if (mbi.State == MEM_FREE)
				{
					if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
					{
						if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
						{
							return mbi.BaseAddress;
						}
					}
				}
			}
			return NULL;
		}
		PVOID GetWowNtdllBase(HANDLE ProcessHandle)
		{
			//HMODULE hMods[1024] = {};
			//DWORD cbNeeded = 0;
			//if (EnumProcessModules(ProcessHandle, hMods, sizeof(hMods), &cbNeeded))
			//{
			//	for (ULONG i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			//	{
			//		TCHAR szModName[MAX_PATH] = {};

			//		// Get the full path to the module's file.

			//		if (GetModuleFileNameEx(ProcessHandle, hMods[i], szModName,
			//			sizeof(szModName) / sizeof(TCHAR)))
			//		{
			//			// Print the module name and handle value.
			//			DBG_PRINT(TEXT("%s %p\r\n"), szModName, hMods[i]);
			//			//_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
			//			
			//		}
			//	}
			//}
			return PVOID(0x70000000);
		}
	};
}