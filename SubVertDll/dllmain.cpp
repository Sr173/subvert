// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
#include "../Common/common.h"
#include "../Common/native_class.h"
//#include "../bin/shellcode_cc.h"
//#include "../bin/shellcode_base.h"
#include "inject_code.h"
const WCHAR *GameName = L"dnf.exe";//��ʾ����ע�����Ϸ
void find_process(LPCWSTR lpszName,std::map<DWORD,DWORD> &m_ProcessList)
{
	unsigned long cbBuffer = 0x5000;  //Initial Buffer Size
	void* Buffer = (void*)LocalAlloc(0, cbBuffer);
	if (Buffer == 0) return;
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
				if (Buffer == 0) return;
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
			WCHAR szName[MAX_PATH] = { 0 };
			__try
			{
				RtlCopyMemory(szName, p->ImageName.Buffer, min(p->ImageName.MaximumLength, 512));
				if (_wcsicmp(PathFindFileName(szName), lpszName) == 0)
				{
					auto pid = reinterpret_cast<DWORD>(p->UniqueProcessId);
					if (m_ProcessList.find(pid) == m_ProcessList.end())
					{
						m_ProcessList[pid] = 1;
					}
				}
			}
			__except (1)
			{
				DBG_PRINT(_T("����ͨ��  ����ͨ�� Failed\r\n"));
				return;
			}
			if (p->NextEntryDelta == 0) break;
			p = (NTDLL::SYSTEM_PROCESSES_INFORMATION*)((unsigned char*)p + (p->NextEntryDelta));
		}
	}
	LocalFree(Buffer);
	return;
}

bool inject_dll(DWORD ProcessId, LPCTSTR lpszFileName)
{
	//inject_remote_thread(ProcessId, lpszFileName);
	auto Process = std::experimental::make_unique_resource(
		OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)ProcessId), &CloseHandle);

	HANDLE ProcessHandle = Process.get();
	if (ProcessHandle == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	inject::inject_code_context((DWORD)ProcessId, lpszFileName, ProcessHandle);
	//inject::inject_code_thread(ProcessHandle);
	return true;
}
DWORD WINAPI MainThreadRoutine(LPVOID _param)
{
	std::map<DWORD, DWORD> m_ProcessList;
	while (1)
	{
		DBG_PRINT(_T("here is the code\r\n"));
		//�ҽ���
		find_process(GameName,m_ProcessList);
		//ע��
		for (auto item : m_ProcessList)
		{
			DWORD pid = item.first;
			if (item.second == 1)
			{
				//printf("find pid= %d\r\n", pid);
				//����������룡
				inject_dll(pid, L"C:\\helperdll.dll");//�ռ�ע��һ��ˢ��
				m_ProcessList[pid] = 2;
			}
		}
		Sleep(5000);
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DBG_PRINT(_T("SSSSS\r\n"));
		native::get_all_privilege();
		CreateThread(nullptr, 0, MainThreadRoutine, nullptr, 0, nullptr);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

