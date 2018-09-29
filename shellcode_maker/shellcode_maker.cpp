// shellcode_maker.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../Common/common.h"

#pragma optimize( "", off ) 
__declspec(naked) void stub()
{
	__asm
	{
		pushad
		pushfd
		call start

		start :
			pop ecx
			sub ecx, 7

			lea eax, [ecx + 32]
			push eax
			call dword ptr[ecx - 4]

			popfd
			popad
			ret
	}
}

DWORD WINAPI stub_end()
{
	return 0;
}
#pragma optimize("", on )

int main()
{
	HANDLE hFile = CreateFile(_T("shellcode.bin"), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	
	DWORD dwWrite = 0;
	WriteFile(hFile, (PVOID)stub, (ULONG_PTR)stub_end - (ULONG_PTR)stub, &dwWrite, nullptr);
	CloseHandle(hFile);
    return 0;
}

