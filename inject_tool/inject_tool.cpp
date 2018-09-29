// inject_tool.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../Common/common.h"
#include "../Common/native_class.h"
#include "../Common/native_inject.h"
#include "subvert_sys.h"

int main()
{
	native::get_all_privilege();
	ATOM hAtom;
	LPCTSTR lpszAtomName = TEXT("{DFBB9E8A-A098-4B0F-8720-EEF3C93E7E50}");
	if ((hAtom = GlobalFindAtom(lpszAtomName)))
	{
		ExitProcess(-1);
	}
	hAtom = GlobalAddAtom(lpszAtomName);

	install::install_drv();
	auto csrss_pid = CsrGetProcessId();
	if (csrss_pid)
	{
		_tprintf(_T("csrss pid = %llu\r\n"), (DWORD_PTR)csrss_pid);
		native::inject::getInstance().inject_dll_ex((DWORD)csrss_pid, L"\\SubVertDll.dll");
	}
    return 0;

}

