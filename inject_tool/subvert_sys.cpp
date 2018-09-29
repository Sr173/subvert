#include "stdafx.h"
#include "../Common/common.h"
#include "../Common/serviceManagement.h"
#include "subvert_sys.h"
namespace install
{
	// Return an error message of corresponding Win32 error code.
	std::basic_string<TCHAR> GetWin32ErrorMessage(
		__in std::uint32_t ErrorCode)
	{
		TCHAR* message = nullptr;
		if (!::FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr,
			ErrorCode, LANG_USER_DEFAULT, reinterpret_cast<LPTSTR>(&message), 0,
			nullptr))
		{
			return TEXT("");
		}
		if (!message)
		{
			return TEXT("");
		}
		//auto messageDeleter = std::experimental::make_scope_exit(
		//    [message]() { ::LocalFree(message); });

		const auto length = ::_tcslen(message);
		if (!length)
		{
			return TEXT("");
		}

		if (message[length - 2] == TEXT('\r'))
		{
			message[length - 2] = TEXT('\0');
		}
		return message;
	}
	// Throw std::runtime_error with an error message.
	void ThrowRuntimeError(
		__in const std::basic_string<TCHAR>& Message)
	{
		const auto errorCode = ::GetLastError();
		const auto errorMessage = GetWin32ErrorMessage(errorCode);
		char msg[1024];
#if UNICODE
		static const char FORMAT_STR[] = "%S : %lu(0x%08x) : %S";
#else
		static const char FORMAT_STR[] = "%s : %lu(0x%08x) : %s";
#endif
		StringCchPrintfA(msg, _countof(msg), FORMAT_STR,
			Message.c_str(), errorCode, errorCode, errorMessage.c_str());
		throw std::runtime_error(msg);
	}
	// Build a full path corresponds to a given file name. Throw std::runtime_error
	// when a given file does not exist.
	std::basic_string<TCHAR> CreateFullPathFromName(
		__in const std::basic_string<TCHAR>& FileName)
	{
		TCHAR fullPath[MAX_PATH];
		if (!::PathSearchAndQualify(FileName.c_str(),
			fullPath, _countof(fullPath)))
		{
			ThrowRuntimeError(TEXT("PathSearchAndQualify failed."));
		}

		if (!::PathFileExists(fullPath))
		{
			ThrowRuntimeError(TEXT("PathFileExists failed."));
		}
		return fullPath;
	}


	// Returns a base name of a given full path. For example, when the first
	// parameter is 'C:\dir\name.exe', then the function returns 'name'.
	std::basic_string<TCHAR> CreateServiceName(
		__in const std::basic_string<TCHAR>& DriverFullPath)
	{
		TCHAR serviceName[MAX_PATH];
		if (!SUCCEEDED(::StringCchCopy(serviceName, _countof(serviceName),
			DriverFullPath.c_str())))
		{
			ThrowRuntimeError(TEXT("StringCchCopy failed."));
		}

		::PathRemoveExtension(serviceName);
		::PathStripPath(serviceName);
		return serviceName;
	}
	void install_drv()
	{
		const auto driverFullPath = CreateFullPathFromName(TEXT("SubvertSys.sys"));

		const auto serviceName = CreateServiceName(driverFullPath);
		//	system("pause");
		// Check if the service exists
		if (IsServiceInstalled(serviceName))
		{
			// Uninstall the service when it has already been installed
			if (!UnloadDriver(serviceName))
			{
				MessageBox(nullptr,TEXT("UnloadDriver failed."),nullptr,MB_OK);
				//return FALSE;
			}
		}
		{
			// Then, load the driver
			if (!LoadDriver(serviceName, driverFullPath))
			{
				_tprintf(_T("%s\r\n"), driverFullPath.c_str());
				MessageBox(nullptr,TEXT("LoadDriver failed."),nullptr,MB_OK);
				//return FALSE;
			}
		}
	}
};