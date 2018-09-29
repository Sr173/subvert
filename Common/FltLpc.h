#pragma once
#include "common.h"

namespace flt
{
	typedef struct _FS_LPC_MESSAGE_
	{
		ULONG32 PacketId;
		ULONG32 PacketSize;
		ULONG32 ContentOffset;
		BYTE Body[1];
	}FS_LPC_MESSAGE, *PFS_LPC_MESSAGE; //发送到驱动的数据

	typedef struct _FS_LPC_USR_MESSAGE
	{
		ULONG32 TypeId;
		ULONG32 ContentSize;//真大小，小于0x1000大于等于0
		BYTE BODY[0x1000];//<--PAGE_SIZE码，MAX_PATH的一个WCHAR就是520
	}FS_LPC_USR_MESSAGE,*PFS_LPC_USR_MESSAGE;
	
	typedef struct FS_LPC_USR_GET_MSG
	{
		FILTER_MESSAGE_HEADER msgheader;
		FS_LPC_USR_MESSAGE Body;
		OVERLAPPED Overlapped;
	}FS_LPC_USR_GET_MSG, *PFS_LPC_USR_GET_MSG;

	class FltLpc
	{
	public:
		using flt_lpc_callback = std::function<void(PFS_LPC_USR_GET_MSG)>;
		FltLpc()
		{
			FltCompletionPort = nullptr;
			FltPortHandle = nullptr;
			_ScanCallback = nullptr;
		}
		~FltLpc()
		{
			CloseHandle(FltPortHandle);
			CloseHandle(FltCompletionPort);
			FltCompletionPort = nullptr;
			FltPortHandle = nullptr;
		}
		HRESULT Connect(
			_In_ LPCWSTR PortName)
		{
			HRESULT result;
			HANDLE communicationPort;

			result = FilterConnectCommunicationPort(
				PortName,
				0,
				NULL,
				0,
				NULL,
				&communicationPort);

			if (SUCCEEDED(result))
			{
				FltPortHandle = communicationPort;

				//FltCompletionPort = CreateIoCompletionPort(
				//	FltPortHandle,
				//	NULL,
				//	0,
				//	NumberOfScanThreads);
			}

			return result;
		}
		HRESULT SendMessage(PVOID SendBuffer, ULONG SendBufferLength, PVOID ReplyBuffer, ULONG ReplyBufferLength, PULONG ReturnedLength)
		{	
			auto result = FilterSendMessage(
				FltPortHandle,
				SendBuffer,
				SendBufferLength,
				ReplyBuffer ,
				ReplyBufferLength,
				ReturnedLength);
			return result;
		}
		HRESULT ReplyMsg(PVOID Msg,ULONG MsgSize,PFILTER_MESSAGE_HEADER MsgHeader)
		{
			ULONG total_size = MsgSize + sizeof(FILTER_REPLY_HEADER);
			auto p_reply_Msg = malloc(total_size);
			auto exit_p = std::experimental::make_scope_exit([&]() {
				if (p_reply_Msg)
				{
					free(p_reply_Msg);
				}
			});
			if (!p_reply_Msg)
			{
				return -1;
			}
			{
				RtlZeroMemory(p_reply_Msg, total_size);
			}
			auto p_reply_header = reinterpret_cast<PFILTER_REPLY_HEADER>(p_reply_Msg);
			auto p_reply_body = reinterpret_cast<PVOID>((PUCHAR)p_reply_Msg + sizeof(FILTER_REPLY_HEADER));
			p_reply_header->MessageId = MsgHeader->MessageId;
			p_reply_header->Status = STATUS_SUCCESS;
			RtlCopyMemory(p_reply_body, Msg, MsgSize);
			auto ret = FilterReplyMessage(FltPortHandle,
				p_reply_header,
				total_size);
			return ret;
		}
		
	private:
		HANDLE FltPortHandle;
		HANDLE FltCompletionPort;
	private:
		DWORD GetProcessorCount()
		{
			SYSTEM_INFO systemInfo;

			GetSystemInfo(&systemInfo);

			return systemInfo.dwNumberOfProcessors;
		}
	private:
		flt_lpc_callback _ScanCallback;
	public:
		bool start_working(flt_lpc_callback _callback)
		{
			if (FltCompletionPort)
				return false;
			if (!FltPortHandle)
				return false;
			if (!_callback)
				return false;

			_ScanCallback = _callback;
			auto NumberOfScanThreads = (GetProcessorCount());
			FltCompletionPort = CreateIoCompletionPort(
				FltPortHandle,
				NULL,
				0,
				NumberOfScanThreads);
			if (FltCompletionPort)
			{
				for (DWORD i = 0; i < NumberOfScanThreads; i++)
				{
					auto my_thread = std::thread(std::bind(&FltLpc::working, this));
					my_thread.detach();
				}
				return true;
			}
			return false;
		}
		void working()
		{
			FS_LPC_USR_GET_MSG notificationBuffer;
			PFS_LPC_USR_GET_MSG notification;

			RtlZeroMemory(&notificationBuffer.Overlapped, sizeof(OVERLAPPED));
			notification = &notificationBuffer;

			while (TRUE)
			{
				HRESULT result;
				NTSTATUS status;
				BOOL success;
				DWORD outSize;
				ULONG_PTR key;
				LPOVERLAPPED overlapped;
				UCHAR responseFlags;

				result = FilterGetMessage(
					FltPortHandle,
					&notification->msgheader,
					FIELD_OFFSET(FS_LPC_USR_GET_MSG, Overlapped),
					&notification->Overlapped);

				if (result != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
					break;

				success = GetQueuedCompletionStatus(
					FltCompletionPort,
					&outSize,
					&key,
					&overlapped,
					INFINITE);

				if (!success)
					break;

				notification = CONTAINING_RECORD(overlapped, FS_LPC_USR_GET_MSG, Overlapped);
				if(_ScanCallback)
					_ScanCallback(notification);
			}
		}
	};
};