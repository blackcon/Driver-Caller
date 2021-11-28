// call_ahcache.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <ntstatus.h>
#include <processthreadsapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <combaseapi.h>
#include <shellapi.h>
#include "sdb.h"
#pragma comment(lib, "ntdll.lib")

BOOL resolveSdbFunctions();
extern SdbOpenDatabase SdbOpenDatabasePtr;
extern SdbCloseDatabase SdbCloseDatabasePtr;
extern SdbTagToString SdbTagToStringPtr;
extern SdbGetFirstChild SdbGetFirstChildPtr;
extern SdbGetTagFromTagID SdbGetTagFromTagIDPtr;
extern SdbGetNextChild SdbGetNextChildPtr;
extern SdbReadBinaryTag SdbReadBinaryTagPtr;

#define MAX_LAYER_LENGTH            256
#define GPLK_USER                   1
#define GPLK_MACHINE                2
#define SHIMDATA_MAGIC  0xAC0DEDAB

LPCWSTR filename = L"C:\\Users\\bk-vmware\\Desktop\\tools\\driverview-x64\\readme.txt";

typedef struct _ShimData
{
	/*
	WCHAR szModule[MAX_PATH];
	DWORD dwSize;
	DWORD dwMagic;
	SDBQUERYRESULT Query;
	WCHAR szLayer[MAX_LAYER_LENGTH];
	DWORD dwRosProcessCompatVersion;  // ReactOS specific
	*/
	BYTE unk[0x208];
	DWORD dwMaxSize;	// +0x208 (v9 == 0x11C0)
	DWORD dwMagic;			// +0x20c
};

struct ApphelpCacheControlData
{
	PVOID unk0;
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	PVOID unk5;
	PVOID unk6;
	PVOID unk7;
	PVOID unk8;
	PVOID unk9;
	PVOID unk10;
	PVOID unk11;
	PVOID unk12;
	PVOID unk13;
	PVOID unk14;
	PVOID unk15;
	PVOID unk16;
	PVOID unk17;
	PVOID unk18;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	PVOID unk22;
	PVOID unk23;
	PVOID unk24;
	PVOID unk25;
	PVOID unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID unk30;
	PVOID unk31;
	PVOID unk32;
	PVOID unk33;
	PVOID unk34;
	PVOID unk35;
	PVOID unk36;
	PVOID unk37;
	PVOID unk38;
	PVOID unk39;
	PVOID unk40;
	PVOID unk41;
	PVOID unk42;
	PVOID unk43;
	PVOID unk44;
	PVOID unk45;
	PVOID unk46;
};

// 참고: 
//  Windows: Elevation of Privilege in ahcache.sys/NtApphelpCacheControl
//  (https://bugs.chromium.org/p/project-zero/issues/detail?id=118&redir=1)에서 제공된 poc.zip
struct APPHELP_QUERY
{
	int match_tags[16];
	int unk40[16];
	int layer_tags[8];
	int flags;
	int main_tag;
	int match_count;
	int layer_count;
	GUID exe_guid;
	int unkC0[264 / 4];
};


//HANDLE CaptureImpersonationToken();
ApphelpCacheControlData *AhcCdbRefresh();	// cmd = 0x7;
ApphelpCacheControlData *AhcApiInitProcessData();	// cmd = 0xa;
ApphelpCacheControlData *AhcApiLookupAndWriteToProcess();	// cmd = 0xb;



HANDLE CreateProcessHandle()
{
	HANDLE fileHandle;
	UNICODE_STRING deviceName;
	OBJECT_ATTRIBUTES object;
	IO_STATUS_BLOCK IoStatusBlock;

	RtlInitUnicodeString(&deviceName, (PWSTR)L"\\Device\\ahcache");
	InitializeObjectAttributes(&object, &deviceName, 0, NULL, NULL);

	NTSTATUS status = NtCreateFile(&fileHandle, MAXIMUM_ALLOWED, &object, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, 0, NULL, NULL);

	if (status != STATUS_SUCCESS)
	{
		printf("[-] NtCreateFile error: %x \n", status);
		return fileHandle;
	}
	return fileHandle;
}

NTSTATUS _DeviceIoControlFile(HANDLE hProc)
{
	DWORD dwRet = 0;
	NTSTATUS status = -1;
	IO_STATUS_BLOCK IoStatusBlock;
	APPHELP_QUERY query = { 0 };

	DWORD menu = 0;
	DWORD _AppHelpCacheCmd = 0xa;
	ApphelpCacheControlData *data;

	printf(" [+] Enter _AppHelpCacheCmd\r\n");
	printf("  -> 0. AhcCdbRefresh\r\n");
	printf("  -> 1. AhcApiInitProcessData\r\n");
	printf("  -> 2. AhcApiLookupAndWriteToProcess\r\n");
	scanf_s("%d", &menu);
	switch (menu) { // This logic is to configure data set for each function
	case 0:
		_AppHelpCacheCmd = 0x7;
		data = AhcCdbRefresh(); // _AppHelpCacheCmd = 0x7;
		break;
	case 1:
		_AppHelpCacheCmd = 0xa;
		data = AhcApiInitProcessData();	// _AppHelpCacheCmd = 0xa;
		break;
	case 2:
		_AppHelpCacheCmd = 0xb;
		data = AhcApiLookupAndWriteToProcess();	// _AppHelpCacheCmd = 0xb;
		break;
	default:
		printf("[ERROR] Fail\n");
		return -1;
	}
	if (data == NULL)
	{
		printf(" [ERROR] Fail\n");
		return -1;
	}
	else {
		printf(" [!] before call NtDeviceIoControlFile() \n");
		getchar();

		status = NtDeviceIoControlFile(hProc,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			CTL_CODE(FILE_DEVICE_UNKNOWN, _AppHelpCacheCmd, METHOD_NEITHER, FILE_ANY_ACCESS),	// 4 * a1 | 0x220003  -> [000000100010][00][000000000000][11] ; ntokrnl.exe에서 NtApphelpCacheControl() 참고
																							// https://ezbeat.tistory.com/286 :: ([DEVICE_TYPE][ACCESS][FUNCTION][METHOD])
			data,
			sizeof(ApphelpCacheControlData),
			NULL,
			NULL
		);

		return status;
	}
}

ApphelpCacheControlData *AhcCdbRefresh()
{
	ApphelpCacheControlData data;
	memset(&data, 0, sizeof(ApphelpCacheControlData));

	data.unk0 = (void *)0x61616161;
	data.unk1 = malloc(0x20);	// some struct{ QWORD base_addr;	unsigned __int16 offset; }
	memset(data.unk1, 0x30, 0x20);
	data.unk2 = (void *)strlen((char *)data.unk1);
	data.unk3 = (void *)0x64646464;	// file_handler; ex)craetefile(data.unk1);

	return &data;
}
ApphelpCacheControlData *AhcApiInitProcessData()
{
	_ShimData *shimData;

	ApphelpCacheControlData data;
	memset(&data, 0, sizeof(ApphelpCacheControlData));
	data.unk0 = (PVOID)0x61616161;
	data.unk1 = (PVOID)0x62626262;
	data.unk2 = (PVOID)0x63636363;
	data.unk3 = (PVOID)0x64646464;
	data.unk4 = (PVOID)0x65656565;
	data.unk5 = (PVOID)0x66666666;
	data.unk6 = (PVOID)0x67676767;
	data.unk7 = (PVOID)0x68686868;
	data.unk8 = (PVOID)0x69696969;
	data.unk9 = (PVOID)0x6a6a6a6a;
	data.unk10 = (PVOID)0x6b6b6b6b;
	data.unk11 = (PVOID)0x6c6c6c6c;
	data.unk12 = (PVOID)0x6d6d6d6d;
	data.unk13 = (PVOID)0x6e6e6e6e;
	data.unk14 = (PVOID)0x6f6f6f6f;
	data.unk15 = (PVOID)0x70707070;
	data.unk16 = (PVOID)0x71717171;
	data.unk17 = (PVOID)0x72727272;
	data.unk18 = (PVOID)0x73737373;
	data.unk19 = (PVOID)0x74747474;
	data.unk20 = (PVOID)0x75757575;
	data.unk21 = (PVOID)0x76767676;
	data.unk22 = (PVOID)0x77777777;
	data.unk23 = (PVOID)0x78787878;
	data.unk24 = (PVOID)0x79797979;
	data.unk25 = (PVOID)0x7a7a7a7a;
	data.unk26 = (PVOID)0x7b7b7b7b;
	data.unk27 = (PVOID)0x7c7c7c7c;
	data.unk28 = (PVOID)0x7d7d7d7d;
	data.unk29 = (PVOID)0x7e7e7e7e;
	data.unk30 = (PVOID)0x7f7f7f7f;
	data.unk31 = (PVOID)0x80808080L;
	data.unk32 = (PVOID)0x81818181L;
	data.unk33 = (PVOID)0x82828282L;
	data.unk34 = (PVOID)0x83838383L;
	data.unk35 = (PVOID)0x84848484L;
	data.unk36 = (PVOID)0x85858585L;
	data.unk37 = (PVOID)0x86868686L;
	data.unk38 = (PVOID)0x87878787L;
	data.unk39 = (PVOID)0x88888888L;
	data.unk40 = (PVOID)0x89898989L;

	// use in ahcache!AhcApiInitProcessData()
	data.unk41 = (PVOID)0x8a8a8a8aL;	// unknown. It is not NULL

	shimData = (_ShimData *)malloc(sizeof(_ShimData));
	shimData->dwMaxSize = 0x11C0;
	shimData->dwMagic = SHIMDATA_MAGIC;
	data.unk42 = shimData;			// base_addr ( addr & 3 == 0x0 // 끝자리가 0,4,8,c여야 함) -> 아마도 ShimData를 담고있는 구조체의 주소일듯
	data.unk43 = (PVOID)0x1cd0;		// size > 0x1cc0	
	/////////////////////////

	data.unk44 = (PVOID)0x8d8d8d8dL;
	data.unk45 = (PVOID)0x8e8e8e8eL;
	data.unk46 = (PVOID)0x8f8f8f8fL;

	return &data;
}
ApphelpCacheControlData *AhcApiLookupAndWriteToProcess()
{
	ApphelpCacheControlData data;
	memset(&data, 0, sizeof(ApphelpCacheControlData));
	data.unk0 = (PVOID)0x61616161;		
	data.unk1 = (PVOID)lstrlenW(filename);	// length of buffer_for_filename; start position
	data.unk2 = (PVOID)&filename;	// buffer_for_filename; !(buffer_for_filename) & 3
	data.unk3 = (PVOID)CreateFile(filename, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, 0); // some handler
	data.unk4 = (PVOID)0x65656565;
	data.unk5 = (PVOID)0x66666666;
	data.unk6 = (PVOID)0x67676767;
	data.unk7 = (PVOID)0x68686868;
	data.unk8 = (PVOID)0x69696969;
	data.unk9 = (PVOID)0x6a6a6a6a;
	data.unk10 = (PVOID)0x6b6b6b6b;
	data.unk11 = (PVOID)0x6c6c6c6c;
	data.unk12 = (PVOID)0x6d6d6d6d;
	data.unk13 = (PVOID)0x6e6e6e6e;
	data.unk14 = (PVOID)0x6f6f6f6f;
	data.unk15 = (PVOID)0x70707070;
	data.unk16 = (PVOID)0x71717171;
	data.unk17 = (PVOID)0x72727272;
	data.unk18 = (PVOID)0x73737373;
	data.unk19 = (PVOID)0x74747474;
	data.unk20 = (PVOID)0x75757575;
	data.unk21 = (PVOID)0x76767676;
	data.unk22 = (PVOID)0x77777777;
	data.unk23 = (PVOID)0x78787878;
	data.unk24 = (PVOID)0x79797979;
	data.unk25 = (PVOID)0x7a7a7a7a;
	data.unk26 = (PVOID)0x7b7b7b7b;
	data.unk27 = (PVOID)0x7c7c7c7c;
	data.unk28 = (PVOID)0x7d7d7d7d;
	data.unk29 = (PVOID)0x7e7e7e7e;
	data.unk30 = (PVOID)0x7f7f7f7f;
	data.unk31 = (PVOID)0x80808080L;
	data.unk32 = (PVOID)0x81818181L;
	data.unk33 = (PVOID)0x82828282L;
	data.unk34 = (PVOID)0x83838383L;
	data.unk35 = (PVOID)0x84848484L;
	data.unk36 = (PVOID)0x85858585L;
	data.unk37 = (PVOID)0x86868686L;
	data.unk38 = (PVOID)0x87878787L;
	data.unk39 = (PVOID)0x88888888L;
	data.unk40 = (PVOID)0x89898989L;
	data.unk41 = (PVOID)0x8a8a8a8aL;
	data.unk42 = (PVOID)0x8b8b8b8bL;
	data.unk43 = (PVOID)0x8c8c8c8cL;
	data.unk44 = (PVOID)0x8d8d8d8dL;
	data.unk45 = (PVOID)0x8e8e8e8eL;	// address_on_usermode_a4
	data.unk46 = (PVOID)0x8f8f8f8fL;

	return &data;

}

int target_ahcache()
{
	// get driver handler
	HANDLE hProc = CreateProcessHandle();
	printf(" [+] procHandle: %x\n", (DWORD)hProc);
	if (hProc == 0) {
		return 0;
	}
	// DeviceIoControlFile
	NTSTATUS status =  _DeviceIoControlFile(hProc);
	if (status != 0) {
		printf(" [-] Fail DeviceIoControlFile: %x\n", status);
	}
	else {
		printf(" [+] Success DeviceIoControlFile: %x\n", status);
	}

	return 0;
}

int main(void)
{
	target_ahcache();
	_flushall();
	getchar();
}
