#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4244)
#pragma warning(disable : 4005)
#pragma warning(disable : 4477)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)
#pragma warning(disable : 4313)
#pragma warning(disable : 4267)
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <thread>
#include <TlHelp32.h>
#include <Psapi.h>
#include "MDE.h"
#pragma comment(lib, "Psapi.lib")
using namespace std;
void __cdecl CallbackMDE(MDE::PMMAP_INFO mmap)
{
	char mde_type[35]; memset(mde_type, 0, sizeof(mde_type));
	switch (mmap->detectionType)
	{
	case MDE::MMAP_DLL_HEADERS:
		strcpy(mde_type, "DLL HEADERS");
		break;
	case MDE::MMAP_DLL_THREAD:
		strcpy(mde_type, "DLL THREAD");
		break;
	case MDE::MMAP_CRT_STUB:
		strcpy(mde_type, "CRT STUB");
		break;
	case MDE::MMAP_IMPORT_TABLE:
		strcpy(mde_type, "IMPORT TABLE");
		break;
	}
#ifdef _WIN64
	printf("\nDetected manual map at address: 0x%llX | Determined by: %s\n", mmap->base_address, mde_type);
#else
	printf("\nDetected manual map at address: 0x%X | Determined by: %s\n", mmap->base_address, mde_type);
#endif
}
void __stdcall MmapScanner()
{
	while (true)
	{
		MDE::MemoryScanner(MDE::MMAP_DLL_THREAD, MDE::SCANTIME_DLLTHREADS, CallbackMDE);
		while (MDE::IsScanningStillActive(MDE::MMAP_DLL_THREAD)) { Sleep(1); }
		MDE::MemoryScanner(MDE::MMAP_IMPORT_TABLE, MDE::SCANTIME_IAT, CallbackMDE);
		while (MDE::IsScanningStillActive(MDE::MMAP_IMPORT_TABLE)) { Sleep(1); }
	}
}
int main()
{
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MmapScanner, 0, 0, 0);
	system("pause");
	return 1;
}