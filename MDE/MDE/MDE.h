#pragma once
// MDE - ManualMap Detection Engine 
// by NtKernelMC
// Date of creation: 07.04.19
// Task: Detection of manual-map injected DLL`s

/*
	================= FEATURES [ENG]
	> Support for multi-threaded scanning
	> Support of 4th different detection vectors
	> Detection by DLL Headers
	> Detection by DLL Thread
	> Detection by dllMain CRT stub
	> Detection by Import Table
	> Support of x64-x86 architectures & Windows OS family from Vista and higher
	================== ���������� [RUS]
	> ��������� ��������������� �������������
	> ��������� �� ����� ��������� ������� ��������
	> ������ ����������� DLL �� PE-����������
	> ������ ����������� DLL �� �������� ������
	> ������ ����������� DLL �� dllMain CRT �����
	> ������ ����������� DLL �� ������� �������
	> ��������� ������ ��� x64-x86 ���������� �� ���� O� �������� Windows �� Vista � ����
*/
#include <Windows.h>
#pragma comment(lib, "MDE.lib")
namespace MDE
{
	enum MDE_SCANTYPE
	{
		MMAP_DLL_HEADERS = 0x1,
		MMAP_DLL_THREAD = 0x2,
		MMAP_CRT_STUB = 0x3,
		MMAP_IMPORT_TABLE = 0x4
	};
	typedef struct
	{
		LPVOID base_address;
		MDE_SCANTYPE detectionType;
		DWORD AllocatedProtect;
		PVOID AllocatedBase;
		DWORD AllocatedSize;
	} MMAP_INFO, *PMMAP_INFO;
	typedef void(__cdecl *CallbackMDE)(PMMAP_INFO mmap);
	void __cdecl MemoryScanner(MDE_SCANTYPE scanType, CallbackMDE NotifyCallback);
}
