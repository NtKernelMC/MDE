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
	================== ФУНКЦИОНАЛ [RUS]
	> Поддержка мультипоточного сканнирования
	> Поддержка до четёрх различных режимов сканнера
	> Способ обнаружения DLL по PE-заголовкам
	> Способ обнаружения DLL по созданию потока
	> Способ обнаружения DLL по dllMain CRT стабе
	> Способ обнаружения DLL по таблице импорта
	> Поддержка работы для x64-x86 архитектур на всех OС семества Windows от Vista и выше
*/
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <winternl.h>
#include <string>
#include <thread>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#pragma warning(disable : 4244)
using namespace std;
namespace MDE
{
	typedef BYTE byte;
#ifdef _WIN64
#define START_ADDRESS (PVOID)0x00000000010000
#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
#define START_ADDRESS (PVOID)0x10000
#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif
#ifdef _WIN64
	typedef DWORD64 COMPATIBLE_DWORD;
#else
	typedef DWORD COMPATIBLE_DWORD;
#endif
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
		COMPATIBLE_DWORD AllocatedProtect;
		PVOID AllocatedBase;
		DWORD AllocatedSize;
	} MMAP_INFO, *PMMAP_INFO;
	typedef void(__cdecl *CallbackMDE)(PMMAP_INFO mmap);
	typedef struct
	{
		CallbackMDE NotifyCallback;
		MDE_SCANTYPE scanType;
	} SCANNER_DATA, *PSCANNER_DATA;
	map<LPVOID, DWORD> __cdecl BuildModuledMemoryMap()
	{
		map<LPVOID, DWORD> memoryMap; HMODULE hMods[1024]; DWORD cbNeeded;
		typedef BOOL (__stdcall *PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
		PtrEnumProcessModules EnumProcModules = (PtrEnumProcessModules)GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
		EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded);
		typedef BOOL (__stdcall *GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
		GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MODULEINFO modinfo; GetMdlInfo(GetCurrentProcess(), hMods[i], &modinfo, sizeof(modinfo));
			memoryMap.insert(memoryMap.begin(), pair<LPVOID, DWORD>(modinfo.lpBaseOfDll, modinfo.SizeOfImage));
		}
		return memoryMap;
	}
	bool __cdecl IsMemoryInModuledRange(LPVOID base)
	{
		map<LPVOID, DWORD> memory = BuildModuledMemoryMap();
		for (const auto &it : memory)
		{
			if (base >= it.first && base <= (LPVOID)((COMPATIBLE_DWORD)it.first + it.second)) return true;
		}
		return false;
	}
	template<typename First, typename Second>
	bool __stdcall SearchForMapMatch(const map<First, Second> &map, const First first, const Second second)
	{
		for (auto it : map)
		{
			if (it.first == first && it.second == second) return true;
		}
		return false;
	}
	void __stdcall WatchMemoryAllocations(PSCANNER_DATA scanData, PMMAP_INFO mmap, 
	const void* ptr, size_t length, MEMORY_BASIC_INFORMATION* info, int size)
	{
		if (scanData == nullptr || ptr == nullptr || info == nullptr) return;
		const void* end = (const void*)((const char*)ptr + length);
		DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ);
		while (ptr < end && VirtualQuery(ptr, &info[0], sizeof(*info)) == sizeof(*info))
		{
			MEMORY_BASIC_INFORMATION* i = &info[0];
			if ((i->State != MEM_FREE || i->State != MEM_RELEASE) && i->Type & (MEM_IMAGE | MEM_PRIVATE) && i->Protect & mask)
			{
				if (!IsMemoryInModuledRange((LPVOID)ptr))
				{
					for (DWORD_PTR z = (DWORD_PTR)ptr; z < ((DWORD_PTR)ptr + i->RegionSize); z++)
					{
						if (scanData->scanType == MDE_SCANTYPE::MMAP_IMPORT_TABLE)
						{
							bool complete_sequence = false;
							__try
							{
								for (DWORD x = 0; x < (10 * 6); x += 0x6)
								{
									if (*(byte*)(z + x) == 0xFF && *(byte*)(x + z + 0x1) == 0x25)
									{
										complete_sequence = true;
									}
									else complete_sequence = false;
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER) { };
							if (complete_sequence)
							{
								mmap->base_address = (LPVOID)ptr;
								mmap->AllocatedBase = i->AllocationBase;
								mmap->AllocatedProtect = i->AllocationProtect;
								mmap->AllocatedSize = i->RegionSize;
								mmap->detectionType = MMAP_IMPORT_TABLE;
								scanData->NotifyCallback(mmap);
								break;
							}
						}
						else if (scanData->scanType == MDE_SCANTYPE::MMAP_CRT_STUB)
						{
#ifdef _WIN64
							const char pattern[] = { "\x48\x8B\xC4\x48\x89\x58\x20\x4C\x89\x40\x18\x89\x50\x10\x48\x89\x48\x08\x56\x57\x41\x56\x48\x83\xEC\x40\x49\x8B\xF0\x8B\xFA\x4C\x8B\xF1\x85\xD2\x75\x0F\x39\x15\x00\x00\x00\x00\x7F\x07\x33\xC0\xE9\x00\x00\x00\x00" };
							const char wildcard[] = { "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxx????" };
#else
							const char pattern[] = { "\x6A\x10\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x6A\x00\xE8\x00\x00\x00\x00\x59\x84\xC0\x75\x07" };
							const char wildcard[] = { "xxx????x????xxx????xxxxx" };
#endif
							bool found = false; DWORD patternLength = (DWORD)strlen(wildcard);
							__try
							{
								for (DWORD j = 0; j < patternLength; j++)
								{
									found &= wildcard[j] == '?' || pattern[j] == *(char*)(z + j);
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER) { };
							if (found)
							{
								mmap->base_address = (LPVOID)ptr;
								mmap->AllocatedBase = i->AllocationBase;
								mmap->AllocatedProtect = i->AllocationProtect;
								mmap->AllocatedSize = i->RegionSize;
								mmap->detectionType = MMAP_CRT_STUB;
								scanData->NotifyCallback(mmap);
								break;
							}
						}
						else if (scanData->scanType == MDE_SCANTYPE::MMAP_DLL_HEADERS)
						{
							__try
							{
								PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(LPVOID)z;
								if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
								{
									PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)z + dosHeader->e_lfanew);
									if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
									{
										if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
										{
											mmap->base_address = (LPVOID)ptr;
											mmap->AllocatedBase = i->AllocationBase;
											mmap->AllocatedProtect = i->AllocationProtect;
											mmap->AllocatedSize = i->RegionSize;
											mmap->detectionType = MMAP_DLL_HEADERS;
											scanData->NotifyCallback(mmap);
											break;
										}
									}
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER) { };
						}
					}
				}
			}
			ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
		}
	}
	void __cdecl ScanForDllThread(void *scanner_data)
	{
		PSCANNER_DATA scanData = (PSCANNER_DATA)scanner_data;
		typedef NTSTATUS(__stdcall *tNtQueryInformationThread)
		(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
		PVOID ThreadInformation, ULONG ThreadInformationLength,
		PULONG ReturnLength); tNtQueryInformationThread NtQueryInformationThread =
		(tNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtQueryInformationThread");
		THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
				{
					HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
					if (targetThread)
					{
						SuspendThread(targetThread); COMPATIBLE_DWORD tempBase = 0x0;
						NtQueryInformationThread(targetThread, (THREADINFOCLASS)9,
						&tempBase, sizeof(COMPATIBLE_DWORD), NULL);
						ResumeThread(targetThread); CloseHandle(targetThread);
						if (!IsMemoryInModuledRange((LPVOID)tempBase))
						{
							MMAP_INFO mmap; MEMORY_BASIC_INFORMATION mme;
							VirtualQueryEx(GetCurrentProcess(), (LPCVOID)tempBase, &mme, sizeof(th32.dwSize));
							mmap.base_address = (LPVOID)tempBase;
							mmap.AllocatedBase = mme.AllocationBase;
							mmap.AllocatedProtect = mme.AllocationProtect;
							mmap.AllocatedSize = mme.RegionSize;
							mmap.detectionType = MMAP_DLL_THREAD;
							scanData->NotifyCallback(&mmap);
							break;
						}
					}
				}
			}
			while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
	}
	void __cdecl ScanForCheats(void *scanner_data)
	{
		PSCANNER_DATA scanData = (PSCANNER_DATA)scanner_data; 
		MEMORY_BASIC_INFORMATION mme; MMAP_INFO mmap;
		WatchMemoryAllocations(scanData, &mmap, START_ADDRESS, END_ADDRESS, &mme, sizeof(MEMORY_BASIC_INFORMATION));
	}
	void __cdecl MemoryScanner(MDE_SCANTYPE scanType, CallbackMDE NotifyCallback)
	{
		auto InitThisThread = [&, NotifyCallback](SCANNER_DATA &scn) -> void
		{
			memset(&scn, 0, sizeof(SCANNER_DATA));
			scn.NotifyCallback = NotifyCallback;
			scn.scanType = scanType;
		};
		static SCANNER_DATA scn; InitThisThread(scn);
		if (scanType == MDE_SCANTYPE::MMAP_DLL_THREAD)
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ScanForDllThread, (void*)&scn, 0, 0);
		else CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ScanForCheats, (void*)&scn, 0, 0);
	}
}