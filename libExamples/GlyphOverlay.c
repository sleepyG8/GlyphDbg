// Example Use for Glyph bindings in C
// Sleepy 2026

// Feel free to extend this however you want just make sure to give credit where its due.

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef struct {
    void* address;
} sexportAddr;

typedef struct {
    char name[128];
    int timesCalled;
    int currentAddressCount;
    sexportAddr addr[300];
} sexportData;

typedef struct {
    char name[150];
    void* address;
} HookedFunctions;

typedef struct {
    char name[128];
    FARPROC address;
} Imports;

typedef struct {
    char name[100];
    void* address;
    int timesCalled;
} exports;

typedef struct {
    wchar_t modName[MAX_PATH];
    FARPROC modAddress;
    exports* export;
    unsigned long exportCount;
} Dlls;

int readExports(void* hProcess, void* exportList) {
    sexportData* exports = malloc(1000 * sizeof(sexportData));
    int res = 0;
    if (!ReadProcessMemory(hProcess, exportList, exports, sizeof(sexportData) * 1000, &res)) return 1;

    for (int i=0; i < res / sizeof(sexportData); i++) {
        printf("%lu Export: %s\t Times Called: %lu\n", i ,exports[i].name, exports[i].timesCalled);
        if (exports[i].timesCalled == 00) return 0;

        for (int p=0; p < exports[i].timesCalled; p++) {
            printf("0x%p\n", exports[i].addr[p].address);
        }
    }

    return 0;
}

int readHooked(void* hProcess, void* hookedList) {
    
    HookedFunctions hooked[100];
    ReadProcessMemory(hProcess, hookedList, &hooked, sizeof(hooked), NULL);
        
    for (int i=0; i < 100; i++) {
        if (hooked[i].address == 00) break;
        printf("Hooked: %s [0x%p]\n", hooked[i].name, hooked[i].address);
    }

    return 0;
}

int readModules(void* hProcess, void* moduleStruct) {
            
    Dlls modules[300];
    ReadProcessMemory(hProcess, moduleStruct, &modules, sizeof(modules), NULL);
        
    for (int i=0; i < 300; i++) {
        if (modules[i].modAddress == 00) break;
        printf("%S\n", modules[i].modName);
    }

    return 0;
}

int readImports(void* hProcess, void* ImportStruct) {
    
    Imports imports[500];
    ReadProcessMemory(hProcess, ImportStruct, &imports, sizeof(imports), NULL);
        
    for (int i=0; i < 500; i++) {
        if (imports[i].address == 00) break;
        printf("%s - 0x%p\n", imports[i].name, imports[i].address);
    }

    return 0;
}

typedef struct GlyphHandle {
    void* hproc;
    void* base;
} GlyphHandle;

// Retrieve data from Glyph. Pass the desired struct as name. and the PE base as baseAddress.
void* GlyphGetHandle(GlyphHandle* in, char* name) {

void* baseAddress = in->base;
void* hProcess = in->hproc;

IMAGE_DOS_HEADER dh;
if (!ReadProcessMemory(hProcess, baseAddress, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) return 3;

if (dh.e_magic != IMAGE_DOS_SIGNATURE) return 1;

IMAGE_NT_HEADERS64 nt;
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) return 1;

IMAGE_OPTIONAL_HEADER oh;
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader), &oh, sizeof(IMAGE_OPTIONAL_HEADER), NULL)) return 1;

BYTE* importDescAddr = (BYTE*)baseAddress + oh.DataDirectory[0].VirtualAddress;

IMAGE_EXPORT_DIRECTORY id;
if (!ReadProcessMemory(hProcess, importDescAddr, &id, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) return 1;

DWORD* addressOfNames = (DWORD*)((BYTE*)baseAddress + id.AddressOfNames);
DWORD* AddressOfFunctions = (DWORD*)((BYTE*)baseAddress + id.AddressOfFunctions);
WORD* ordinaladdr = (WORD*)((BYTE*)baseAddress + id.AddressOfNameOrdinals);

for (int i=0; i < id.NumberOfNames; i++) {

    DWORD nameRVA;
    if (!ReadProcessMemory(hProcess, &addressOfNames[i], &nameRVA, sizeof(DWORD), NULL)) break;

    WORD currentOrdinal;
    if (!ReadProcessMemory(hProcess, &ordinaladdr[i], &currentOrdinal, sizeof(WORD), NULL)) break;

    DWORD rva;
    if (!ReadProcessMemory(hProcess, &AddressOfFunctions[currentOrdinal], &rva, sizeof(DWORD), NULL)) break;
    
    char nameBuff[100];
    ReadProcessMemory(hProcess, (BYTE*)baseAddress + nameRVA, &nameBuff, sizeof(nameBuff), NULL);

    if (strcmp(name, nameBuff) == 0) {
        return (void*)((BYTE*)baseAddress + rva);
    }

}

return 4;
}

//defined my own PEB to get BITFIELD and other structures in the future
typedef struct _MYPEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
        union {
        BYTE BitField;
        struct {
            BYTE ImageUsesLargePages : 1;
            BYTE IsProtectedProcess : 1;
            BYTE IsImageDynamicallyRelocated : 1;
            BYTE SkipPatchingUser32Forwarders : 1;
            BYTE IsPackagedProcess : 1;
            BYTE IsAppContainer : 1;
            BYTE IsProtectedProcessLight : 1;
            BYTE IsLongPathAwareProcess : 1;
        };
    };
    union {
    ULONG CrossProcessFlags;
    struct {
        ULONG ProcessInJob : 1;
        ULONG ProcessInitializing : 1;
        ULONG ProcessUsingVEH : 1;
        ULONG ProcessUsingVCH : 1;
        ULONG ProcessUsingFTH : 1;
        ULONG ReservedBits0 : 27;
    };
};
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} MYPEB;

MYPEB pbi;
unsigned long long GetGlyph(GlyphHandle* out, char* procName) {

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    char procString[128];
    snprintf(procString, 128, "fiberdebug.exe -c %s -api", procName);

    BOOL success = CreateProcessA(
        NULL,                  // Application name
        procString,         // Command line
        NULL,                  // Process security
        NULL,                  // Thread security
        FALSE,                 // Inherit handles
        NULL,      // ← Suspended flag
        NULL,                  // Environment
        NULL,                  // Current directory
        &si,                   // Startup info
        &pi                    // Process info
    );

    void* hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProcess) return 3;

    void* (*NtQueryInformationProcess)() = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION proc = {0};
    ULONG returnlen;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc, sizeof(PROCESS_BASIC_INFORMATION), &returnlen);
    if (status != 0) return 3;

    if (!ReadProcessMemory(hProcess, proc.PebBaseAddress, &pbi, sizeof(pbi), NULL)) return 3;

    unsigned long long imageBase = 0;
    ReadProcessMemory(hProcess, (BYTE*)proc.PebBaseAddress + 0x10, &imageBase, sizeof(unsigned long long), NULL);
    
    out->base = imageBase;
    out->hproc = hProcess;

    Sleep(2000);

    return 0;
    
    }

int GlyphSendCommandA(GlyphHandle* out, void* apiInAddress, unsigned char* command) {
    
    if (strlen(command) >= 120) return 3;

    unsigned char data[120];
    data[0] = 0xDE;
    data[1] = 0xAD;

    int i;
    for (i = 0; i < strlen(command); i++) {
        data[i+2] = command[i];
    }

    if (data[i+1] != '\n') {
        data[i+2] = '\n';
    }    

    if (!WriteProcessMemory(out->hproc, apiInAddress, data, strlen(command) + 3, 0)) {
        return 1;
    }

    return 0;
}

int GlyphCloseHandle(GlyphHandle* out) {
    if (!TerminateProcess(out->hproc, 0)) return 1;
    return 0;
}

int main(int argc, char* argv[]) {
    
    // Startup Glyph and get GlyphHandle
    GlyphHandle out;
    if (GetGlyph(&out, argv[1]) != 0) return 0;

    // Get address of structure
    HANDLE* modules = GlyphGetHandle(&out, "modules");
    if (!modules) return 0;
    
    // Read Dll List
    //readModules(out.hproc, modules);

    HANDLE* ImportList = GlyphGetHandle(&out, "imports");
    if (!ImportList) return 0;

    // Read Imports
    //readImports(out.hproc, ImportList);

    HANDLE* hookedList = GlyphGetHandle(&out, "hooked");

    // Get Hooks
    //readHooked(out.hproc, hookedList);

    HANDLE* exportList = GlyphGetHandle(&out, "exportData");

    // Get exports
    //readExports(out.hproc, exportList);

    HANDLE* commandBuff = GlyphGetHandle(&out, "apiIn");

    while(1) {
    unsigned char buff[120];
    fgets(buff, 120, stdin);
    if (buff[0] == 'q' && buff[1] == '\n') break;
    GlyphSendCommandA(&out, commandBuff, buff);
    }

    GlyphCloseHandle(&out);

    return 0;
}
