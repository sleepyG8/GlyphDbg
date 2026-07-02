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
    unsigned char engineName[0x20];
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

int GetGlyph(GlyphHandle* out, char* procName) {

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    char procString[128];
    snprintf(procString, 128, "%s -c %s -api", out->engineName, procName);

    BOOL success = CreateProcessA(NULL, procString, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);

    void* hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProcess) return 3;

    NTSTATUS (*NtQueryInformationProcess)() = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

    unsigned char proc[48];
    unsigned long returnlen = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc, sizeof(proc), &returnlen);
    if (status != 0) return 3;

    unsigned char peb[0x98];
    if (!ReadProcessMemory(hProcess, *(unsigned long long**)(proc + 0x08), &peb, sizeof(peb), NULL)) return 3;

    unsigned long long imageBase = *(unsigned long long**)(peb + 0x10);
    
    out->base = imageBase;
    out->hproc = hProcess;

    Sleep(2000);

    return 0;
    
}

int wideToChar(wchar_t* word, char* out, int size) {

    for (int i=0; i < size; i++) {
        if (word[i] == 00 && word[i+1] == 00) {
            out[i] = 00;
            break;
        }
        if (word[i] == 00) continue;
        out[i] = word[i];
    }
    
    return 0;
}

int wideLen(wchar_t* word) {
    for (int i=0; i < MAX_PATH; i++) {
        if (word[i] == 00 && word[i+1] == 00) return i+1;
    }
}

unsigned long long GlyphConnect(GlyphHandle* out, char* GlyphEXEName, char* sessionName) {
 
    unsigned long res = 0;
    void* (*NtQuerySystemInformation)() = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
    NtQuerySystemInformation(5, NULL, NULL, &res);
    SYSTEM_PROCESS_INFORMATION* procBuff = malloc(res);
    NtQuerySystemInformation(5, procBuff, res, &res);

    for (int i=0; ; i++) {

        unsigned char narrow[1028];
        wideToChar(procBuff->ImageName.Buffer, &narrow, procBuff->ImageName.Length);

        if (procBuff->ImageName.Buffer && strcmp(narrow, GlyphEXEName) == 0) {
            
            void* hproc = OpenProcess(PROCESS_ALL_ACCESS, 1, procBuff->UniqueProcessId);
            if (!hproc) return 3;

            PSYSTEM_THREAD_INFORMATION threads = (PSYSTEM_THREAD_INFORMATION)(procBuff + 1);
            void* hThread = OpenThread(THREAD_ALL_ACCESS, 1, threads[0].ClientId.UniqueThread);
            if (!hThread) {
                if (procBuff == (unsigned char*)procBuff + procBuff->NextEntryOffset) break;
                procBuff = (unsigned char*)procBuff + procBuff->NextEntryOffset;
                continue;
            }

            void* (*qit)() = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
            unsigned char tbi[0x30];
            NTSTATUS status = qit(hThread, 0, &tbi, sizeof(tbi), NULL);
            if (!NT_SUCCESS(status)) return 3;

            unsigned long long teb = *(unsigned long long**)((unsigned char*)tbi + 8);

            unsigned char peb[0x98];
            if (!ReadProcessMemory(hproc, teb - 0x1000, &peb, sizeof(peb), 0)) return 3;

            unsigned long long params = *(unsigned long long**)(peb + 0x20);
            unsigned long long commandPointer = 0;
            ReadProcessMemory(hproc, params + 0x78, &commandPointer, sizeof(unsigned long long), 0);

            unsigned char commandLine[1028];
            ReadProcessMemory(hproc, commandPointer, &commandLine, sizeof(commandLine), 0);
    
            unsigned char outLine[128];
            for (int p=0; p < 1028; p++) {
                if (commandLine[p] == '-' && commandLine[p+2] == 'c') {
                    for (int j=0; j < 128; j++) {
                        if (commandLine[p+6+j] == 0x20) {
                            outLine[j] = 00;
                            outLine[j+1] = 00;
                            break;
                        }
                            outLine[j] = commandLine[p+6+j];
                    }
                }
            }

            unsigned char outnarrow[1028];
            wideToChar(outLine, &outnarrow, wideLen(outLine));

            if (strcmp(sessionName, outnarrow) == 0) {
            out->hproc = hproc;
            out->base = *(unsigned long long**)(peb + 0x10);
            return 0;
            }

        }

        if (procBuff == (unsigned char*)procBuff + procBuff->NextEntryOffset) break;
        procBuff = (unsigned char*)procBuff + procBuff->NextEntryOffset;
    }

    return 1;
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

int GlyphDump(GlyphHandle* out, void* commandBuff, unsigned char* address) {

    GlyphSendCommandA(out, commandBuff, address);
    Sleep(1000);
    HANDLE* inBuffFromGlyph = GlyphGetHandle(out, "apiOut");
    unsigned char buff[0x1000];
    ReadProcessMemory(out->hproc, inBuffFromGlyph, &buff, sizeof(buff), 0);

    for (int i=0; i < sizeof(buff); i++) {
        printf("%02X ", buff[i]);
        if (*(wchar_t*)(buff + i) == 0xADDE) {
            //WriteProcessMemory(out.hproc, inBuffFromGlyph, 00, 0x1000, 0);    // overwrite whole buffer
            break;
        }
    }

}

int main(int argc, char* argv[]) {

    //Glyphs handle. If base or hproc is 0 after initialization. Getting internal Handles will fail.
    GlyphHandle out;

    if (argc >= 3) {
    //This Starts a brand new RE session (Will fail with Glyph Error code 4)
    if (strcmp(argv[1], "start") == 0) {
    if (strlen(argv[2]) > sizeof(out.engineName)) return 4;
    strncpy(out.engineName, argv[2], sizeof(out.engineName));
    int res = GetGlyph(&out, argv[3]);
    if (res != 0) return 4;
    return 0;
    }
    }

    //Handle Commands 
    if (argc >= 3) { 

    //Connect to a already running Glyph session (Will fail with Glyph Error code 4)
    if (GlyphConnect(&out, argv[1], argv[2]) != 0) return 4;

    HANDLE* commandBuff = GlyphGetHandle(&out, "apiIn");

    if (argv[3][0] == '0' && argv[3][1] == 'x') { // address check
    GlyphDump(&out, commandBuff, argv[3]);
    return 0;
    }

    if (strcmp(argv[3], "!modules") == 0) {
    //Get Handle to structure
    HANDLE* modules = GlyphGetHandle(&out, "modules");
    if (!modules) return 0;
    
    //Read Dll List
    readModules(out.hproc, modules);
    return 0;
    }

    if (strcmp(argv[3], "!imports") == 0) {
    //Get Handle to structure
    HANDLE* ImportList = GlyphGetHandle(&out, "imports");
    if (!ImportList) return 0;

    //Read Imports
    readImports(out.hproc, ImportList);
    return 0;
    }

    if (strcmp(argv[3], "!hooked") == 0) {
    HANDLE* hookedList = GlyphGetHandle(&out, "hooked");
    //Get Hooks
    readHooked(out.hproc, hookedList);
    return 0;
    }

    if (strcmp(argv[3], "!graph") == 0) {
    HANDLE* exportList = GlyphGetHandle(&out, "exportData");
    //Get exports
    readExports(out.hproc, exportList);
    return 0;
    }

    if (strcmp(argv[3], "!shutdown") == 0) {
    //Shutdown and cleanup (Only call when you want main engine to die)
    GlyphCloseHandle(&out);
    return 0;
    }

    GlyphSendCommandA(&out, commandBuff, argv[3]);
    printf("Command sent to Glyph\n");
    return 0;
    }

    printf("Start a MotherShip: start <engine name> <procName>\t Send Command: <command> <engine name> <debugee name>\n");

    return 0;
}
