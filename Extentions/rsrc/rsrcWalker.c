// Walking the resource directory of the PE
// Compile with cl /LD rsrcWalker.c


#include <Windows.h>
#include <stdio.h>

BYTE* VAFromRVA(DWORD rva, PIMAGE_NT_HEADERS nt, BYTE* base) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD sectionVA = section->VirtualAddress;
        DWORD sectionSize = section->Misc.VirtualSize;

        if (rva >= sectionVA && rva < (sectionVA + sectionSize)) {
            return base + section->PointerToRawData + (rva - sectionVA);
        }
    }

    return NULL;
}

int getImg = 0;

int walkResource(BYTE* final, IMAGE_RESOURCE_DIRECTORY* id, PIMAGE_NT_HEADERS nt) {

        IMAGE_RESOURCE_DIRECTORY_ENTRY* entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((BYTE*)id + sizeof(IMAGE_RESOURCE_DIRECTORY));

        printf("Num of Named Entries: %lu\n", id->NumberOfNamedEntries);

        int numOfEntries = id->NumberOfIdEntries + id->NumberOfNamedEntries;

        printf("Num of ID Entries: %lu\n", id->NumberOfIdEntries);

        for (int i=0; i < numOfEntries; i++) {

            IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = &entries[i];

            if (entry->NameIsString) {
        
                IMAGE_RESOURCE_DIR_STRING_U* nameStr = final + entry->NameOffset;
        
                wprintf(L"Named Entry: %ws\n", nameStr->NameString);
    
            }

    
            if (entry->DataIsDirectory) {

                printf("Is directory\n");
    
                IMAGE_RESOURCE_DIRECTORY* subDir = (IMAGE_RESOURCE_DIRECTORY*)((BYTE*)id + (entry->OffsetToDirectory));
                if (!subDir) continue;

                printf("Subdirectory at: 0x%p\n", subDir);

                // for (int i=0; i < 100; i++) {
                //     printf("%02X ", ((unsigned char*)subDir)[i]);
                // }
 
                walkResource(final, subDir, nt);
    
            } else {

                BYTE* resourceDate = entry->OffsetToData + id;
                IMAGE_RESOURCE_DATA_ENTRY* dataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)((BYTE*)final + entry->OffsetToData);

                printf("Resource Data at RVA: 0x%p, Size: %p\n", resourceDate, dataEntry->Size);

                if (dataEntry->Size != 0 && getImg) {
                for (int j=0; j < 500; j++) {
                    printf("%02X ", resourceDate[j]);
                }
                getImg = 0;
                }

                if (dataEntry->Size == 0) return 0;

            }
    
        }

        return 0;
    }

__declspec(dllexport) int __stdcall getRsrc(char* filePath)  {
        
        FILE* file = fopen(filePath, "rb");

        if (!file) return 0;

        fseek(file, 0, SEEK_END);
        size_t size = ftell(file);
        fseek(file, 0, SEEK_SET);

        BYTE* final = malloc(size);

        fread(final, 1, size, file);

        PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)final;
        if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        
        // Read NT headers
        DWORD e_lfanew = *(DWORD*)(final + 0x3C);
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
           return FALSE;
        }


        // Get Optional Header
        PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

        // Locate Import Table
        IMAGE_RESOURCE_DIRECTORY* id = (IMAGE_RESOURCE_DIRECTORY*)VAFromRVA(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, nt, final);

        if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == 0) return 0;

        // for (int i=0; i < 100; i++){
        //     printf("%02X ", ((unsigned char*)id)[i]);
        // }

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        PIMAGE_SECTION_HEADER rsrc = NULL;

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (sec->VirtualAddress == nt->OptionalHeader.DataDirectory[2].VirtualAddress) {
                rsrc = sec;
                break;
            }
        }

        BYTE* rsrcBase = final + rsrc->PointerToRawData;

        walkResource(rsrcBase, id, nt);
        
        return 0;

}
