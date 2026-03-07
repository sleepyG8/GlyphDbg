#include <Windows.h>

typedef struct {
    char option[28];
} storage;

storage iteration[128];

int zeroStruct() {
    for (int i=0; i < 128; i++) {
        strcpy(iteration[i].option, "NULL");
    }
}

__declspec(dllexport) int __stdcall cmdPack(char* option, int getHistory, int startUp)  {

    if (startUp == 1) {
        zeroStruct();
    }

    if (option[0] == 0) return 0;

    if (strcmp(option, "!noob") == 0) {
        printf("Welcome to the Tutorial:\n");
        printf("Coming soon...\n");
        return 0;
    }

    // cpy into global struct
    for (int i=0; i < 128; i++) {
        if (strcmp(option, "!history") == 0) break;
        if (strcmp(iteration[i].option, "NULL") == 0) {
            if (strlen(option) > 28) break;
            strcpy(iteration[i].option, option);
            break;
        }
    }

    if (strcmp(option, "!history") == 0) {
        for (int i=0; i < 128; i++) {
            if (strcmp(iteration[i].option, "NULL") == 0) break;
            printf("[%lu] %s\n", i, iteration[i].option);
        }
    }


    return 0;
}
