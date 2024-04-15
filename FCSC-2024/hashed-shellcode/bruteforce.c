#include <openssl/sha.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

char shellcode[] = {0x52, 0x5e, 0x0f, 0x05};
char valid[] = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
unsigned int valid_size = sizeof(valid) / sizeof(valid[0]) - 1;

int main() {
    struct SHA256state_st ctx;
    srand(time(NULL));

    while (1) {
        char attempt[0x20] = "FCSC_";
        char attempt2[0x20];
        for (int i = 5; i <= sizeof(attempt); i++) {
            attempt[i] = valid[(unsigned int)rand() % valid_size];
        }

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, attempt, sizeof(attempt));
        SHA256_Final(attempt2, &ctx);

        if (memcmp(shellcode, attempt2, sizeof(shellcode)) == 0) {
            puts("found:");
            write(0, attempt, 0x20);
            putchar('\n');
        }
    }
}