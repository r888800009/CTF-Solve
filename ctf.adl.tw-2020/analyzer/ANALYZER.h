#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>


struct INFO {
    char key[11];
    char* const code;
    char* const data;
};

void init(char* code);
void read_pass(char* key);
void decrypt_code(const char* key, char* code);
void read_data(char* data);
void check_data(const char* data, int len);
