#include <stdio.h>
#include <stdlib.h>
typedef char byte;

void decrypt_code(char *key, char *code)

{
  byte tmp;
  uint uVar1;
  int iVar2;
  int k;
  uint index;
  int i;
  byte arr[256];

  k = 0;
  while (k < 0x100) {
    arr[k] = (byte)k;
    k = k + 1;
  }
  k = 0;
  index = 0;
  while (k < 0x100) {
    index = (uint)(byte)key[k % 0xb] + arr[k] + index + 0x57 & 0xff;
    tmp = arr[k];
    arr[k] = arr[index];
    arr[index] = tmp;
    k = k + 1;
  }

  i = 0;
  index = 0;
  while (i < 0x4) {
    uVar1 = (uint)(i + 1 >> 0x1f) >> 0x18;
    iVar2 = (i + 1 + uVar1 & 0xff) - uVar1;
    index = arr[iVar2] + index & 0xff;
    tmp = arr[iVar2];
    arr[iVar2] = arr[index];
    arr[index] = tmp;
    code[i] = code[i] ^ arr[(byte)(arr[index] + arr[iVar2])];
    i = i + 1;
  }
  return;
}

int main(int argc, char *argv[]) {
  char *first3bytes = "\b\x7b\xba";
  char key[11];
  for (long i = 0; i < 0xffffffffff; i++) {
    char tmp[4] = "";
    memset(key, 0, 11);
    strcpy(key, (char *)&i);
    key[9] = '\xcd';
    key[10] = '\x80';
    strcpy(tmp, first3bytes);
    decrypt_code(key, tmp);
    tmp[2] = 0;
    if (strcmp(tmp, "[\xc3") == 0) {
      printf("%p\n", i);
      decrypt_code(key, tmp);
      printf("%x %x\n", tmp[0], tmp[1]);
      return 0;
    }
  }

  return 0;
}

