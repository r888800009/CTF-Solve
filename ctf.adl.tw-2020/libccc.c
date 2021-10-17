#include <stdio.h>
#include <unistd.h>

int n;

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    write(1, &stdin, 8);  // leak libc addr
}

int main() {
    char str[0x40];

    init();
    puts("===== String Concatenate =====");

    puts("Enter one string: ");
    n = read(0, str, 0x40);
    if (str[n - 1] == '\n') {  // remove newline
        n--;
    }

    puts("Enter another: ");
    n += read(0, str + n, 0x40);
    str[n] = '\0';

    printf("Here's your result! %s\n", str);

    return 0;
}
