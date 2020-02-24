#include<stdio.h>

void baby_shell(){
        system("sh");
}

int main(){
        setvbuf(stdout , 0 , 2 , 0);
        puts("====== Baby Pwn Challenge ======");
        puts("You need to take one trash line to continue");
        puts("Your payload = ");
        char buf[100];
        gets(buf);
        return 0;
}