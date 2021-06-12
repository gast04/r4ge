#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAG "thank_you_for_using_r4ge"

int check(char *in) {
    int ret = 1;
    int len = strlen(FLAG);
    ret = strncmp(in, FLAG, len);
    return ret == 0;
}

void hello() {
    puts("Hello, radare2 and r4ge");
}

int main() {
    hello();
    char *buf = malloc(0x20);
    printf("input: ") ;
    fgets(buf, 0x1f, stdin);
    if (check(buf)) 
        puts("Correct!");
    else
        puts("Incorrect!");

    return 0;
}

__attribute__((constructor))
void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}
