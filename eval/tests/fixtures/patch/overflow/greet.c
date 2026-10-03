/* The patch-quality loop's synthetic case: a stack overflow with a reproducer. */
#include <stdio.h>
#include <string.h>

static void greet(const char *name) {
    char buf[16];
    strcpy(buf, name);
    printf("hello %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    greet(argv[1]);
    return 0;
}
