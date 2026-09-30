#include <stdio.h>

void consume(const char *name) {
    char buf[64];
    sprintf(buf, "value=%s", name);
}

int main(void) { consume("seed"); return 0; }
