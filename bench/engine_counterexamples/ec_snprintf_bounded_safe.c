#include <stdio.h>

void consume(const char *src) {
    char buf[64];
    snprintf(buf, sizeof(buf), "value=%s", src);
}

int main(void) { consume("seed"); return 0; }
