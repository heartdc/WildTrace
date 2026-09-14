#include <string.h>

void consume(const char *src) {
    char buf[64];
    strcpy(buf, src);
}

int main(void) { consume("seed"); return 0; }
