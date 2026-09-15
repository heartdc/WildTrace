#include <string.h>

void consume(const void *src) {
    char buf[32];
    memcpy(buf, src, 16);
}

int main(void) { char src[32] = {0}; consume(src); return 0; }
