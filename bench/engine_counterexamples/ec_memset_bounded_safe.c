#include <string.h>

void consume(void) {
    char buf[64];
    memset(buf, 0, sizeof(buf));
}

int main(void) { consume(); return 0; }
