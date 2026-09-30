#include <stdlib.h>

void consume(size_t n) {
    char *p = malloc(n);
    p[0] = 'x';
}

int main(void) { consume(64); return 0; }
