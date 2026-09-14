#include <stdlib.h>

void consume(size_t n) {
    char *p = malloc(n);
    free(p);
    free(p);
}

int main(void) { consume(64); return 0; }
