#include <stdlib.h>

int consume(size_t n) {
    char *p = malloc(n);
    if (p == NULL) {
        return -1;
    }
    p[0] = 'x';
    return 0;
}

int main(void) { return consume(64); }
