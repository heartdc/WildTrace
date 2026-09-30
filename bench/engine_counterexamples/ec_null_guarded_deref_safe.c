#include <stdlib.h>

void consume(char *p) {
    if (p) {
        p[0] = 'x';
    }
}

int main(void) { consume(0); return 0; }
