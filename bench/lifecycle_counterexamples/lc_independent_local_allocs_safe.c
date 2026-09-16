#include <stdlib.h>
typedef struct obj { int slot; } obj;
void sink(obj *handle);

/* Both handles are distinct fresh local allocations; they cannot alias. */
void independent_locals(void)
{
    obj *kept = malloc(sizeof *kept);
    obj *dropped = malloc(sizeof *dropped);
    free(dropped);
    sink(kept);
}
