#include <stdlib.h>
typedef struct obj { int slot; } obj;
void sink(obj *handle);

/* Reassignment between delete and use replaces the handle value entirely. */
void reassigned_then_used(obj *stale, obj *replacement)
{
    obj *live = stale;
    free(stale);
    live = replacement;
    sink(live);
}
