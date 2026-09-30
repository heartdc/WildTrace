#include <stdlib.h>
typedef struct obj { int slot; } obj;
void sink(obj *handle);

/* Direct same-handle sequence: the freed pointer is passed to a later call. */
void use_after_free(obj *handle)
{
    free(handle);
    sink(handle);
}
