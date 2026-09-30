#include <stdlib.h>
typedef struct obj { int slot; } obj;
typedef struct other { long wide; } other;
void use_other(other *handle);

/* Different object types cannot alias; the delete/use sequence is by design. */
void mixed_types(obj *dropped, other *kept)
{
    free(dropped);
    use_other(kept);
}
