#include <stddef.h>
typedef struct cJSON { struct cJSON *next, *child; int type; char *valuestring; } cJSON;
cJSON *cJSON_Duplicate(const cJSON *item, int recurse);
void cJSON_Delete(cJSON *item);

/* The reviewed fix from cases/cjson_merge_alias/patch.diff: duplicate the
 * borrowed patch BEFORE deleting target, so no handle is used after free. */
cJSON *merge_patch_nonobject_fixed(cJSON *target, cJSON *patch)
{
    cJSON *duplicate = cJSON_Duplicate(patch, 1);
    cJSON_Delete(target);
    return duplicate;
}
