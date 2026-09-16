#include <stddef.h>
typedef struct cJSON { struct cJSON *next, *child; int type; char *valuestring; } cJSON;
cJSON *cJSON_Duplicate(const cJSON *item, int recurse);
void cJSON_Delete(cJSON *item);

/* Reduced from cJSON_Utils.c merge_patch() non-object branch at pinned
 * commit 388cfc96; public known case, see cases/cjson_merge_alias.
 * Deleting target frees memory patch may alias (patch == target or an
 * owned subtree), so duplicating patch afterwards reads freed memory. */
cJSON *merge_patch_nonobject(cJSON *target, cJSON *patch)
{
    cJSON_Delete(target);
    return cJSON_Duplicate(patch, 1);
}
