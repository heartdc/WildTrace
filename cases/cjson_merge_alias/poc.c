/* Local regression reproducer for the public cJSON MergePatch alias issue.
 * Fixed, tiny inputs only. No network, external input, or exploit payload.
 * In alias modes the library consumes target AND its borrowed patch subtree.
 * The caller deliberately never deletes either stale pointer after merging.
 */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

int main(int argc, char **argv)
{
    cJSON *target = NULL, *patch = NULL, *result = NULL, *expected = NULL;
    const char *want = NULL;
    int owns_patch = 0, sensitive = 0, ok;
    if (argc < 2 || argc > 3) return 64;
    if (argc == 3) {
        if (strcmp(argv[2], "sensitive")) return 64;
        sensitive = 1;
    }
    if (!strcmp(argv[1], "subtree")) {
        target = cJSON_Parse("{\"payload\":[1,2,3],\"keep\":true}");
        if (!target) return 70;
        patch = cJSON_GetObjectItemCaseSensitive(target, "payload");
        want = "[1,2,3]";
    } else if (!strcmp(argv[1], "scalar-subtree")) {
        target = cJSON_Parse("{\"payload\":7}");
        if (!target) return 70;
        patch = cJSON_GetObjectItemCaseSensitive(target, "payload");
        want = "7";
    } else if (!strcmp(argv[1], "self-array")) {
        target = cJSON_Parse("[1,2,3]");
        patch = target;
        want = "[1,2,3]";
    } else if (!strcmp(argv[1], "independent")) {
        target = cJSON_Parse("{\"a\":1}");
        patch = cJSON_Parse("[{\"b\":2}]");
        owns_patch = 1;
        want = "[{\"b\":2}]";
    } else if (!strcmp(argv[1], "detached")) {
        target = cJSON_Parse("{\"payload\":[1,2,3]}");
        if (!target) return 70;
        patch = cJSON_DetachItemFromObjectCaseSensitive(target, "payload");
        owns_patch = 1;
        want = "[1,2,3]";
    } else if (!strcmp(argv[1], "object-merge")) {
        target = cJSON_Parse("{\"a\":1,\"keep\":[1,2]}");
        patch = cJSON_Parse("{\"a\":2,\"add\":3}");
        owns_patch = 1;
        want = "{\"a\":2,\"keep\":[1,2],\"add\":3}";
    } else if (!strcmp(argv[1], "object-delete")) {
        target = cJSON_Parse("{\"a\":1,\"keep\":2}");
        patch = cJSON_Parse("{\"a\":null}");
        owns_patch = 1;
        want = "{\"keep\":2}";
    } else return 64;
    if (!target || !patch) {
        if (owns_patch) cJSON_Delete(patch);
        cJSON_Delete(target);
        return 70;
    }
    result = sensitive ? cJSONUtils_MergePatchCaseSensitive(target, patch)
                       : cJSONUtils_MergePatch(target, patch);
    /* MergePatch may destroy target. Never use/delete target again. */
    target = NULL;
    if (!owns_patch) patch = NULL;
    expected = cJSON_Parse(want);
    ok = result && expected && cJSON_Compare(result, expected, 1);
    cJSON_Delete(result);
    cJSON_Delete(expected);
    if (owns_patch) cJSON_Delete(patch);
    if (!ok) return 71;
    printf("CASE_OK %s %s\n", argv[1], sensitive ? "sensitive" : "normal");
    return 0;
}
