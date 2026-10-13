// re_features.c - reports which optional capabilities this build was compiled with.
// Module: feature (C11).
// Owns: the compile time feature flags and the string that describes them.
// Depends: none. No I/O, no globals beyond one const string, no parsing.
#include "features/meta/re_features.h"

static const char *const kFeatureNames[] = {
    "utils",    "core",
#ifdef RE_ENABLE_DISASM
    "disasm",
#endif
#ifdef RE_ENABLE_CAPSTONE
    "capstone",
#endif
#ifdef RE_ENABLE_FLIRT
    "flirt",
#endif
};

static const size_t kFeatureCount = sizeof(kFeatureNames) / sizeof(kFeatureNames[0]);

const char *re_features_name(size_t index) {
    return index < kFeatureCount ? kFeatureNames[index] : NULL;
}

size_t re_features_count(void) {
    return kFeatureCount;
}

bool re_features_has(const char *name) {
    for (size_t i = 0; i < kFeatureCount; i++) {
        const char *n = kFeatureNames[i];
        size_t k = 0;
        while (n[k] && name[k] && n[k] == name[k])
            k++;
        if (!n[k] && !name[k])
            return true;
    }
    return false;
}
