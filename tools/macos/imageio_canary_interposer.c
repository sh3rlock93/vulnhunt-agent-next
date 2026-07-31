/*
 * Reviewed allocator canary for the analyst-owned ImageIO harness process.
 *
 * This dylib is loaded only by the networkless disposable-VM job runner.  It
 * uses malloc-zone entry points to avoid recursively calling the interposed
 * symbols, preserves calloc zero semantics, and fills only newly allocated
 * bytes in the reviewed size interval.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <malloc/malloc.h>

#define VULNHUNT_CANARY_REVISION "m16-canary-interposer-v1"

static _Atomic uint64_t observed_allocations = 0;
static uint8_t configured_canary = 0;
static size_t configured_minimum = 1;
static size_t configured_maximum = 0;
static bool configured = false;

static bool parse_size(const char *value, size_t *result) {
    if (value == NULL || *value == '\0') return false;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (end == value || *end != '\0' || parsed > SIZE_MAX) return false;
    *result = (size_t)parsed;
    return true;
}

__attribute__((constructor))
static void configure_canary(void) {
    size_t byte_value = 0;
    size_t minimum = 0;
    size_t maximum = 0;
    const char *revision = getenv("VULNHUNT_CANARY_REVISION");
    if (revision == NULL || strcmp(revision, VULNHUNT_CANARY_REVISION) != 0 ||
        !parse_size(getenv("VULNHUNT_CANARY_BYTE"), &byte_value) ||
        !parse_size(getenv("VULNHUNT_CANARY_MIN_BYTES"), &minimum) ||
        !parse_size(getenv("VULNHUNT_CANARY_MAX_BYTES"), &maximum) ||
        byte_value > UINT8_MAX || minimum == 0 || minimum > maximum) {
        return;
    }
    configured_canary = (uint8_t)byte_value;
    configured_minimum = minimum;
    configured_maximum = maximum;
    configured = true;
}

static bool should_fill(size_t size) {
    return configured && size >= configured_minimum && size <= configured_maximum;
}

static void fill_new_bytes(void *pointer, size_t offset, size_t size) {
    if (pointer == NULL || size <= offset || !should_fill(size)) return;
    memset((unsigned char *)pointer + offset, configured_canary, size - offset);
    atomic_fetch_add_explicit(&observed_allocations, 1, memory_order_relaxed);
}

static void *vulnhunt_malloc(size_t size) {
    void *pointer = malloc_zone_malloc(malloc_default_zone(), size);
    fill_new_bytes(pointer, 0, size);
    return pointer;
}

static void *vulnhunt_calloc(size_t count, size_t size) {
    /* Never replace calloc's required zero initialization with a canary. */
    return malloc_zone_calloc(malloc_default_zone(), count, size);
}

static void *vulnhunt_realloc(void *old_pointer, size_t size) {
    size_t old_size = old_pointer == NULL ? 0 : malloc_size(old_pointer);
    malloc_zone_t *zone = old_pointer == NULL
        ? malloc_default_zone()
        : malloc_zone_from_ptr(old_pointer);
    void *pointer = malloc_zone_realloc(zone, old_pointer, size);
    fill_new_bytes(pointer, old_size < size ? old_size : size, size);
    return pointer;
}

__attribute__((visibility("default")))
uint64_t vulnhunt_canary_allocation_count(void) {
    return atomic_load_explicit(&observed_allocations, memory_order_relaxed);
}

__attribute__((visibility("default")))
uint8_t vulnhunt_canary_value(void) {
    return configured_canary;
}

__attribute__((visibility("default")))
const char *vulnhunt_canary_revision(void) {
    return VULNHUNT_CANARY_REVISION;
}

#define DYLD_INTERPOSE(_replacement, _replacee)                         \
    __attribute__((used)) static struct {                               \
        const void *replacement;                                        \
        const void *replacee;                                           \
    } _interpose_##_replacee                                            \
        __attribute__((section("__DATA,__interpose"))) = {              \
            (const void *)(uintptr_t)&_replacement,                      \
            (const void *)(uintptr_t)&_replacee,                         \
        }

DYLD_INTERPOSE(vulnhunt_malloc, malloc);
DYLD_INTERPOSE(vulnhunt_calloc, calloc);
DYLD_INTERPOSE(vulnhunt_realloc, realloc);
