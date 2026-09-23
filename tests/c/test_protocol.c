#include <assert.h>
#include <string.h>
#include "omni_protocol.h"

int main(void) {
    unsigned char storage[sizeof(omni_mm_header) + 8] = {0};
    omni_mm_header *h = (omni_mm_header *)storage;
    h->magic = OMNI_MM_MAGIC;
    h->version = OMNI_MM_VERSION;
    h->command = 1;
    h->payload_size = 8;
    assert(omni_mm_validate(h, sizeof(storage)) == OMNI_OK);
    h->magic = 0;
    assert(omni_mm_validate(h, sizeof(storage)) == OMNI_ERR_MAGIC);
    h->magic = OMNI_MM_MAGIC;
    h->payload_size = OMNI_MM_MAX_PAYLOAD + 1;
    assert(omni_mm_validate(h, sizeof(storage)) == OMNI_ERR_SIZE);

    omni_a11y_node node = { .id = 1, .name_length = 4, .value_length = 0 };
    assert(omni_a11y_validate(&node) == OMNI_OK);
    node.state = OMNI_A11Y_PASSWORD;
    node.value_length = 6;
    assert(omni_a11y_validate(&node) == OMNI_ERR_SECRET);
    return 0;
}
