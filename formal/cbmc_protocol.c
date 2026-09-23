#include <assert.h>
#include <stddef.h>
#include "omni_protocol.h"

static void prove_mm_contract(void) {
    omni_mm_header h;
    size_t size;
    omni_status result = omni_mm_validate(&h, size);

    if (result == OMNI_OK) {
        assert(size >= sizeof(h));
        assert(h.magic == OMNI_MM_MAGIC);
        assert(h.version == OMNI_MM_VERSION);
        assert(h.payload_size <= OMNI_MM_MAX_PAYLOAD);
        assert((size_t)h.payload_size <= size - sizeof(h));
        assert(h.command >= 1 && h.command <= 16);
    }
}

static void prove_password_redaction(void) {
    omni_a11y_node node;
    omni_status result = omni_a11y_validate(&node);

    if ((node.state & OMNI_A11Y_PASSWORD) != 0 && node.value_length != 0) {
        assert(result != OMNI_OK);
    }
    if (result == OMNI_OK) {
        assert(node.name_length > 0);
        assert((node.state & OMNI_A11Y_PASSWORD) == 0 || node.value_length == 0);
    }
}

int main(void) {
    prove_mm_contract();
    prove_password_redaction();
    return 0;
}
