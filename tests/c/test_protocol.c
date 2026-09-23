#include <assert.h>
#include <stddef.h>
#include "omni_protocol.h"

static omni_mm_header good_header(void) {
    omni_mm_header h = { .magic=OMNI_MM_MAGIC,.version=OMNI_MM_VERSION,.command=1,.payload_size=0,.flags=0 };
    return h;
}
int main(void) {
    omni_mm_header h=good_header(); size_t full=sizeof(h)+8;
    assert(omni_mm_validate(NULL,full)==OMNI_ERR_NULL);
    assert(omni_mm_validate(&h,sizeof(h)-1)==OMNI_ERR_SIZE);
    h.magic=0; assert(omni_mm_validate(&h,full)==OMNI_ERR_MAGIC); h=good_header();
    h.version=99; assert(omni_mm_validate(&h,full)==OMNI_ERR_VERSION); h=good_header();
    h.payload_size=OMNI_MM_MAX_PAYLOAD+1; assert(omni_mm_validate(&h,full)==OMNI_ERR_SIZE); h=good_header();
    h.payload_size=8; assert(omni_mm_validate(&h,sizeof(h)+7)==OMNI_ERR_SIZE); h=good_header();
    h.command=0; assert(omni_mm_validate(&h,full)==OMNI_ERR_COMMAND); h=good_header();
    h.command=17; assert(omni_mm_validate(&h,full)==OMNI_ERR_COMMAND); h=good_header();
    assert(omni_mm_validate(&h,full)==OMNI_OK);
    assert(omni_a11y_validate(NULL)==OMNI_ERR_NULL);
    omni_a11y_node node={.id=1,.name_length=0};
    assert(omni_a11y_validate(&node)==OMNI_ERR_SIZE);
    node.name_length=4; node.state=OMNI_A11Y_PASSWORD; node.value_length=6;
    assert(omni_a11y_validate(&node)==OMNI_ERR_SECRET);
    node.value_length=0; assert(omni_a11y_validate(&node)==OMNI_OK);
    return 0;
}
