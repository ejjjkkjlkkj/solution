#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "omni_protocol.h"
extern uint32_t nondet_uint32_t(void); extern uint16_t nondet_uint16_t(void); extern size_t nondet_size_t(void);
int main(void){
  omni_mm_header h={nondet_uint32_t(),nondet_uint16_t(),nondet_uint16_t(),nondet_uint32_t(),nondet_uint32_t()};
  size_t size=nondet_size_t(); omni_status s=omni_mm_validate(&h,size);
  if(s==OMNI_OK){
    assert(size>=sizeof(h)); assert(h.magic==OMNI_MM_MAGIC); assert(h.version==OMNI_MM_VERSION);
    assert(h.payload_size<=OMNI_MM_MAX_PAYLOAD); assert((size_t)h.payload_size<=size-sizeof(h));
    assert(h.command>=1 && h.command<=16);
  }
  return 0;
}
