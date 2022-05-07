#include <stdint.h>
#include <stddef.h>

typedef unsigned char validate_uint8[sizeof(uint8_t) == 1 ? 1 : -1];
typedef unsigned char validate_uint16[sizeof(uint16_t) == 2 ? 1 : -1];
typedef unsigned char validate_uint32[sizeof(uint32_t) == 4 ? 1 : -1];
typedef unsigned char validate_uint64[sizeof(uint64_t) == 8 ? 1 : -1];

typedef unsigned char validate_size[sizeof(size_t) == RUST_USIZE_WIDTH_BYTES ? 1 : -1];
