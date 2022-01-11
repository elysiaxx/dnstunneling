#ifndef _BASE32_H_
#define _BASE32_H_

#include <stdint.h>

int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize);
int base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize);

#endif /* _BASE32_H_ */
