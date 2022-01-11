#ifndef _PAYLOAD
#define _PAYLOAD 1

#include <stdint.h>
#include <rpc.h>
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))

#define BLOCKSIZE 120
typedef unsigned char _uuid_dt[16];

PACK(struct dns_payload {
  _uuid_dt uuid;
  uint8_t action;
  uint32_t sequence;
  uint8_t length;
  char data[BLOCKSIZE];
});

#endif

