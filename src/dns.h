#include "payload.h"

#ifndef _DNS_H

#define _DNS_H 1
#define MAX_BUFFER_SIZE 512
#define DNS_PORT 53

#define RESPONSE_SUCCESS 0
#define REPONSE_FORMAT_ERROR 1
#define RESPONSE_FAILURE 2
#define RESPONSE_NAME_ERROR 3
#define RESPONSE_REFUSED 5

#define QTYPE_A 0x01
#define QTYPE_AAAA 0x1C

#define QCLASS_INET 0x0001

// All uint16 are in network byte order!!!
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))

PACK(struct dns_header {
  uint16_t id;

  unsigned short rd : 1;
  unsigned short tc : 1;
  unsigned short aa : 1;
  unsigned short opcode : 4;
  unsigned short qr : 1;

  unsigned short rcode : 4;
  unsigned short z : 3;
  unsigned short ra : 1;

  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
});


PACK(struct dns_response_trailer {
  uint8_t ans_type;
  uint8_t name_offset;
  uint16_t type;
  uint16_t qclass;
  uint32_t ttl;
  uint16_t rdlength;
  uint32_t rdata;
});

PACK(struct dns_query {
  size_t num_segments;
  char segment[10][64];
  uint16_t type;
  uint16_t qclass;
});


#endif