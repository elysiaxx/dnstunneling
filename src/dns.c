#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock.h>
#include "dns.h"
void extract_dns_query(unsigned char *dns_buffer,
                       struct dns_query *name_query) {
  unsigned char *query_ptr = dns_buffer + sizeof(struct dns_header);
  name_query->num_segments = 0;
  uint8_t segment_size;
  while ((segment_size = *((uint8_t *)query_ptr))) {
    if (segment_size > 63) { // malformed request
      return;
    }
    strncpy(name_query->segment[name_query->num_segments],
            (char *)(query_ptr + 1), segment_size);
    name_query->segment[name_query->num_segments][segment_size] = '\0';
    ++name_query->num_segments;
    query_ptr += segment_size + 1;
  }
  uint16_t *qtype_ptr = (uint16_t *)(query_ptr + 1);
  name_query->type = ntohs(*qtype_ptr);
  uint16_t *qclass_ptr = (uint16_t *)(query_ptr + 3);
  name_query->qclass = ntohs(*qclass_ptr);
}

struct dns_payload * get_respayload(struct dns_query * dns_query) {
    uint8_t base32_buf[300] = {0};
    for (int i = 0; i < dns_query->num_segments - 2; ++i) {
        strncat((char *)base32_buf, dns_query->segment[i], 1024);
    }
    uint8_t payload_buf[300];
    base32_decode(base32_buf, payload_buf, 300);
    struct dns_payload *payload = (struct dns_payload *)payload_buf;
    printf("Payload\n");
    print_buffer(payload_buf, sizeof(struct dns_payload) - BLOCKSIZE);
    printf("uuid %s, action %d, sequence %d, length %d\n", payload->uuid, payload->action, payload->sequence,
            payload->length);
    return payload;
}

void print_uuid(UUID *uuid) {
  unsigned char *uTemp;
  if(UuidToString(uuid,&uTemp)==RPC_S_OK){
    printf("UUID : %s\n",uTemp);
  }
  else {
    perror("Out of memory.\n");
    exit(1);
  }
}

void makeUUID(struct dns_payload *payload) 
{
  UUID *session_id = malloc(sizeof(UUID *));
  if(UuidCreate(session_id) != RPC_S_OK)
  {
    perror("Create UUID fail.");
    exit(1);
  }
  unsigned char *uTemp;
  if(UuidToString(session_id,&uTemp)!=RPC_S_OK){
    perror("Failed to convert uuid into string.");
    exit(1);
  }
  print_uuid(session_id);
  int j = 0;
  for(int i = 0 ; i < strlen(uTemp);)
  {
    if( uTemp[i] == (unsigned char)'-')
    {
      i++;
      continue;
    }
    char str[3] = { uTemp[i],uTemp[i+1], '\x0' };
    payload->uuid[j]= (int)strtol(str, NULL, 16); 
    j++;
    i = i + 2;
  }
}