
#include <stdio.h>
#include <string.h>

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
