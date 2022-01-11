#include "filehandler.h"

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