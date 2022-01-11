#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#include "dns.h"
#include "payload.h"

BOOL directoryExists(LPCTSTR);
BOOL createDirectory(LPCTSTR);
void save_data(struct dns_query *);
