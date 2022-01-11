# Sample makefile

all: client.exe

.c.obj:
  $(cc) $(cdebug) $(cflags) $(cvars) $*.c

client.exe: client.obj
  $(link) $(ldebug) $(conflags) -out:client.exe client.obj $(conlibs) lsapi32.lib
