#ifndef config_h
#define config_h
#include <stdio.h>
#include "packetdump.h"

void
read_configuration(int argc, char **argv, struct PacketDump *conf);

void
echo_configuration(FILE *fp, struct PacketDump *conf);

void
configuration_help(void);

#endif /* config_h */
