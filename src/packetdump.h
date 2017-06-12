#ifndef packetdump_h
#define packetdump_h
#include <stdint.h>

/***************************************************************************
 ***************************************************************************/
struct PacketDump {
    
    /**
     * The netwrok interface to start packet-sniffing on
     */
    const char *ifname;
    
    /**
     * The filename to write packets into. This can also be a filename
     * spec, that allows adding data/timestamp parameters to the
     * filename.
     */
    const char *filename;
    
    const char *readfile;
    
    /**
     * Maximum number of bytes in a file before it is rotated. For
     * compressed files, this is the maximum number after
     * compression
     * [packetdump -C size]
     * [packetdump --filesize size]
     */
    uint64_t rotate_size;
    
    /**
     * Maximum number of seconds before rotating a file.
     */
    uint64_t rotate_seconds;
    
    /**
     * Maximum number of files to write before deleting
     * old ones
     */
    uint64_t rotate_filecount;
    
    /**
     * user account for dropping priviledges
     */
    const char *drop_user;
    
    /**
     * BPF rule specified on commandline
     */
    const char *bpf_rule;
    
    const char *bpf_file;
    
    char is_monitor_mode;
    char is_promiscuous_mode;
    char is_compression;
    char is_gmt;
    
    char is_help;
    char is_version;
    char is_iflist;
    char is_echo;
};
typedef struct PacketDump PacketDump;

#endif /* packetdump_h */
