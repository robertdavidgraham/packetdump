/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __PCAPFILE_H
#define __PCAPFILE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <time.h>

enum {
    PCAPFILE_NO_COMPRESSION=0,
    
    /* LZ4 default (fastest) compression */
    PCAPFILE_LZ4,
    
    /* LZ4 maximum, and slowest, compress */
    PCAPFILE_LZ4SLOW,
};
struct PcapFile;


unsigned pcapfile_datalink(struct PcapFile *handle);

/**
 * Append a packet/frame to the output file. If the file was opened with
 * a compresison flag, this packet will be compressed.
 * @param capfile
 *      A file handled opened with 'pcapfile_openwrite()'
 * @param buffer
 *      The contents of the packet buffer.
 * @param buffer_size
 *      The (possibly sliced) length of the packet buffer [caplen]
 * @param original_length
 *      The original length of the packet [len]
 * @param time_sec
 *      Number of seconds since 1970 (time_t) [ts.tv_sec]
 * @param time_usec
 *      Number of microseconds since the start of the current
 *      second [ts.tv_usec]. 
 * @return
 *      The number of bytes written, which may be smaller than the number
 *      of bytes in the packet if compression is enabled. A negative
 *      number is returned if there is an error.
 */
ssize_t pcapfile_writeframe(
    struct PcapFile *capfile,
    const void *buffer,
    unsigned buffer_size,
    unsigned original_length,
    long time_sec,
    long time_usec
    );

struct PcapFile *pcapfile_openread(const char *capfilename);


/**
 * Opens a pcapfile for writing.
 * @param capfilename
 *      Name of the file to open. If it exists, it'll be sillently overwritten
 * @param linktype
 *      The type of data link layer, such as Ethernet or one fo the several
 *      possible WiFi encapsulations.
 * @param compression_type
 *      The type of compression supported, 0 for none, or PCAPFILE_LZ4
 *      for the LZ4 algorithm.
 */
struct PcapFile *pcapfile_openwrite(const char *capfilename, unsigned linktype, int compression_type);
    
struct PcapFile *pcapfile_openappend(const char *capfilename, unsigned linktype);

unsigned pcapfile_percentdone(struct PcapFile *handle, uint64_t *r_bytes_read);

void pcapfile_get_timestamps(struct PcapFile *handle, time_t *start, time_t *end);

/**
 * Set a "maximum" size for a file. When the current file fills up with data,
 * it will close that file and open a new one, then continue to write
 * from that point on in the new file.
 */
void pcapfile_set_max(struct PcapFile *capfile, unsigned max_megabytes, unsigned max_files);

/**
 *  Read a single frame from the file.
 *  Returns 0 if failed to read (from error or end of file), and
 *  returns 1 if successful.
 */
int pcapfile_readframe(
    struct PcapFile *capfile,
    unsigned *r_time_secs,
    unsigned *r_time_usecs,
    unsigned *r_original_length,
    unsigned *r_captured_length,
    unsigned char *buf,
    unsigned sizeof_buf
    );


void pcapfile_close(struct PcapFile *handle);

#ifdef __cplusplus
}
#endif
#endif /*__PCAPFILE_H*/
