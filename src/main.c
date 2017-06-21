#include "packetdump.h"
#include "config.h"
#include "logger.h"
#include "lz4/lz4.h"
#include "pixie-threads.h"
#include "pixie-timer.h"
#include "rawsock-pcap.h"       /* dynamicly load pcap library */
#include "rawsock-pcapfile.h"   /* write capture files */
#include "readfiles.h"
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * All the globals in this project
 */
unsigned control_c_pressed = 0;
unsigned control_c_pressed_again = 0;

/***************************************************************************
 ***************************************************************************/
static char *
morph_filename(const struct PacketDump *conf, time_t now, size_t filecount)
{
    struct tm *tm;
    char *newfilename;
    const char *oldfilename = conf->filename;
    size_t i, j=0;
    
    if (conf->is_gmt) {
        tm = gmtime(&now);
    } else {
        tm = localtime(&now);
    }
    
    newfilename = malloc(1024 + strlen(oldfilename));
    
    for (i=0; oldfilename[i]; i++) {
        if (oldfilename[i] != '%')
            newfilename[j++] = oldfilename[i];
        else {
            int code = oldfilename[++i];
            switch (code) {
                case 'y':
                    j += sprintf(newfilename+j, "%02u", tm->tm_year % 100);
                    break;
                case 'Y':
                    j += sprintf(newfilename+j, "%02u", tm->tm_year + 1900);
                    break;
                case 'm':
                    j += sprintf(newfilename+j, "%02u", tm->tm_mon + 1);
                    break;
                case 'd':
                    j += sprintf(newfilename+j, "%02u", tm->tm_mday);
                    break;
                case 'H':
                    j += sprintf(newfilename+j, "%02u", tm->tm_hour);
                    break;
                case 'M':
                    j += sprintf(newfilename+j, "%02u", tm->tm_min);
                    break;
                case 'S':
                    j += sprintf(newfilename+j, "%02u", tm->tm_sec);
                    break;
                default:
                    newfilename[j++] = (char)code;
            }
        }
    }
    
    newfilename[j] = '\0';
    
    
    return newfilename;
}

/***************************************************************************
 ***************************************************************************/
static time_t
next_rotate_time(time_t last_rotate, unsigned period, unsigned offset)
{
    time_t next;
    
    if (period == 0)
        next = INT_MAX;
    else
        next = last_rotate - (last_rotate % period) + period + offset;
    
    return next;
}

/***************************************************************************
 ***************************************************************************/
struct WriteContext
{
    /**
     * The configuration information that tells us how we should be writing
     * packets.
     */
    const struct PacketDump *conf;
    
    /**
     * Handle to the file where we are writing packets. This changes while we
     * write packets whenever we need to rotate the file to a new one
     */
    struct PcapFile *fp;
    
    /**
     * The current filename, which is based on morphing the configured
     * filename, such as adding data/timestamp information
     */
    char *filename;
    
    /**
     * The total number of files that we have processed
     */
    size_t total_file_count;
    
    /**
     * The timestamp when we should next rotate the output file.
     */
    time_t rotate_time;
    
    /**
     * The libpcap data-link value (Ethernet, WiFi, etc.)
     */
    int data_link;
    
    size_t file_bytes_written;
    size_t file_packets_written;
    
};

/***************************************************************************
 * Write a single packet to the output file.
 *
 * Note that most of the logic in this function is about rotating the
 * file when it gets too big, or when it exceeds a timestamp. Indeed,
 * because of rotation issues, we don't even open the file for the first
 * time until we are ready to write the first frame.
 ***************************************************************************/
static int
handle_packet(struct WriteContext *ctx, const struct pcap_pkthdr *hdr, const void *buf)
{
    const struct PacketDump *conf = ctx->conf;
    ssize_t bytes_written;
    
    /*
     * open the output file
     */
again:
    if (ctx->fp == NULL) {
        
        /* Create a new filename based on timestamp and filecount information */
        ctx->filename = morph_filename(conf, hdr->ts.tv_sec, ctx->total_file_count);
        LOG(0, "%s: opening new file\n", ctx->filename);
        
        /* Open the file */
        ctx->fp = pcapfile_openwrite(ctx->filename, ctx->data_link, PCAPFILE_LZ4);
        if (ctx->fp == NULL) {
            /* This is bad. I don't know how to recover at this point */
            fprintf(stderr, "%s: couldn't open file\n", ctx->filename);
            return -1;
        }
        
        /* Calculate the timestamp when the file should next be rotated.
         * Note that his is aligned, so that if "hourly" rotation is desired,
         * it'll rotate every hour on the hour  */
        ctx->rotate_time = next_rotate_time(hdr->ts.tv_sec,
                                            (unsigned)conf->rotate_seconds,
                                            0);
        ctx->file_bytes_written = 0;
        ctx->file_packets_written = 0;
        ctx->total_file_count++;
    }
    
    /*
     * Rotate the old capture file if necessary
     */
    if ((conf->rotate_size && ctx->file_bytes_written >= conf->rotate_size)
        || (ctx->rotate_time && hdr->ts.tv_sec >= ctx->rotate_time)) {
        LOG(0, "%s: file#%llu, wrote %llu bytes, wrote %llu packets\n",
            ctx->filename,
            ctx->total_file_count,
            ctx->file_bytes_written,
            ctx->file_packets_written);
        pcapfile_close(ctx->fp);
        ctx->fp = NULL;
        free(ctx->filename);
        ctx->filename = NULL;
        goto again;
    }
    
    
    /*
     * write the frame
     */
    bytes_written = pcapfile_writeframe(ctx->fp,
                                        buf,
                                        hdr->caplen,
                                        hdr->len,
                                        hdr->ts.tv_sec,
                                        hdr->ts.tv_usec
                                        );
    if (bytes_written < 0) {
        fprintf(stderr, "packet write failure\n");
        return -1;
    }
    
    ctx->file_bytes_written += bytes_written;
    ctx->file_packets_written++;

    return 0;
}

/***************************************************************************
 ***************************************************************************/
void statistics_thread(void *userdata)
{
    unsigned long long total_packets = 0;
    unsigned long long total_drops = 0;
    
    while (!control_c_pressed) {
        struct pcap_stat stats = {0};
        size_t bytes_printed;
        size_t i;
        
        pixie_usleep(100000 );
        
        PCAP.stats(userdata, &stats);
        
        total_packets = stats.ps_recv;
        total_drops = stats.ps_drop + stats.ps_ifdrop;
        
        bytes_printed = fprintf(stderr, "packets=%llu, drops=%llu                 ",
                                total_packets,
                                total_drops);
        for (i=0; i<bytes_printed; i++) {
            fprintf(stderr, "\b");
        }
    }
    
}

/***************************************************************************
 ***************************************************************************/
void
capture_thread(const struct PacketDump *conf)
{
    pcap_t *p;
    char errbuf[PCAP_ERRBUF_SIZE];
    size_t total_packets_written = 0;
    struct WriteContext ctx[1] = {0};
    size_t t;

    /*
     * open the network adapter
     */
    p = PCAP.open_live(
                       conf->ifname, /* network adapter to sniff from*/
                       65536,   /* snap length */
                       1,       /* promiscuous mode */
                       10,      /* read timeout in milliseconds */
                       errbuf   /* error buffer */
                       );
    if (p == NULL) {
        fprintf(stderr, "%s: %s\n", conf->ifname, errbuf);
        return;
    } else {
        //fprintf(stderr, "%s: buffsize = %d\n", conf->ifname, PCAP.bufsize(p));
        fprintf(stderr, "%s: capture started\n", conf->ifname);
    }
    
    /*
     * Start a statistics thread
     */
    t = pixie_begin_thread(statistics_thread, 0, p);
    
    /*
     * Setup the context
     */
    ctx->conf = conf;
    ctx->data_link = PCAP.datalink(p);
    
    /*
     * now loop reading packets
     */
    while (!control_c_pressed) {
        struct pcap_pkthdr *hdr;
        const unsigned char *buf;
        int x;
        
        /*
         * Read the next packet
         */
        x = PCAP.next_ex(p, &hdr, &buf);
        if (x == 0)
            continue; /* timeout expired */
        else if (x < 0) {
            PCAP.perror(p, conf->ifname);
            break;
        }
        
        x = handle_packet(ctx, hdr, buf);
        if (x < 0)
            break;
    }
    
    pixie_thread_join(t);
    fprintf(stderr, "read %u packets\n", (unsigned)total_packets_written);
    
    if (ctx->fp)
        pcapfile_close(ctx->fp);
    if (ctx->filename)
        free(ctx->filename);
    if (p)
        PCAP.close(p);
}

/***************************************************************************
 * We trap the <ctrl-c> so that instead of exiting immediately, we sit in
 * a loop for a few seconds waiting for any late response. But, the user
 * can press <ctrl-c> a second time to exit that waiting.
 ***************************************************************************/
static void
control_c_handler(int x)
{
    if (control_c_pressed == 0) {
        fprintf(stderr,
                "waiting several seconds to exit..."
                "                                            \n"
                );
        fflush(stderr);
        control_c_pressed = 1+x;
    } else {
        control_c_pressed_again = 1;
    }
}

/***************************************************************************
 * This function prints to the command line a list of all the network
 * intefaces/devices.
 ***************************************************************************/
static void
rawsock_list_adapters(void)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;
    int index;
    const pcap_if_t *d;
    
    /*
     * Get the list of network adapters
     */
    x = PCAP.findalldevs(&alldevs, errbuf);
    if (x < 0) {
        fprintf(stderr, "%s\n", errbuf);
        return;
    }
    if (alldevs == NULL) {
        fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
        return;
    }

    /* 
     * Print the list, with a numeric index
     */
    index = 0;
    for(d=alldevs; d; d=PCAP.dev_next(d)) {
        fprintf(stderr, " %d  %s \t", index++, PCAP.dev_name(d));
        if (PCAP.dev_description(d))
            fprintf(stderr, "(%s)\n", PCAP.dev_description(d));
        else
            fprintf(stderr, "(No description available)\n");
    }
    fprintf(stderr,"\n");
    
    
    /*
     * Free the memory. Not really necessary, since we are going to exit
     * immediately anyway.
     */
    PCAP.freealldevs(alldevs);
}

/***************************************************************************
 ***************************************************************************/
int
main(int argc, char *argv[])
{
    struct PacketDump conf[1] = {0};
    unsigned statuscount = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
 
    fprintf(stderr, "--- packetdump/1.0 by Robert Graham ---\n");
    
    /* Dynamically load the 'libcap' library */
    pcap_init();
 
    /* Read in the configuration from the command-line, and if the --conf
     * option is used, configuration files from the disk */
    if (argc == 1) {
        fprintf(stderr, "no options specified, use '-h' for help\n");
        return 1;
    }
    read_configuration(argc, argv, conf);
    
    if (conf->ifname == 0)
        conf->ifname = PCAP.lookupdev(errbuf);

    /*
     * trap <ctrl-c> to pause
     */
    signal(SIGINT, control_c_handler);
    

    /*
     * Print info items that user might have requested. If the user specifies
     * these, then we won't start capture
     */
    if (conf->is_help) {
        configuration_help();
        statuscount++;
    }
    if (conf->is_echo) {
        echo_configuration(stdout, conf);
        statuscount++;
    }
    if (conf->is_version) {
        fprintf(stderr, "packetdump version = 1.0\n");
        fprintf(stderr, "%s\n", PCAP.lib_version());
        fprintf(stderr, "LZ4 version = %s\n", LZ4_versionString());
        statuscount++;
    }
    if (conf->is_iflist) {
        rawsock_list_adapters();
        statuscount++;
    }
    if (statuscount)
        return 1;
    
    if (conf->readfiles) {
        read_files(conf);
        return 0;
    }
    
    /*
     * Make sure we have a capture interface and a file to write 
     * to
     */
    if (conf->ifname == NULL || conf->ifname[0] == '\0') {
        fprintf(stderr, "FAIL: no interface specified\n");
        fprintf(stderr, "  hint: use the '-i' option to specify an interface\n");
        return 1;
    }
    if (conf->filename == NULL || conf->filename[0] == '\0') {
        fprintf(stderr, "FAIL: no output files specified\n");
        fprintf(stderr, "  hint: use the '-w' option to specify a file to write to\n");
        return 1;
    }
    
    /*
     * Start the capture thread
     */
    capture_thread(conf);
    
    return 0;
}
