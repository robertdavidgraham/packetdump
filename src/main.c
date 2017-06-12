#include "packetdump.h"
#include "config.h"
#include "logger.h"
#include "lz4/lz4.h"
#include "rawsock-pcap.h"       /* dynamicly load pcap library */
#include "rawsock-pcapfile.h"   /* write capture files */
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
void
capture_thread(const struct PacketDump *conf)
{
    pcap_t *p;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct PcapFile *out = NULL;
    size_t total_packets_written = 0;
    ssize_t total_bytes_written = 0;
    time_t rotate_time = 0;
    size_t total_file_count = 0;
    char *newfilename = 0;
    

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
        fprintf(stderr, "%s: capture started\n", conf->ifname);
    }
    
    
    /*
     * now loop reading packets
     */
    while (!control_c_pressed) {
        struct pcap_pkthdr *hdr;
        const unsigned char *buf;
        ssize_t bytes_written;
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
        
        /*
         * open the output file
         */
    again:
        if (out == NULL) {
            
            newfilename = morph_filename(conf, hdr->ts.tv_sec, total_file_count);
            LOG(0, "%s: opening new file\n", newfilename);
            out = pcapfile_openwrite(newfilename, PCAP.datalink(p), PCAPFILE_LZ4);
            if (out == NULL) {
                fprintf(stderr, "%s: couldn't open file\n", newfilename);
                break;;
            }
            rotate_time = next_rotate_time(hdr->ts.tv_sec, (unsigned)conf->rotate_seconds, 0);
            total_bytes_written = 0;
            total_packets_written = 0;
            total_file_count++;
        }
        
        /*
         * Rotate the old capture file if necessary
         */
        if ((conf->rotate_size && total_bytes_written >= conf->rotate_size) || hdr->ts.tv_sec >= rotate_time) {
            LOG(0, "%s: file#%u, wrote %llu bytes, wrote %llu packets\n",
                newfilename,
                (unsigned)total_file_count,
                total_bytes_written,
                total_packets_written);
            pcapfile_close(out);
            free(newfilename);
            out = NULL;
            goto again;
        }
        
        
        /*
         * write the frame
         */
        bytes_written = pcapfile_writeframe(out,
                            buf,
                            hdr->caplen,
                            hdr->len,
                            hdr->ts.tv_sec,
                            hdr->ts.tv_usec
                            );
        if (bytes_written < 0) {
            fprintf(stderr, "packet write failure\n");
            break;
        }
        total_bytes_written += bytes_written;
        total_packets_written++;
    }
    
    fprintf(stderr, "read %u packets\n", (unsigned)total_packets_written);
    
    if (out)
        pcapfile_close(out);
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
    
    if (PCAP.findalldevs(&alldevs, errbuf) != -1) {
        int i;
        const pcap_if_t *d;
        i=0;
        
        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for(d=alldevs; d; d=PCAP.dev_next(d)) {
            fprintf(stderr, " %d  %s \t", i++, PCAP.dev_name(d));
            if (PCAP.dev_description(d))
                fprintf(stderr, "(%s)\n", PCAP.dev_description(d));
            else
                fprintf(stderr, "(No description available)\n");
        }
        fprintf(stderr,"\n");
        PCAP.freealldevs(alldevs);
    } else {
        fprintf(stderr, "%s\n", errbuf);
    }
}

/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
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
