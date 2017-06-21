/*
    Dynamically load libpcap at runtime
 
 This library optionally loads the 'libpcap' library at runtime, rather
 than statically linked at compile time. The advantage of this is that
 the user can build this project with no dependencies -- although they
 may require this dependency in order to run the program.
 
 As of 2017, libpcap shared libraries are standard on major Linux
 distributions (Debian, Readhat), FreeBSD, OpenBSD, and macOS. On
 Windows, "winpcap" must be downloaded. 
*/
#ifndef RAWSOCK_PCAP_H
#define RAWSOCK_PCAP_H
#include <stdio.h>

#ifdef STATICPCAP
#include <pcap/pcap.h>
#endif

#ifndef STATICPCAP
enum {
    DLT_EN10MB = 1,
    DLT_RAW = 101,
};

/* Including the right ".h" file to define "timeval" is difficult, so instead
 * so instead we are simply going to define our own structure. This should
 * match the binary definition within the operating system
 */
struct pcap_timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};

/* Forward reference of opaque 'pcap_t' structure */
struct pcap;
typedef struct pcap pcap_t;

/* Forward reference of opaque 'pcap_if_t' structure */
struct pcap_if;
typedef struct pcap_if pcap_if_t;

/* How many bytes to reserve for error messages. This is the number specified
 * in libpcap, smaller numbers can crash */
enum {
    PCAP_ERRBUF_SIZE=256,
};

/* used in pcap_setdirection() */
typedef enum {
    PCAP_D_INOUT    = 0,
    PCAP_D_IN       = 1,
    PCAP_D_OUT      = 2,
} pcap_direction_t;

/* The packet header for capturing packets. Apple macOS inexplicably adds
 * an extra comment-field onto the end of this, so the definition needs
 * to be careful to match the real definition */
struct pcap_pkthdr {
    struct pcap_timeval ts;
    unsigned caplen;
    unsigned len;
#ifdef __APPLE__
    char comment[256];
#endif
};

struct pcap_stat {
    unsigned ps_recv;		/* number of packets received */
    unsigned ps_drop;		/* number of packets dropped */
    unsigned ps_ifdrop;	/* drops by interface -- only supported on some platforms */
#ifdef WIN32
    unsigned ps_capt;		/* number of packets that reach the application */
    unsigned ps_sent;		/* number of packets sent by the server on the network */
    unsigned ps_netdrop;	/* number of packets lost on the network */
#endif /* _WIN32 */
};

#endif /*STATICPCAP*/

/*
 * This block is for function declarations. Consult the libpcap
 * documentation for what these functions really mean
 */
typedef void        (*PCAP_HANDLE_PACKET)(unsigned char *v_seap, const struct pcap_pkthdr *framehdr, const unsigned char *buf);

typedef void        (*PCAP_close)(pcap_t *hPcap);
typedef int         (*PCAP_datalink)(pcap_t *hPcap);
typedef const char *(*PCAP_datalink_val_to_name)(int dlt);
typedef int         (*PCAP_dispatch)(pcap_t *hPcap, int how_many_packets, PCAP_HANDLE_PACKET handler, unsigned char *handle_data);
typedef int         (*PCAP_findalldevs)(pcap_if_t **alldevs, char *errbuf);
typedef void        (*PCAP_freealldevs)(pcap_if_t *alldevs);
typedef const char *(*PCAP_lib_version)(void);
typedef char *      (*PCAP_lookupdev)(char *errbuf);
typedef int         (*PCAP_major_version)(pcap_t *p);
typedef int         (*PCAP_minor_version)(pcap_t *p);
typedef const unsigned char *(*PCAP_next)(pcap_t *p, struct pcap_pkthdr *h);
typedef int         (*PCAP_next_ex)(pcap_t *p, struct pcap_pkthdr **h, const unsigned char **buf);
typedef pcap_t *    (*PCAP_open_live)(const char *, int, int, int, char *);
typedef pcap_t *    (*PCAP_open_offline)(const char *fname, char *errbuf);
typedef void        (*PCAP_perror)(pcap_t *p, const char *prefix);
typedef int         (*PCAP_sendpacket)(pcap_t *p, const unsigned char *buf, int size);
typedef int         (*PCAP_setdirection)(pcap_t *, pcap_direction_t);
typedef int         (*PCAP_stats)(pcap_t *p, struct pcap_stat *ps);

/*
 * New PCAP
 */
typedef pcap_t	*(*PCAP_create)(const char *, char *);
typedef int	(*PCAP_set_snaplen)(pcap_t *, int);
typedef int	(*PCAP_set_promisc)(pcap_t *, int);
typedef int	(*PCAP_can_set_rfmon)(pcap_t *);
typedef int	(*PCAP_set_rfmon)(pcap_t *, int);
typedef int	(*PCAP_set_timeout)(pcap_t *, int);
typedef int	(*PCAP_set_buffer_size)(pcap_t *, int);
typedef int	(*PCAP_activate)(pcap_t *);

typedef const char *(*PCAP_dev_name)(const pcap_if_t *dev);
typedef const char *(*PCAP_dev_description)(const pcap_if_t *dev);
typedef const pcap_if_t *(*PCAP_dev_next)(const pcap_if_t *dev);


/*
 * PORTABILITY: Windows supports the "sendq" feature, and is really slow
 * without this feature. It's not needed on Linux, so we just create
 * equivelent functions that do nothing
 */
struct pcap_send_queue;
typedef struct pcap_send_queue pcap_send_queue;

typedef pcap_send_queue *(*PCAP_sendqueue_alloc)(size_t size);
typedef unsigned (*PCAP_sendqueue_transmit)(pcap_t *p, pcap_send_queue *queue, int sync);
typedef void (*PCAP_sendqueue_destroy)(pcap_send_queue *queue);
typedef int (*PCAP_sendqueue_queue)(pcap_send_queue *queue, const struct pcap_pkthdr *pkt_header, const unsigned char *pkt_data);





struct PcapFunctions {
    unsigned func_err:1;
    unsigned is_available:1;
    unsigned is_printing_debug:1;
    unsigned status;
    unsigned errcode;
    
    PCAP_close              close;
    PCAP_datalink           datalink;
    PCAP_datalink_val_to_name datalink_val_to_name;
    PCAP_dispatch           dispatch;
    PCAP_findalldevs        findalldevs;
    PCAP_freealldevs        freealldevs;
    PCAP_lookupdev          lookupdev;
    PCAP_lib_version        lib_version;
    PCAP_major_version      major_version;
    PCAP_minor_version      minor_version;
    PCAP_next               next;
    PCAP_next_ex            next_ex;
    PCAP_open_live          open_live;
    PCAP_open_offline       open_offline;
    PCAP_perror             perror;
    PCAP_sendpacket         sendpacket;
    PCAP_setdirection       setdirection;
    PCAP_stats              stats;
    
    /* New PCAP */
    PCAP_create             create;
    PCAP_set_snaplen        set_snaplen;
    PCAP_set_promisc        set_promisc;
    PCAP_can_set_rfmon      can_set_rfmon;
    PCAP_set_rfmon          set_rfmon;
    PCAP_set_timeout        set_timeout;
    PCAP_set_buffer_size    set_buffer_size;
    PCAP_activate           activate;
 
    /* Accessor functions for opaque data structure, don't really
     * exist in libpcap */
    PCAP_dev_name           dev_name;
    PCAP_dev_description    dev_description;
    PCAP_dev_next           dev_next;

    /* Windows-only functions */
	PCAP_sendqueue_alloc	sendqueue_alloc;
	PCAP_sendqueue_transmit	sendqueue_transmit;
	PCAP_sendqueue_destroy	sendqueue_destroy;
	PCAP_sendqueue_queue	sendqueue_queue;

};

/**
 * This is global structure containing all the libpcap function pointers.
 * use in the form "PCAP.functionname()" rather than "pcap_functioname()".
 */
extern struct PcapFunctions PCAP;

/**
 * Dynamically loads the shared library (libpcap.so, libpcap.dynlib,
 * or libpcap.dll. Call this during program startup like main() in order
 * to load the libraries. Not thread safe, so call from the startup
 * thread, but not within threads.
 * @return
 *  0 on success or
 *  -1 on failure
 */
int pcap_init(void);


#endif
