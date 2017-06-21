/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Copyright (c) 2017 by Robert David Graham
 * Programer(s): Robert David Graham [rdg]
 */
/*
	LIBPCAP INTERFACE
 
 This VERY MESSY code is a hack to load the 'libpcap' library 
 at runtime rather than compile time.
 
 This reason for this mess is that it gets rid of a dependency
 when compiling this project. Otherwise, developers would have
 to download the 'libpcap-dev' dependency in order to build
 this project.
 
 Almost every platform these days (OpenBSD, FreeBSD, macOS,
 Debian, RedHat) comes with a "libpcap.so" library already
 installed by default with a known BINARY interface. Thus,
 we can include the data structures definitions directly
 in this project, then load the library dynamically.
 
 For those systems without libpcap.so already installed, the
 user can either install those on the system, or compile
 this project in "STATIC" mode, which will link to the 
 static libpcap.a library.
 
*/
#include "logger.h"


#if _MSC_VER==1200
#pragma warning(disable:4115 4201)
#include <winerror.h>
#endif
#include "rawsock-pcap.h"

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef UNUSEDPARM
#define UNUSEDPARM(x) x=(x)
#endif


#ifndef STATICPCAP
struct pcap_if {
    struct pcap_if *next;
    char *name;		/* name to hand to "pcap_open_live()" */
    char *description;	/* textual description of interface, or NULL */
    void  *addresses;
    unsigned flags;	/* PCAP_IF_ interface flags */
};
#endif


static void *my_null(int x, ...)
{
    UNUSEDPARM(x);
    return 0;
}

static void seterr(char *errbuf, const char *msg)
{
    size_t length = strlen(msg);
    
    if (length > PCAP_ERRBUF_SIZE-1)
    length = PCAP_ERRBUF_SIZE-1;
    memcpy(errbuf, msg, length);
    errbuf[length] = '\0';
}

#ifdef STATICPCAP
#define DECLARESTUB(n) static PCAP_##n stub_##n = pcap_##n;
#else
#define DECLARESTUB(n) static PCAP_##n stub_##n = (PCAP_##n)my_null;
#endif

DECLARESTUB(close);
DECLARESTUB(datalink);
DECLARESTUB(dispatch);
DECLARESTUB(findalldevs);
DECLARESTUB(freealldevs);
DECLARESTUB(lookupdev);
DECLARESTUB(open_live);
DECLARESTUB(major_version);
DECLARESTUB(minor_version);
DECLARESTUB(lib_version);
DECLARESTUB(open_offline);
DECLARESTUB(sendpacket);
DECLARESTUB(next);
DECLARESTUB(next_ex);
DECLARESTUB(setdirection);
DECLARESTUB(datalink_val_to_name);
DECLARESTUB(perror);
DECLARESTUB(stats);



static const char *stub_dev_name(const pcap_if_t *dev)
{
    return dev->name;
}
static const char *stub_dev_description(const pcap_if_t *dev)
{
    return dev->description;
}
static const pcap_if_t *stub_dev_next(const pcap_if_t *dev)
{
    return dev->next;
}

static pcap_send_queue *stub_sendqueue_alloc(size_t size)
{
	UNUSEDPARM(size);
	return 0;
}
static unsigned stub_sendqueue_transmit(pcap_t *p, pcap_send_queue *queue, int sync)
{
	my_null(3, p, queue, sync);
	return 0;
}
static void stub_sendqueue_destroy(pcap_send_queue *queue)
{
	my_null(1, queue);
	UNUSEDPARM(queue);
}
static int stub_sendqueue_queue(pcap_send_queue *queue,
    const struct pcap_pkthdr *pkt_header,
    const unsigned char *pkt_data)
{
	my_null(4, queue, pkt_header, pkt_data);
	return 0;
}

/*
 * New API
 */
DECLARESTUB(create);
DECLARESTUB(set_snaplen);
DECLARESTUB(set_promisc);
DECLARESTUB(can_set_rfmon);
DECLARESTUB(set_rfmon);
DECLARESTUB(set_timeout);
DECLARESTUB(set_buffer_size);
DECLARESTUB(activate);


/****************************************************************************
 *****************************************************************************/
struct PcapFunctions PCAP = {0};


/**
 * Runtime-load the libpcap shared-object or the winpcap DLL. We
 * load at runtime rather than loadtime to allow this program to
 * be used to process offline content, and to provide more helpful
 * messages to people who don't realize they need to install PCAP.
 */
int pcap_init(void)
{
    struct PcapFunctions *pl = &PCAP;
#ifdef WIN32
    void * hPacket;
    void * hLibpcap;
    void * hAirpcap;
    
    pl->is_available = 0;
    pl->is_printing_debug = 1;
    
    /* Look for the Packet.dll */
    hPacket = LoadLibraryA("Packet.dll");
    if (hPacket == NULL) {
        if (pl->is_printing_debug)
        switch (GetLastError()) {
            case ERROR_MOD_NOT_FOUND:
            fprintf(stderr, "%s: not found\n", "Packet.dll");
            return;
            default:
            fprintf(stderr, "%s: couldn't load %d\n", "Packet.dll", (int)GetLastError());
            return;
        }
    }
    
    /* Look for the Packet.dll */
    hLibpcap = LoadLibraryA("wpcap.dll");
    if (hLibpcap == NULL) {
        if (pl->is_printing_debug)
        fprintf(stderr, "%s: couldn't load %d\n", "wpcap.dll", (int)GetLastError());
        return;
    }
    
    /* Look for the Packet.dll */
    hAirpcap = LoadLibraryA("airpcap.dll");
    if (hLibpcap == NULL) {
        if (pl->is_printing_debug)
        fprintf(stderr, "%s: couldn't load %d\n", "airpcap.dll", (int)GetLastError());
        return;
    }
    
#define DOLINK(PCAP_DATALINK, datalink) \
pl->datalink = (PCAP_DATALINK)GetProcAddress(hLibpcap, "pcap_"#datalink); \
if (pl->datalink == NULL) pl->func_err=1, pl->datalink = null_##PCAP_DATALINK;
#endif
    
    
#ifndef WIN32
#ifndef STATICPCAP
    void *hLibpcap = 0;
    
    pl->is_available = 0;
    pl->is_printing_debug = 1;
    
    {
        static const char *possible_names[] = {
            "libpcap.so",
            "libpcap.A.dylib",
            "libpcap.dylib",
            "libpcap.so.0.9.5",
            "libpcap.so.0.9.4",
            "libpcap.so.0.8",
            0
        };
        unsigned i;
        for (i=0; possible_names[i]; i++) {
            hLibpcap = dlopen(possible_names[i], RTLD_LAZY);
            if (hLibpcap) {
                LOG(1, "pcap: found library: %s\n", possible_names[i]);
                break;
            } else {
                LOG(2, "pcap: failed to load: %s\n", possible_names[i]);
            }
        }
     
        if (hLibpcap == NULL) {
            fprintf(stderr, "pcap: failed to load libpcap shared library\n");
            fprintf(stderr, "    HINT: you must install libpcap or WinPcap\n");
        }
    }
    
#define DOLINK(DATALINK, datalink) \
    pl->datalink = (PCAP_##DATALINK)dlsym(hLibpcap, "pcap_"#datalink); \
    if (pl->datalink == NULL) LOG(1, "pcap: pcap_%s: failed\n", #datalink); \
    if (pl->datalink == NULL) pl->func_err=1, pl->datalink = stub_##DATALINK;
#define DYNLINK(datalink) \
    pl->datalink = (PCAP_##datalink)dlsym(hLibpcap, "pcap_"#datalink); \
    if (pl->datalink == NULL) LOG(1, "pcap: pcap_%s: failed\n", #datalink); \
    if (pl->datalink == NULL) pl->func_err=1, pl->datalink = stub_##datalink;
#else
#define DOLINK(PCAP_DATALINK, datalink) \
pl->func_err=0, pl->datalink = null_##PCAP_DATALINK;
#endif
#endif
    
#ifdef WIN32
    DOLINK(PCAP_GET_AIRPCAP_HANDLE, get_airpcap_handle);
    if (pl->func_err) {
        pl->func_err = 0;
    }
    if (hAirpcap) {
        pl->airpcap_set_device_channel = (AIRPCAP_SET_DEVICE_CHANNEL)GetProcAddress(hAirpcap, "AirpcapSetDeviceChannel");
        if (pl->airpcap_set_device_channel == NULL)
        pl->airpcap_set_device_channel = null_AIRPCAP_SET_DEVICE_CHANNEL;
    }
#endif
    
#ifdef STATICPCAP
#define DYNLINK(n) PCAP.n = stub_##n
#endif
    
    DYNLINK(close);
    DYNLINK(datalink);
    DYNLINK(datalink_val_to_name);
    DYNLINK(dispatch);
    DYNLINK(findalldevs);
    DYNLINK(freealldevs);
    DYNLINK(lib_version);
    DYNLINK(lookupdev);
    DYNLINK(major_version);
    DYNLINK(minor_version);
    DYNLINK(next);
    DYNLINK(next_ex);
    DYNLINK(open_live);
    DYNLINK(open_offline);
    DYNLINK(perror);
    DYNLINK(sendpacket);
    DYNLINK(setdirection);
    DYNLINK(stats);

    DYNLINK(create);
    DYNLINK(set_snaplen);
    DYNLINK(set_promisc);
    DYNLINK(can_set_rfmon);
    DYNLINK(set_rfmon);
    DYNLINK(set_timeout);
    DYNLINK(set_buffer_size);
    DYNLINK(activate);
    
    DYNLINK(dev_name);
    DYNLINK(dev_description);
    DYNLINK(dev_next);

	DYNLINK(sendqueue_alloc);
	DYNLINK(sendqueue_transmit);
	DYNLINK(sendqueue_destroy);
	DYNLINK(sendqueue_queue);

    
    if (!pl->func_err)
        pl->is_available = 1;
    else
        pl->is_available = 0;
    
    return 0;
}

