#pragma once 
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pcap.h>

/**
 * libpcap defs can be found at:
 * https://www.tcpdump.org/manpages/pcap.3pcap.html
 **/

#ifdef __cplusplus
extern "C" {
#endif

// libc shim
typedef int (*fnsocket)(int domain, int type, int protocol);
typedef int (*fnsetsockopt)(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen);
typedef int (*fngetsockopt)(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
typedef ssize_t (*fnread)(int fd, void *buf, size_t count);
typedef ssize_t (*fnwrite)(int fd, const void *buf, size_t count);
typedef ssize_t (*fnsend)(int sockfd, const void *buf, size_t len, int flags);
typedef ssize_t (*fnsendto)(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t (*fnsendmsg)(int sockfd, const struct msghdr *msg, int flags);
typedef ssize_t (*fnrecv)(int sockfd, void *buf, size_t len, int flags);
typedef ssize_t (*fnrecvfrom)(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen);
typedef ssize_t (*fnrecvmsg)(int sockfd, struct msghdr *msg, int flags);
typedef int (*fnclose)(int fd);
typedef int (*fnioctl)(int fd, unsigned long request, ...);
typedef int (*fnprctl)(int option, unsigned long arg2, unsigned long arg3,
    unsigned long arg4, unsigned long arg5);


// pcap shim 
typedef pcap_t *(*fnpcap_create)(const char *source, char *errbuf);
typedef int (*fnpcap_activate)(pcap_t *p);
typedef int (*fnpcap_findalldevs)(pcap_if_t **alldevsp, char *errbuf);
typedef void (*fnpcap_freealldevs)(pcap_if_t *alldevs);
typedef char *(*fnpcap_lookupdev)(char *errbuf);
typedef pcap_t *(*fnpcap_open_offline)(const char *fname, char *errbuf);
typedef pcap_t *(*fnpcap_open_offline_with_tstamp_precision)(const char *fname,
    u_int precision, char *errbuf);
typedef pcap_t *(*fnpcap_fopen_offline)(FILE *fp, char *errbuf);
typedef pcap_t *(*fnpcap_fopen_offline_with_tstamp_precision)(FILE *fp,
    u_int precision, char *errbuf);
typedef pcap_t *(*fnpcap_open_live)(const char *device, int snaplen,
    int promisc, int to_ms, char *errbuf);
typedef pcap_t *(*fnpcap_open_dead)(int linktype, int snaplen);
typedef pcap_t *(*fnpcap_open_dead_with_tstamp_precision)(int linktype, int snaplen,
    u_int precision);
typedef int (*fnpcap_snapshot)(pcap_t *p);
typedef pcap_t *(*fnpcap_open_live)(const char *device, int snaplen,
    int promisc, int to_ms, char *errbuf);
typedef void (*fnpcap_close)(pcap_t *p);
typedef int (*fnpcap_set_snaplen)(pcap_t *p, int snaplen);
typedef int (*fnpcap_snapshot)(pcap_t *p);
typedef int (*fnpcap_set_promisc)(pcap_t *p, int promisc);
typedef int (*fnpcap_set_protocol)(pcap_t *p, int protocol);
typedef int (*fnpcap_set_rfmon)(pcap_t *p, int rfmon);
typedef int (*fnpcap_can_set_rfmon)(pcap_t *p);
typedef int (*fnpcap_set_timeout)(pcap_t *p, int to_ms);
typedef int (*fnpcap_set_buffer_size)(pcap_t *p, int buffer_size);
typedef int (*fnpcap_set_tstamp_type)(pcap_t *p, int tstamp_type);
typedef int (*fnpcap_list_tstamp_types)(pcap_t *p, int **tstamp_typesp);
typedef void (*fnpcap_free_tstamp_types)(int *tstamp_types);
typedef const char (*fnpcap_tstamp_type_val_to_name)(int tstamp_type);
typedef const char (*fnpcap_tstamp_type_val_to_description)(int tstamp_type);
typedef int (*fnpcap_tstamp_type_name_to_val)(const char *name);
typedef int (*fnpcap_set_tstamp_precision)(pcap_t *p, int tstamp_precision);
typedef int (*fnpcap_get_tstamp_precision)(pcap_t *p);
typedef FILE *(*fnpcap_file)(pcap_t *p);
typedef int (*fnpcap_is_swapped)(pcap_t *p);
typedef int (*fnpcap_major_version)(pcap_t *p);
typedef int (*fnpcap_minor_version)(pcap_t *p);
typedef int (*fnpcap_datalink)(pcap_t *p);
typedef int (*fnpcap_set_datalink)(pcap_t *p, int dlt);
typedef int (*fnpcap_list_datalinks)(pcap_t *p, int **dlt_buf);
typedef void (*fnpcap_free_datalinks)(int *dlt_list);
typedef const char *(*fnpcap_datalink_val_to_name)(int dlt);
typedef const char *(*fnpcap_datalink_val_to_description)(int dlt);
typedef int (*fnpcap_datalink_name_to_val)(const char *name);
typedef int (*fnpcap_loop)(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
typedef int (*fnpcap_dispatch)(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
typedef int (*fnpcap_next_ex)(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
typedef const u_char *(*fnpcap_next)(pcap_t *p, struct pcap_pkthdr *h);
typedef void (*fnpcap_breakloop)(pcap_t *);
typedef int (*fnpcap_setnonblock)(pcap_t *p, int nonblock, char *errbuf);
typedef int (*fnpcap_getnonblock)(pcap_t *p, char *errbuf);
typedef int (*fnpcap_get_selectable_fd)(pcap_t *p);
typedef const char *(*fnpcap_strerror)(int);
typedef char *(*fnpcap_geterr)(pcap_t *);
typedef void (*fnpcap_perror)(pcap_t *, const char *);
typedef int (*fnpcap_compile)(pcap_t *p, struct bpf_program *fp, 
    const char *str, int optimize, bpf_u_int32 netmask);
typedef int (*fnpcap_compile_nopcap)(int snaplen, int linktype, struct bpf_program *fp, 
    char *str, int optimize, bpf_u_int32 mask);
typedef void (*fnpcap_freecode)(struct bpf_program *);
typedef int (*fnpcap_setfilter)(pcap_t *p, struct bpf_program *fp);
typedef int (*fnpcap_lookupnet)(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf);
typedef int (*fnpcap_offline_filter)(const struct bpf_program *fp, 
    const struct pcap_pkthdr *h, const u_char *pkt);
typedef int (*fnpcap_setdirection)(pcap_t *p, pcap_direction_t d);
typedef int (*fnpcap_stats)(pcap_t *p, struct pcap_stat *ps);
typedef pcap_dumper_t *(*fnpcap_dump_open)(pcap_t *p, const char *fname);
typedef pcap_dumper_t *(*fnpcap_dump_open_append)(pcap_t *p, const char *fname);
typedef pcap_dumper_t *(*fnpcap_dump_fopen)(pcap_t *p, FILE *fp);
typedef void (*fnpcap_dump_close)(pcap_dumper_t *p);
typedef FILE *(*fnpcap_dump_file)(pcap_dumper_t *p);
typedef void (*fnpcap_dump)(u_char *user, struct pcap_pkthdr *h, u_char *sp);
typedef int (*fnpcap_dump_flush)(pcap_dumper_t *p);
typedef long (*fnpcap_dump_ftell)(pcap_dumper_t *p);
typedef int64_t (*fnpcap_dump_ftell64)(pcap_dumper_t *p);
typedef int (*fnpcap_inject)(pcap_t *p, const void *buf, size_t size);
typedef int (*fnpcap_sendpacket)(pcap_t *p, const u_char *buf, int size);
typedef const char *(*fnpcap_statustostr)(int error);
typedef const char *(*fnpcap_lib_version)(void);

#ifdef __cplusplus
};
#endif

#ifdef __cplusplus
#include "logging.hpp"
template<typename Tfn>
Tfn dlfn(const char *name, bool mandatory = true)
{
    auto fn = reinterpret_cast<Tfn>(dlsym(RTLD_NEXT, name));
    if (fn == nullptr && mandatory) {
        LOG(3) << "failed to find dynamic link symbol: " << name;
        LOG(3) << "exiting.";
        exit(1);
    }
    return fn;
}
#endif
