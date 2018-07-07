#pragma once
#include "common.hpp"
#include "dlfn.h"
#include "rpc/client.h"
#include <dlfcn.h>
#include <map>
#include <memory>
#include <sys/socket.h>
#include <sys/types.h>

extern "C" {
struct pcap
{
    sockmap_t::iterator sockit_;
    struct pcap_pkthdr pcap_hdr_;
    rpc_pcap_pktdata_t pcap_data_;
};
};
int get_pcap_id(const struct pcap* p) { return p->sockit_->second.id_; }
int get_pcap_sd(const struct pcap* p) { return p->sockit_->second.sd_; }
typedef std::map<int, struct pcap> pcapmap_t;

class Hooks
{
  public:
    Hooks();

    // libc hooks
    int socket(int domain, int type, int protocol);
    int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
    int getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen);
    ssize_t send(int sockfd, const void* buf, size_t len, int flags);
    ssize_t sendto(int sock_id, const void* buf, size_t len, int flags,
            const struct sockaddr* dest_addr, socklen_t addrlen);
    ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags);
    ssize_t recv(int sockfd, void* buf, size_t len, int flags);
    ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr,
            socklen_t* addrlen);
    ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags);
    int close(int fd);
    int ioctl(int fd, unsigned long request, char* argp);
    ssize_t read(int fd, void* buf, size_t count);
    ssize_t write(int fd, const void* buf, size_t count);
    int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
            unsigned long arg5);

    // pcap hooks
    pcap_t* pcap_create(const char* source, char* errbuf);
    int pcap_activate(pcap_t* p);
    int pcap_findalldevs(pcap_if_t** alldevsp, char* errbuf);
    void pcap_freealldevs(pcap_if_t* alldevs);
    char* pcap_lookupdev(char* errbuf);
    pcap_t* pcap_open_offline(const char* fname, char* errbuf);
    pcap_t* pcap_open_offline_with_tstamp_precision(
            const char* fname, u_int precision, char* errbuf);
    pcap_t* pcap_fopen_offline(FILE* fp, char* errbuf);
    pcap_t* pcap_fopen_offline_with_tstamp_precision(FILE* fp, u_int precision, char* errbuf);
    pcap_t* pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf);
    pcap_t* pcap_open_dead(int linktype, int snaplen);
    pcap_t* pcap_open_dead_with_tstamp_precision(int linktype, int snaplen, u_int precision);
    void pcap_close(pcap_t* p);
    int pcap_set_snaplen(pcap_t* p, int snaplen);
    int pcap_snapshot(pcap_t* p);
    int pcap_set_promisc(pcap_t* p, int promisc);
    int pcap_set_protocol(pcap_t* p, int protocol);
    int pcap_set_rfmon(pcap_t* p, int rfmon);
    int pcap_can_set_rfmon(pcap_t* p);
    int pcap_set_timeout(pcap_t* p, int to_ms);
    int pcap_set_buffer_size(pcap_t* p, int buffer_size);
    int pcap_set_tstamp_type(pcap_t* p, int tstamp_type);
    int pcap_list_tstamp_types(pcap_t* p, int** tstamp_typesp);
    void pcap_free_tstamp_types(int* tstamp_types);
    const char* pcap_tstamp_type_val_to_name(int tstamp_type);
    const char* pcap_tstamp_type_val_to_description(int tstamp_type);
    int pcap_tstamp_type_name_to_val(const char* name);
    int pcap_set_tstamp_precision(pcap_t* p, int tstamp_precision);
    int pcap_get_tstamp_precision(pcap_t* p);
    int pcap_is_swapped(pcap_t* p);
    int pcap_major_version(pcap_t* p);
    int pcap_minor_version(pcap_t* p);
    FILE* pcap_file(pcap_t* p);
    int pcap_datalink(pcap_t* p);
    int pcap_set_datalink(pcap_t* p, int dlt);
    int pcap_list_datalinks(pcap_t* p, int** dlt_buf);
    void pcap_free_datalinks(int* dlt_list);
    const char* pcap_datalink_val_to_name(int dlt);
    const char* pcap_datalink_val_to_description(int dlt);
    int pcap_datalink_name_to_val(const char* name);
    int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user);
    int pcap_dispatch(pcap_t* p, int cnt, pcap_handler callback, u_char* user);
    int pcap_next_ex(pcap_t* p, struct pcap_pkthdr** pkt_header, const u_char** pkt_data);
    const u_char* pcap_next(pcap_t* p, struct pcap_pkthdr* h);
    void pcap_breakloop(pcap_t*);
    int pcap_setnonblock(pcap_t* p, int nonblock, char* errbuf);
    int pcap_getnonblock(pcap_t* p, char* errbuf);
    int pcap_get_selectable_fd(pcap_t* p);
    const char* pcap_statustostr(int);
    const char* pcap_strerror(int);
    char* pcap_geterr(pcap_t*);
    void pcap_perror(pcap_t*, const char*);
    int pcap_compile(pcap_t* p, struct bpf_program* fp, const std::string& filter_exp, int optimize,
            bpf_u_int32 netmask);
    int pcap_compile_nopcap(int snaplen, int linktype, struct bpf_program* fp, const char* str,
            int optimize, bpf_u_int32 mask);
    int pcap_setfilter(pcap_t* p, struct bpf_program* fp);
    void pcap_freecode(struct bpf_program*);
    int pcap_lookupnet(const char* device, bpf_u_int32* netp, bpf_u_int32* maskp, char* errbuf);
    int pcap_offline_filter(
            const struct bpf_program* fp, const struct pcap_pkthdr* h, const u_char* pkt);
    int pcap_setdirection(pcap_t* p, pcap_direction_t d);
    int pcap_stats(pcap_t* p, struct pcap_stat* ps);
    pcap_dumper_t* pcap_dump_open(pcap_t* p, const char* fname);
    pcap_dumper_t* pcap_dump_open_append(pcap_t* p, const char* fname);
    pcap_dumper_t* pcap_dump_fopen(pcap_t* p, FILE* fp);
    void pcap_dump_close(pcap_dumper_t* p);
    FILE* pcap_dump_file(pcap_dumper_t* p);
    void pcap_dump(u_char* user, struct pcap_pkthdr* h, u_char* sp);
    int pcap_dump_flush(pcap_dumper_t* p);
    long pcap_dump_ftell(pcap_dumper_t* p);
    int64_t pcap_dump_ftell64(pcap_dumper_t* p);
    int pcap_inject(pcap_t* p, const void* buf, size_t size);
    int pcap_sendpacket(pcap_t* p, const u_char* buf, int size);
    const char* pcap_lib_version(void);

  public:
    fnsocket socket_;
    fnsetsockopt setsockopt_;
    fnclose close_;
    fnsendto sendto_;
    fnioctl ioctl_;
    fnread read_;
    fnwrite write_;
    fnprctl prctl_;

    fnpcap_findalldevs pcap_findalldevs_;
    fnpcap_freealldevs pcap_freealldevs_;
    fnpcap_lookupdev pcap_lookupdev_;
    fnpcap_open_live pcap_open_live_;
    fnpcap_activate pcap_activate_;

    fnpcap_close pcap_close_;
    fnpcap_set_protocol pcap_set_protocol_;
    fnpcap_datalink pcap_datalink_;
    fnpcap_set_datalink pcap_set_datalink_;
    fnpcap_list_datalinks pcap_list_datalinks_;
    fnpcap_free_datalinks pcap_free_datalinks_;
    fnpcap_datalink_val_to_name pcap_datalink_val_to_name_;
    fnpcap_datalink_val_to_description pcap_datalink_val_to_description_;
    fnpcap_datalink_name_to_val pcap_datalink_name_to_val_;
    fnpcap_is_swapped pcap_is_swapped_;
    fnpcap_major_version pcap_major_version_;
    fnpcap_major_version pcap_minor_version_;
    fnpcap_loop pcap_loop_;
    fnpcap_dispatch pcap_dispatch_;
    fnpcap_next_ex pcap_next_ex_;
    fnpcap_next pcap_next_;
    fnpcap_breakloop pcap_breakloop_;
    fnpcap_setnonblock pcap_setnonblock_;
    fnpcap_getnonblock pcap_getnonblock_;
    fnpcap_get_selectable_fd pcap_get_selectable_fd_;
    fnpcap_statustostr pcap_statustostr_;
    fnpcap_strerror pcap_strerror_;
    fnpcap_perror pcap_perror_;
    fnpcap_geterr pcap_geterr_;
    fnpcap_stats pcap_stats_;
    fnpcap_compile pcap_compile_;
    fnpcap_setfilter pcap_setfilter_;
    fnpcap_freecode pcap_freecode_;
    fnpcap_lookupnet pcap_lookupnet_;
    fnpcap_inject pcap_inject_;
    fnpcap_sendpacket pcap_sendpacket_;
    fnpcap_lib_version pcap_lib_version_;

  private:
    sockmap_t sm_;
    pcapmap_t pcm_;
    std::unique_ptr<rpc::client> rpc_;

  private:
    void lazy();
    int map_socket_descriptor(int sockraw_id, int domain, int type, int protocol);
    int rpc_socket_raw(int domain, int type, int protocol);
    int socket_raw(int domain, int type, int protocol);
    int rpc_setsockopt(
            const sockdeets_t& sd, int level, int optname, const void* optval, socklen_t optlen);
    int rpc_ioctl(const sockdeets_t& sd, unsigned long request, char* argp);
    ssize_t rpc_sendto(int sockfd, const void* buf, size_t len, int flags,
            const struct sockaddr* dest_addr, socklen_t addrlen);
    pcap_t* rpc_pcap_open_live(
            const char* device, int snaplen, int promisc, int to_ms, char* errbuf);
    void prepare_dlfns();
};
