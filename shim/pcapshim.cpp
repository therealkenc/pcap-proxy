#include "pcapshim.hpp"
#include "dlfn.h"
#include "logging.hpp"
#include "util.hpp"
#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>

/**
 * Global hooks class, which is the entry point for all our LD_PRELOAD
 * shims over libc.
 **/
static Hooks g_Hooks;

struct idnamepair_t
{
    int id_;
    const char* name_;
};

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
    return N;
}

template <class T>
static std::string to_string(const T& value)
{
    std::stringstream ss;
    ss << value;
    return ss.str();
}

template <size_t N>
std::string id_to_name(const idnamepair_t pairs[N], int id)
{
    std::stringstream ss;
    for (size_t i = 0; i < N; i++) {
        if (pairs[i].id_ == id) {
            ss << pairs[i].name_ << " (" << id << ")";
            return ss.str();
        }
    }
    ss << "??? (" << id << ")";
    return ss.str();
}

void Hooks::prepare_dlfns()
{
    socket_ = dlfn<fnsocket>("socket");
    setsockopt_ = dlfn<fnsetsockopt>("setsockopt");
    close_ = dlfn<fnclose>("close");
    sendto_ = dlfn<fnsendto>("sendto");
    ioctl_ = dlfn<fnioctl>("ioctl");
    read_ = dlfn<fnread>("read");
    write_ = dlfn<fnwrite>("write");
    prctl_ = dlfn<fnprctl>("prctl");

    pcap_findalldevs_ = dlfn<fnpcap_findalldevs>("pcap_findalldevs", false);
    pcap_freealldevs_ = dlfn<fnpcap_freealldevs>("pcap_freealldevs", false);
    pcap_lookupdev_ = dlfn<fnpcap_lookupdev>("pcap_lookupdev", false);
    pcap_open_live_ = dlfn<fnpcap_open_live>("pcap_open_live", false);
    pcap_activate_ = dlfn<fnpcap_activate>("pcap_activate", false);
    pcap_close_ = dlfn<fnpcap_close>("pcap_close", false);
    pcap_set_protocol_ = dlfn<fnpcap_set_protocol>("pcap_setprotocol", false);
    pcap_set_datalink_ = dlfn<fnpcap_set_datalink>("pcap_set_datalink", false);
    pcap_datalink_ = dlfn<fnpcap_datalink>("pcap_datalink", false);
    pcap_list_datalinks_ = dlfn<fnpcap_list_datalinks>("pcap_list_datalinks", false);
    pcap_free_datalinks_ = dlfn<fnpcap_free_datalinks>("pcap_free_datalinks", false);
    pcap_datalink_val_to_name_ =
            dlfn<fnpcap_datalink_val_to_name>("pcap_datalink_val_to_name", false);
    pcap_datalink_val_to_description_ =
            dlfn<fnpcap_datalink_val_to_description>("pcap_datalink_val_to_description", false);
    pcap_datalink_name_to_val_ =
            dlfn<fnpcap_datalink_name_to_val>("pcap_datalink_name_to_val", false);
    pcap_is_swapped_ = dlfn<fnpcap_is_swapped>("pcap_is_swapped", false);
    pcap_major_version_ = dlfn<fnpcap_major_version>("pcap_major_version", false);
    pcap_minor_version_ = dlfn<fnpcap_minor_version>("pcap_minor_version", false);
    pcap_loop_ = dlfn<fnpcap_loop>("pcap_loop", false);
    pcap_dispatch_ = dlfn<fnpcap_dispatch>("pcap_dispatch", false);
    pcap_next_ex_ = dlfn<fnpcap_next_ex>("pcap_next_ex", false);
    pcap_next_ = dlfn<fnpcap_next>("pcap_next", false);
    pcap_breakloop_ = dlfn<fnpcap_breakloop>("pcap_breakloop", false);
    pcap_setnonblock_ = dlfn<fnpcap_setnonblock>("pcap_setnonblock", false);
    pcap_getnonblock_ = dlfn<fnpcap_getnonblock>("pcap_getnonblock", false);
    pcap_get_selectable_fd_ = dlfn<fnpcap_get_selectable_fd>("pcap_get_selectable_fd", false);
    pcap_statustostr_ = dlfn<fnpcap_statustostr>("pcap_statustostr", false);
    pcap_strerror_ = dlfn<fnpcap_strerror>("pcap_strerror", false);
    pcap_perror_ = dlfn<fnpcap_perror>("pcap_perror", false);
    pcap_geterr_ = dlfn<fnpcap_geterr>("pcap_geterr", false);
    pcap_stats_ = dlfn<fnpcap_stats>("pcap_stats", false);
    pcap_compile_ = dlfn<fnpcap_compile>("pcap_compile", false);
    pcap_setfilter_ = dlfn<fnpcap_setfilter>("pcap_setfilter", false);
    pcap_freecode_ = dlfn<fnpcap_freecode>("pcap_freecode", false);
    pcap_lookupnet_ = dlfn<fnpcap_lookupnet>("pcap_lookupnet", false);
    pcap_inject_ = dlfn<fnpcap_inject>("pcap_inject", false);
    pcap_sendpacket_ = dlfn<fnpcap_sendpacket>("pcap_sendpacket", false);
    pcap_lib_version_ = dlfn<fnpcap_lib_version>("pcap_lib_version", false);
}

void Hooks::lazy()
{
    if (rpc_.get() == nullptr) {
        LOG(3) << "initializing pcap";
        rpc_ = std::make_unique<rpc::client>("127.0.0.1", 5000);
    }
}

static int libc_write(int fd, const void* buf, size_t count)
{
    auto fn = dlfn<fnwrite>("write");
    return (fn) ? fn(fd, buf, count) : -1;
}

static void logmsg(const std::string& msg) { libc_write(STDOUT_FILENO, msg.c_str(), msg.length()); }

Hooks::Hooks()
{
    LOG::set_handler(logmsg);
    // LOG(3) << "Hooks::Hooks() constructor.";
    prepare_dlfns();
}

int Hooks::close(int fd)
{
    auto iter = sm_.find(fd);
    if (iter != sm_.end()) {
        sm_.erase(iter);
    }
    int ret = close_(fd);
    return ret;
}

ssize_t Hooks::rpc_sendto(int sock_id, const void* buf, size_t len, int flags,
        const struct sockaddr* dest_addr, socklen_t addrlen)
{
    const u_char* cb = static_cast<const u_char*>(buf);
    rpc_pcap_pktdata_t bufv(cb, cb + len);
    const char* sab = reinterpret_cast<const char*>(dest_addr);
    std::vector<char> addrv(sab, sab + addrlen);
    ssize_t ret = rpc_->call("sendto", sock_id, bufv, flags, addrv).as<ssize_t>();
    return ret;
}

// htons(ETH_P_ALL) = 768
int Hooks::rpc_ioctl(const sockdeets_t& sd, unsigned long request, char* argp)
{
    auto fnifindex = [](struct ifreq& ifr) -> int {
        ifr.ifr_ifindex = 0;
        return 0;
    };

    LOG() << "ioctl() on mapped sd: " << sd.id_;
    int ret = -1;
    switch (request) {
    case SIOCGIFINDEX:
        ret = fnifindex(*reinterpret_cast<struct ifreq*>(argp));
        break;
    default:
        LOG(3) << "unknown ioctl(). exiting";
        exit(1);
        break;
    }
    return ret;
}

int Hooks::ioctl(int fd, unsigned long request, char* argp)
{
    int ret = -1;
    auto iter = sm_.find(fd);
    if (iter != sm_.end()) {
        const sockdeets_t& sd = iter->second;
        ret = rpc_ioctl(sd, request, argp);
    } else {
        ret = ioctl_(fd, request, argp);
    }
    LOG() << "ioctl(" << fd << ", " << request << ", " << ptrtohex(argp);
    return ret;
}

ssize_t Hooks::sendto(int sockfd, const void* buf, size_t len, int flags,
        const struct sockaddr* dest_addr, socklen_t addrlen)
{
    ssize_t ret = -1;
    auto iter = sm_.find(sockfd);
    if (iter != sm_.end()) {
        const sockdeets_t& sd = iter->second;
        int sock_id = sd.id_;
        ret = rpc_sendto(sock_id, buf, len, flags, dest_addr, addrlen);
    } else {
        ret = sendto_(sockfd, buf, len, flags, dest_addr, addrlen);
    }
    std::string dest_str = (dest_addr->sa_family == AF_INET)
                                   ? inet_ntoa(((struct sockaddr_in*)dest_addr)->sin_addr)
                                   : "???";
    LOG() << "sendto(" << sockfd << ", "
          << "[buffer]"
          << ", " << len << ", " << flags << ", " << dest_str << ", " << addrlen;
    return ret;
}

ssize_t Hooks::read(int fd, void* buf, size_t count)
{
    ssize_t ret = read_(fd, buf, count);
    LOG() << "read(" << fd << ", "
          << "[some buf]"
          << ", " << count << ") = " << ret;
    return ret;
}

ssize_t Hooks::write(int fd, const void* buf, size_t count)
{
    ssize_t ret = write_(fd, buf, count);
    LOG() << "write(" << fd << ", "
          << "[some buf]"
          << ", " << count << ") = " << ret;
    return ret;
}

static struct itimerspec& setitimerspecms(struct itimerspec& t, long value, long interval)
{
    t.it_value.tv_sec = value / 1000;
    t.it_value.tv_nsec = (value % 1000) * 1000000;
    t.it_interval.tv_sec = interval / 1000;
    t.it_interval.tv_nsec = (interval % 1000) * 1000000;
    return t;
}

int Hooks::map_socket_descriptor(int sockraw_id, int domain, int type, int protocol)
{
    int ret = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ret != -1) {
        auto iter = sm_.find(ret);
        if (iter != sm_.end()) {
            LOG(3) << "Socket stub fd is already in map. That ain't right. Exiting.";
            exit(1);
        }
        sm_[ret] = {
                .sd_ = ret, .id_ = sockraw_id, .domain_ = domain, .type_ = type, .prot_ = protocol};
        struct itimerspec new_value;
        struct itimerspec old_value;
        setitimerspecms(new_value, 1, 1);
        timerfd_settime(ret, 0, &new_value, &old_value);
    } else {
        LOG(3) << "Couldn't open timer stub fd. Exiting.";
        exit(1);
    }
    return ret;
}

static std::string sockdomain_name(int domain)
{
    static const idnamepair_t pairs[] = {{AF_UNIX, "AF_UNIX"},
            {AF_INET, "AF_INET"},
            {AF_INET6, "AF_INET6"},
            {AF_NETLINK, "AF_NETLINK"},
            {AF_PACKET, "AF_PACKET"}};
    return id_to_name<countof(pairs)>(pairs, domain);
}

static std::string socktype_name(int type)
{
    static idnamepair_t pairs[] = {
            {SOCK_STREAM, "SOCK_STREAM"}, {SOCK_DGRAM, "SOCK_DGRAM"}, {SOCK_RAW, "SOCK_RAW"}};
    type &= ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    return id_to_name<countof(pairs)>(pairs, type);
}

static std::string sockproto_name(int domain, int protocol)
{
    static idnamepair_t ip_pairs[] = {{IPPROTO_IP, "IPPROTO_IP"},
            {IPPROTO_TCP, "IPPROTO_TCP"},
            {IPPROTO_UDP, "IPPROTO_UDP"},
            {IPPROTO_RAW, "IPPROTO_RAW"}};
    static idnamepair_t netlink_pairs[] = {
            {NETLINK_ROUTE, "NETLINK_ROUTE"}, {NETLINK_SELINUX, "NETLINK_SELINUX"}};
    static idnamepair_t eth_pairs[] = {{ETH_P_802_3, "ETH_P_802_3"}, {ETH_P_ALL, "ETH_P_ALL"}};
    switch (domain) {
    case AF_UNIX:
        return to_string(protocol);
    case AF_INET:
    case AF_INET6:
        return id_to_name<countof(ip_pairs)>(ip_pairs, protocol);
    case AF_NETLINK:
        return id_to_name<countof(netlink_pairs)>(netlink_pairs, protocol);
    case AF_PACKET:
        return id_to_name<countof(eth_pairs)>(eth_pairs, ntohs((short)protocol));
    };
}

int Hooks::rpc_socket_raw(int domain, int type, int protocol)
{
    int ret = -1;
    lazy();
    int sockraw_id = rpc_->call("socket", domain, type, protocol).as<int>();
    if (sockraw_id != -1) {
        ret = map_socket_descriptor(sockraw_id, domain, type, protocol);
    } else {
        LOG(3) << "socket() rpc returned -1. Exiting.";
        exit(1);
    }
    return ret;
}

int Hooks::socket_raw(int domain, int type, int protocol)
{
    int ret = -1;
    switch (domain) {
    case AF_INET:
        ret = rpc_socket_raw(domain, type, protocol);
        break;
    case AF_PACKET:
        // LOG() << "socket_raw() AF_PACKET";
        ret = rpc_socket_raw(domain, type, protocol);
        break;
    default: // f.e. AF_UNIX, AF_NETLINK, AF_INET6 etc
        // LOG() << "socket_raw() \"other\" not handled (prot: " << protocol << ")";
        ret = socket_(domain, type, protocol);
        break;
    }
    return ret;
}

int Hooks::socket(int domain, int type, int protocol)
{
    int ret = -1;
    if (type == SOCK_RAW) {
        ret = socket_raw(domain, type, protocol);
    } else {
        ret = socket_(domain, type, protocol);
    }
    LOG() << "socket(" << sockdomain_name(domain) << ", " << socktype_name(type) << ", "
          << sockproto_name(domain, protocol) << ") = " << ret;
    return ret;
}

int Hooks::rpc_setsockopt(
        const sockdeets_t& sd, int level, int optname, const void* optval, socklen_t optlen)
{
    LOG() << "rpc_setsockopt(" << sd.sd_ << " [" << sd.id_ << "], " << level << ", " << optname
          << ", " << tohex_short(optval, optlen) << ", " << optlen << ")";
    const char* p = static_cast<const char*>(optval);
    std::vector<char> opt(p, p + optlen);
    int ret = rpc_->call("setsockopt", sd.id_, level, optname, opt).as<int>();
    if (ret < 0) {
        LOG(3) << "rpc_setsockopt() failed";
        exit(1);
    }
    return ret;
}

/**
  FIXME: We only shim SO_BINDTODEVICE on SOCK_RAW sockets, but
  nmap appears to do this on AF_INET6/SOCK_DGRAM/IPPROTO_UDP
  for reasons. This is just to quash an nmap warning
  that doesn't appear fatal (for now).
 **/
int Hooks::setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    int ret = -1;
    auto iter = sm_.find(sockfd);
    if (iter != sm_.end()) {
        const sockdeets_t& sd = iter->second;
        ret = rpc_setsockopt(sd, level, optname, optval, optlen);
    } else {
        if (optname == SO_BINDTODEVICE) {
            ret = 0; // FIXME: pretend we did something.
        } else {
            ret = setsockopt_(sockfd, level, optname, optval, optlen);
        }
    }
    LOG() << "setsockopt(" << sockfd << ", " << level << ", " << optname << ", " << ptrtohex(optval)
          << ", " << optlen << ") = " << ret;
    return ret;
}

std::string pcap_desc(pcap_t* p)
{
    std::ostringstream ss;
    ss << ptrtohex(p) << " [id: " << get_pcap_id(p) << " sd: " << get_pcap_sd(p) << "]";
    return ss.str();
}

int Hooks::pcap_findalldevs(pcap_if_t** alldevsp, char* errbuf)
{
    LOG(3) << "pcap_findalldevs()";
    exit(1);
}

void Hooks::pcap_freealldevs(pcap_if_t* alldevs)
{
    LOG(3) << "pcap_freealldevs()";
    exit(1);
}

char* Hooks::pcap_lookupdev(char* errbuf)
{
    static char device[64];
    LOG(3) << "pcap_lookupdev()";
    lazy();
    auto ret = rpc_->call("pcap_lookupdev").as<rpc_pcap_lookupdev_ret_t>();
    int retcode = std::get<0>(ret);
    const std::string& d = std::get<1>(ret);
    LOG(3) << "pcap_lookupdev() = " << retcode << " device: " << d
           << " (errbuf: " << std::get<2>(ret) << ")";
    if (retcode == 0) {
        // zero on success
        std::strncpy(device, d.c_str(), sizeof(device));
        return device;
    }
    return NULL;
}

pcap_t* Hooks::rpc_pcap_open_live(
        const char* device, int snaplen, int promisc, int to_ms, char* errbuf)
{
    lazy();
    std::string sdev = device;
    auto ret =
            rpc_->call("pcap_open_live", sdev, snaplen, promisc, to_ms).as<rpc_pcap_basic_ret_t>();
    int id = std::get<0>(ret);
    if (id < 0) {
        LOG(3) << "rpc_pcap_open_live() failed " << id;
        return NULL;
    }
    int sockfd = map_socket_descriptor(id, AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    sockmap_t::iterator sockit = sm_.find(sockfd);
    struct pcap pc;
    pc.sockit_ = sockit;
    struct pcap& pcref = pcm_[sockit->second.id_] = pc;
    const std::string& err = std::get<1>(ret);
    strncpy(errbuf, err.c_str(), PCAP_ERRBUF_SIZE);
    return &pcref; // nonobv: address of reference to pcap in the pcap map
}

pcap_t* Hooks::pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf)
{
    std::memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    pcap_t* p = rpc_pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    const sockdeets_t& sd = p->sockit_->second;
    LOG() << "pcap_open_live(" << device << ", " << snaplen << ", " << promisc << ", " << to_ms
          << ", [errbuf]) = " << pcap_desc(p) << " (" << errbuf << ")";
    return p;
}

int Hooks::pcap_activate(pcap_t* p)
{
    int ret = -1;
    LOG(3) << "pcap_activate(" << ptrtohex(p) << ") = " << ret;
    exit(1);
    return ret;
}

void Hooks::pcap_close(pcap_t* p)
{
    int ret = rpc_->call("pcap_close", get_pcap_id(p)).as<int>();
    LOG() << "pcap_close(" << pcap_desc(p) << ") = " << ret;
}

int Hooks::pcap_set_protocol(pcap_t* p, int protocol)
{
    LOG(3) << "pcap_set_protocol";
    exit(1);
    return 0;
}

int Hooks::pcap_datalink(pcap_t* p)
{
    int ret = rpc_->call("pcap_datalink", get_pcap_id(p)).as<int>();
    LOG() << "pcap_datalink(" << pcap_desc(p) << ") = " << ret;
    return ret;
}

int Hooks::pcap_set_datalink(pcap_t* p, int dlt)
{
    LOG(3) << "pcap_set_datalink()";
    exit(1);
    return 0;
}

int Hooks::pcap_list_datalinks(pcap_t* p, int** dlt_buf)
{
    LOG(3) << "pcap_list_datalinks()";
    exit(1);
    return 0;
}

void Hooks::pcap_free_datalinks(int* dlt_list)
{
    LOG(3) << "pcap_free_datalinks()";
    exit(1);
}

const char* Hooks::pcap_datalink_val_to_name(int dlt)
{
    LOG(3) << "pcap_datalink_val_to_name()";
    exit(1);
    return NULL;
}

const char* Hooks::pcap_datalink_val_to_description(int dlt)
{
    LOG(3) << "pcap_datalink_val_to_description()";
    exit(1);
    return NULL;
}

int Hooks::pcap_datalink_name_to_val(const char* name)
{
    LOG(3) << "pcap_datalink_name_to_val()";
    exit(1);
    return 0;
}

int Hooks::pcap_is_swapped(pcap_t* p)
{
    LOG(3) << "pcap_is_swapped";
    exit(1);
    return 0;
}

int Hooks::pcap_major_version(pcap_t* p)
{
    LOG(3) << "pcap_major_version";
    exit(1);
    return 0;
}

int Hooks::pcap_minor_version(pcap_t* p)
{
    LOG(3) << "pcap_minor_version()";
    exit(1);
    return 0;
}

int Hooks::pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user)
{
    LOG(3) << "pcap_loop()";
    exit(1);
    return 0;
}

int Hooks::pcap_dispatch(pcap_t* p, int cnt, pcap_handler callback, u_char* user)
{
    LOG(3) << "pcap_dispatch()";
    exit(1);
    return 0;
}

int Hooks::pcap_next_ex(pcap_t* p, struct pcap_pkthdr** pkt_header, const u_char** pkt_data)
{
    // first reset the timer fd
    int td = get_pcap_sd(p);
    uint64_t exp;
    int rdret = read(td, &exp, sizeof(uint64_t));
    // LOG(3) << "timer expiries: " << exp << " ret: " << rdret;

    lazy();
    auto rpc_ret = rpc_->call("pcap_next_ex", get_pcap_id(p)).as<rpc_pcap_next_ret_t>();
    int ret = std::get<0>(rpc_ret);
    std::string pktdata_str = "NULL";
    if (ret == 1) {
        const rpc_pcap_pkthdr_t& rpc_hdr = std::get<2>(rpc_ret);
        struct timeval ts = {.tv_sec = std::get<0>(rpc_hdr), .tv_usec = std::get<1>(rpc_hdr)};
        p->pcap_hdr_ = {.ts = ts, .caplen = std::get<2>(rpc_hdr), .len = std::get<3>(rpc_hdr)};
        *pkt_header = &p->pcap_hdr_;
        const rpc_pcap_pktdata_t& rpc_data = std::get<1>(rpc_ret);
        p->pcap_data_ = rpc_data; // local copy lives in our fake struct pcap
        *pkt_data = p->pcap_data_.data();
        pktdata_str = tohex_short(rpc_data.data(), rpc_data.size());
    }
    LOG() << "pcap_next_ex(" << pcap_desc(p) << ", [hdr]) = " << ret << " [" << pktdata_str << "]";
    return ret;
}

const u_char* Hooks::pcap_next(pcap_t* p, struct pcap_pkthdr* h)
{
    // LOG(3) << "pcap_next()";
    const u_char* ret = NULL;
    struct pcap_pkthdr* phdr;
    int retex = Hooks::pcap_next_ex(p, &phdr, &ret);
    if (retex == 1) {
        *h = *phdr;
    }
    return ret;
}

void Hooks::pcap_breakloop(pcap_t* p)
{
    LOG(3) << "pcap_breakloop()";
    exit(1);
}

int Hooks::pcap_setnonblock(pcap_t* p, int nonblock, char* errbuf)
{
    lazy();
    auto rpc_ret =
            rpc_->call("pcap_setnonblock", get_pcap_id(p), nonblock).as<rpc_pcap_basic_ret_t>();
    int ret = std::get<0>(rpc_ret);
    const std::string& err = std::get<1>(rpc_ret);
    strncpy(errbuf, err.c_str(), PCAP_ERRBUF_SIZE);
    LOG(3) << "pcap_setnonblock(" << pcap_desc(p) << ", " << nonblock << ") = " << ret << " ("
           << err << ")";
    return ret;
}

int Hooks::pcap_getnonblock(pcap_t* p, char* errbuf)
{
    LOG(3) << "pcap_getnonblock()";
    exit(1);
    return 0;
}

int Hooks::pcap_get_selectable_fd(pcap_t* p)
{
    int ret = get_pcap_sd(p);
    LOG() << "pcap_get_selectable_fd(" << pcap_desc(p) << ") = " << ret;
    return ret;
}

const char* Hooks::pcap_statustostr(int error)
{
    LOG(3) << "pcap_statustostr()";
    exit(1);
    return NULL;
}

const char* Hooks::pcap_strerror(int)
{
    LOG(3) << "pcap_strerror()";
    exit(1);
    return NULL;
}

char* Hooks::pcap_geterr(pcap_t*)
{
    LOG(3) << "pcap_geterr()";
    exit(1);
    return NULL;
}

void Hooks::pcap_perror(pcap_t*, const char*)
{
    LOG(3) << "pcap_perror()";
    exit(1);
}

int Hooks::pcap_compile(pcap_t* p, struct bpf_program* fp, const std::string& filter_exp,
        int optimize, bpf_u_int32 netmask)
{
    lazy();
    auto rpc_ret = rpc_->call("pcap_compile", get_pcap_id(p), filter_exp, optimize, netmask)
                           .as<rpc_pcap_compile_ret_t>();
    int ret = std::get<0>(rpc_ret);
    if (ret == 0) {
        int prog_id = std::get<1>(rpc_ret);
        const rpc_bpf_program_t& prog = std::get<2>(rpc_ret);
        u_int bf_len = prog.size();
        fp->bf_len = bf_len;
        fp->bf_insns = static_cast<struct bpf_insn*>(std::malloc(bf_len * sizeof(bpf_insn)));
        for (u_int i = 0; i < bf_len; i++) {
            const rpc_bpf_insn_t& insn = prog[i];
            fp->bf_insns[i] = {.code = std::get<0>(insn),
                    .jt = std::get<1>(insn),
                    .jf = std::get<2>(insn),
                    .k = std::get<3>(insn)};
        }
    }
    LOG() << "pcap_compile(" << pcap_desc(p) << ", " << ptrtohex(fp) << ", " << filter_exp << ", "
          << optimize << ", " << netmask << ") = " << ret;
    return ret;
}

int Hooks::pcap_setfilter(pcap_t* p, struct bpf_program* fp)
{
    lazy();
    int ret = rpc_->call("pcap_setfilter", get_pcap_id(p), 71).as<int>();
    LOG() << "pcap_setfilter(" << pcap_desc(p) << ptrtohex(fp) << ") = " << ret;
    return ret;
}

void Hooks::pcap_freecode(struct bpf_program* fp)
{
    int ret = rpc_->call("pcap_freecode", 71).as<int>();
    LOG() << "pcap_freecode(" << ptrtohex(fp) << ") = " << ret;
    std::free(fp->bf_insns);
}

int Hooks::pcap_lookupnet(const char* device, bpf_u_int32* netp, bpf_u_int32* maskp, char* errbuf)
{
    LOG(3) << "pcap_lookupnet()";
    exit(1);
    return 0;
}

int Hooks::pcap_stats(pcap_t* p, struct pcap_stat* ps)
{
    LOG(3) << "pcap_stats()";
    exit(1);
    return 0;
}

int Hooks::pcap_inject(pcap_t* p, const void* buf, size_t size)
{
    LOG(3) << "pcap_inject()";
    exit(1);
    return 0;
}

int Hooks::pcap_sendpacket(pcap_t* p, const u_char* buf, int size)
{
    LOG(3) << "pcap_sendpacket()";
    exit(1);
    return 0;
}

const char* Hooks::pcap_lib_version(void)
{
    static std::string ver;
    lazy();
    ver = rpc_->call("pcap_lib_version").as<std::string>();
    return ver.c_str();
}

static std::string err_str(int ret)
{
    std::ostringstream ss;
    if (ret != -1) {
        ss << ret;
    } else {
        constexpr size_t bufsz = 16384;
        std::array<char, bufsz> buf;
        strerror_r(errno, buf.data(), bufsz);
        ss << ret << " (" << buf.data() << ")";
    }
    return ss.str();
}

// bool g_pass = true;
bool g_pass = false;

extern "C" {

int socket(int domain, int type, int protocol) { return g_Hooks.socket(domain, type, protocol); }

int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    return g_Hooks.setsockopt(sockfd, level, optname, optval, optlen);
}

int close(int fd) { return g_Hooks.close(fd); }

ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr,
        socklen_t addrlen)
{
    return g_Hooks.sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    char* argp = va_arg(ap, char*);
    int ret = g_Hooks.ioctl(fd, request, argp);
    va_end(ap);
    return ret;
}

#if 0
ssize_t read(int fd, void *buf, size_t count)
{
    return g_Hooks.read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    return g_Hooks.write(fd, buf, count);
}
#endif

int pcap_findalldevs(pcap_if_t** alldevsp, char* errbuf)
{
    return (g_pass) ? g_Hooks.pcap_findalldevs_(alldevsp, errbuf)
                    : g_Hooks.pcap_findalldevs(alldevsp, errbuf);
}

void pcap_freealldevs(pcap_if_t* alldevs)
{
    return (g_pass) ? g_Hooks.pcap_freealldevs_(alldevs) : g_Hooks.pcap_freealldevs(alldevs);
}

char* pcap_lookupdev(char* errbuf)
{
    return (g_pass) ? g_Hooks.pcap_lookupdev_(errbuf) : g_Hooks.pcap_lookupdev(errbuf);
}

pcap_t* pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf)
{
    return (g_pass) ? g_Hooks.pcap_open_live_(device, snaplen, promisc, to_ms, errbuf)
                    : g_Hooks.pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
}

int pcap_activate(pcap_t* p)
{
    return (g_pass) ? g_Hooks.pcap_activate_(p) : g_Hooks.pcap_activate(p);
}

void pcap_close(pcap_t* p) { return (g_pass) ? g_Hooks.pcap_close_(p) : g_Hooks.pcap_close(p); }

int pcap_set_protocol(pcap_t* p, int protocol)
{
    return (g_pass) ? g_Hooks.pcap_set_protocol_(p, protocol)
                    : g_Hooks.pcap_set_protocol(p, protocol);
}

int pcap_datalink(pcap_t* p)
{
    return (g_pass) ? g_Hooks.pcap_datalink_(p) : g_Hooks.pcap_datalink(p);
}

int pcap_set_datalink(pcap_t* p, int dlt)
{
    return (g_pass) ? g_Hooks.pcap_set_datalink_(p, dlt) : g_Hooks.pcap_set_datalink(p, dlt);
}

int pcap_list_datalinks(pcap_t* p, int** dlt_buf)
{
    return (g_pass) ? g_Hooks.pcap_list_datalinks_(p, dlt_buf)
                    : g_Hooks.pcap_list_datalinks(p, dlt_buf);
}

void pcap_free_datalinks(int* dlt_list)
{
    (g_pass) ? g_Hooks.pcap_free_datalinks_(dlt_list) : g_Hooks.pcap_free_datalinks(dlt_list);
}

const char* pcap_datalink_val_to_name(int dlt)
{
    return (g_pass) ? g_Hooks.pcap_datalink_val_to_name_(dlt)
                    : g_Hooks.pcap_datalink_val_to_name(dlt);
}

const char* pcap_datalink_val_to_description(int dlt)
{
    return (g_pass) ? g_Hooks.pcap_datalink_val_to_description_(dlt)
                    : g_Hooks.pcap_datalink_val_to_description(dlt);
}

int pcap_datalink_name_to_val(const char* name)
{
    return (g_pass) ? g_Hooks.pcap_datalink_name_to_val_(name)
                    : g_Hooks.pcap_datalink_name_to_val(name);
}

int pcap_is_swapped(pcap_t* p)
{
    return (g_pass) ? g_Hooks.pcap_is_swapped_(p) : g_Hooks.pcap_is_swapped(p);
}

int pcap_major_version(pcap_t* p)
{
    return (g_pass) ? g_Hooks.pcap_major_version_(p) : g_Hooks.pcap_major_version(p);
}

int pcap_minor_version(pcap_t* p)
{
    return (g_pass) ? g_Hooks.pcap_minor_version_(p) : g_Hooks.pcap_minor_version(p);
}

int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user)
{
    return (g_pass) ? g_Hooks.pcap_loop_(p, cnt, callback, user)
                    : g_Hooks.pcap_loop(p, cnt, callback, user);
}

int pcap_dispatch(pcap_t* p, int cnt, pcap_handler callback, u_char* user)
{
    return (g_pass) ? g_Hooks.pcap_dispatch_(p, cnt, callback, user)
                    : g_Hooks.pcap_dispatch(p, cnt, callback, user);
}

int pcap_next_ex(pcap_t* p, struct pcap_pkthdr** pkt_header, const u_char** pkt_data)
{
    return (g_pass) ? g_Hooks.pcap_next_ex_(p, pkt_header, pkt_data)
                    : g_Hooks.pcap_next_ex(p, pkt_header, pkt_data);
}

const u_char* pcap_next(pcap_t* p, struct pcap_pkthdr* h)
{
    return (g_pass) ? g_Hooks.pcap_next_(p, h) : g_Hooks.pcap_next(p, h);
}

void pcap_breakloop(pcap_t* p)
{
    (g_pass) ? g_Hooks.pcap_breakloop_(p) : g_Hooks.pcap_breakloop(p);
}

int pcap_setnonblock(pcap_t* p, int nonblock, char* errbuf)
{
    return (g_pass) ? g_Hooks.pcap_setnonblock_(p, nonblock, errbuf)
                    : g_Hooks.pcap_setnonblock(p, nonblock, errbuf);
}

int pcap_getnonblock(pcap_t* p, char* errbuf)
{
    return (g_pass) ? g_Hooks.pcap_getnonblock_(p, errbuf) : g_Hooks.pcap_getnonblock(p, errbuf);
}

int pcap_get_selectable_fd(pcap_t* p)
{
    return (0) ? g_Hooks.pcap_get_selectable_fd_(p) : g_Hooks.pcap_get_selectable_fd(p);
}

const char* pcap_statustostr(int error)
{
    return (g_pass) ? g_Hooks.pcap_statustostr_(error) : g_Hooks.pcap_statustostr(error);
}

const char* pcap_strerror(int error)
{
    return (g_pass) ? g_Hooks.pcap_strerror_(error) : g_Hooks.pcap_strerror(error);
}

char* pcap_geterr(pcap_t* p) { return (g_pass) ? g_Hooks.pcap_geterr_(p) : g_Hooks.pcap_geterr(p); }

void pcap_perror(pcap_t* p, const char* prefix)
{
    (g_pass) ? g_Hooks.pcap_perror_(p, prefix) : g_Hooks.pcap_perror(p, prefix);
}

int pcap_compile(
        pcap_t* p, struct bpf_program* fp, const char* str, int optimize, bpf_u_int32 netmask)
{
    return (g_pass) ? g_Hooks.pcap_compile_(p, fp, str, optimize, netmask)
                    : g_Hooks.pcap_compile(p, fp, str, optimize, netmask);
}

int pcap_setfilter(pcap_t* p, struct bpf_program* fp)
{
    return (g_pass) ? g_Hooks.pcap_setfilter_(p, fp) : g_Hooks.pcap_setfilter(p, fp);
}

void pcap_freecode(struct bpf_program* fp)
{
    return (g_pass) ? g_Hooks.pcap_freecode_(fp) : g_Hooks.pcap_freecode(fp);
}

int pcap_lookupnet(const char* device, bpf_u_int32* netp, bpf_u_int32* maskp, char* errbuf)
{
    return (g_pass) ? g_Hooks.pcap_lookupnet_(device, netp, maskp, errbuf)
                    : g_Hooks.pcap_lookupnet(device, netp, maskp, errbuf);
}

int pcap_stats(pcap_t* p, struct pcap_stat* ps)
{
    return (g_pass) ? g_Hooks.pcap_stats_(p, ps) : g_Hooks.pcap_stats(p, ps);
}

int pcap_inject(pcap_t* p, const void* buf, size_t size)
{
    return (g_pass) ? g_Hooks.pcap_inject_(p, buf, size) : g_Hooks.pcap_inject(p, buf, size);
}

int pcap_sendpacket(pcap_t* p, const u_char* buf, int size)
{
    return (g_pass) ? g_Hooks.pcap_sendpacket_(p, buf, size)
                    : g_Hooks.pcap_sendpacket(p, buf, size);
}

const char* pcap_lib_version(void)
{
    return (g_pass) ? g_Hooks.pcap_lib_version_() : g_Hooks.pcap_lib_version();
}

} // extern "C"
