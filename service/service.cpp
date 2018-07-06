#include "util.hpp"
#include "logging.hpp"
#include "common.hpp"
#include "rpc/server.h"
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <codecvt>
#endif
#include <stdlib.h>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <tuple>

#ifdef WIN32
typedef SSIZE_T ssize_t;

static std::string hresult_str(HRESULT hr)
{
    char buf[4096];
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        hr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf,
        sizeof(buf), 
        NULL );
    return buf;
}

static std::string errorno_str(int ret)
{
    std::ostringstream ss;
    if (ret < 0) {
        int wsaerrno = WSAGetLastError();
        std::string errstr = hresult_str(wsaerrno);
        ss << "(" << errstr << ")";
    }
    return ss.str();
}

#else

static std::string errorno_str(int ret)
{
    std::ostringstream ss;
    if (ret < 0) {
        ss << "some linux error";
    }
    return ss.str();
}
#endif

class errbuf_t
{
public:
    std::string str() const { return errbuf_; }
    char* data()
    {
        constexpr char success[] = "success";
        std::memcpy(errbuf_, success, sizeof(success));
        return errbuf_;
    }

private:
    char errbuf_[PCAP_ERRBUF_SIZE];
};

constexpr size_t MAC_LEN = 6;
constexpr size_t EHDR_LEN = 2*MAC_LEN+2;
typedef std::map<int, pcap_t *> pcapmap_t;

static std::string ipv4addr_to_str(const struct sockaddr_in *sa)
{
	char buf[INET6_ADDRSTRLEN];
	return inet_ntop(AF_INET, &sa->sin_addr, buf, INET6_ADDRSTRLEN);
}

static std::string ipv6addr_to_str(const struct sockaddr_in6 *sa)
{
	char buf[INET6_ADDRSTRLEN];
	return inet_ntop(AF_INET, &sa->sin6_addr, buf, INET6_ADDRSTRLEN);
}

static std::string sockaddr_to_str(const struct sockaddr * sa)
{
	std::string ret;
	switch (sa->sa_family) {
	case AF_INET:
		ret = ipv4addr_to_str(reinterpret_cast<const struct sockaddr_in*>(sa));
		break;
	case AF_INET6:
		ret = ipv6addr_to_str(reinterpret_cast<const struct sockaddr_in6 *>(sa));
		break;
	default:
		ret = "[some eth addr probably]";
	}
	return ret;
}

static std::string ipv4_ntoa(DWORD a)
{
	sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = 0;
	sa.sin_addr.S_un.S_addr = a;
	return ipv4addr_to_str(&sa);
}

static std::string phys_ntoa(const u_char *mac)
{
	std::ostringstream ss;
	ss << tohex_field(mac[0]);
	for (int i = 1; i < MAC_LEN; i++) {
		ss << ":" << tohex_field(mac[i]);
	}
	return ss.str();
}

/** Sad (grumble). Adding _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING to the 
 *	compiler flags. https://goo.gl/Uxigaq
 **/ 
static std::string utf8_narrow(const std::wstring & wstr)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> convert;
	return convert.to_bytes(wstr);
}

static std::string quoted(const std::string &s)
{
	std::ostringstream ss;
	ss << "\"" << s << "\"";
	return ss.str();
}

static size_t pcap_sendto(pcap_t *p, const char *buf, size_t len)
{
    return (pcap_sendpacket(p, (const u_char*)buf, (int)len) < 0) ? 0 : len;
}

class MACAddr
{
public:
    MACAddr() {}
    MACAddr(const u_char *mac) { std::memcpy(data_, mac, MAC_LEN); }
    MACAddr(const MACAddr& mac) { std::memcpy(data_, mac.data(), MAC_LEN); }
    u_char *data() { return data_; }
    const u_char *data() const { return data_; }
    bool is_null() const { return std::memcmp(null_mac_.data(), data_, MAC_LEN) == 0; }
    std::string str() const { return phys_ntoa(data_); }

private:
    static MACAddr null_mac_;
    u_char data_[MAC_LEN] = {};
};

MACAddr MACAddr::null_mac_;

#ifdef WIN32
class Adapter
{
public:
    Adapter(const IP_ADAPTER_ADDRESSES &aa);
    DWORD src_ip() const { return src_ip_; }
    DWORD gw_ip() const { return gw_ip_; }
    const MACAddr &src_mac() const { return src_mac_; }
    const MACAddr &gw_mac() const { return gw_mac_; }
    std::string str() const;

private:
    int arp_lookup(u_char *mac, DWORD ip);

private:
    const IP_ADAPTER_ADDRESSES &aa_;
    DWORD src_ip_ = 0;
    DWORD gw_ip_ = 0;
    MACAddr src_mac_;
    MACAddr gw_mac_;
    bool gotgw_ = false;
    bool gotsrc_ = false;
};

Adapter::Adapter(const IP_ADAPTER_ADDRESSES &aa) : aa_(aa) 
{
    const PIP_ADAPTER_UNICAST_ADDRESS &ua = aa.FirstUnicastAddress;
    const struct sockaddr_in *sa = 
        reinterpret_cast<const struct sockaddr_in*>(ua->Address.lpSockaddr);
    src_ip_ = (sa != nullptr) ? sa->sin_addr.S_un.S_addr : 0;
    const PIP_ADAPTER_GATEWAY_ADDRESS &gwa = aa.FirstGatewayAddress;
    const struct sockaddr_in *gwsa = reinterpret_cast<const struct sockaddr_in*>((gwa != nullptr) ? 
            gwa->Address.lpSockaddr : nullptr);
    gw_ip_ = (gwsa != nullptr) ? gwsa->sin_addr.S_un.S_addr : 0;
    gotgw_ = gw_ip_ != 0 && arp_lookup(gw_mac_.data(), gw_ip_) == 0;
    gotsrc_ = aa.PhysicalAddressLength == MAC_LEN && 
        std::memcpy(src_mac_.data(), aa.PhysicalAddress, MAC_LEN) != nullptr;
}

int Adapter::arp_lookup(u_char *mac, DWORD ip)
{
	auto log_row = [](DWORD i, const MIB_IPNETROW &row) {
		LOG() << i << ": " << ipv4_ntoa(row.dwAddr) << " " << phys_ntoa(row.bPhysAddr);
	};
    auto find_loop = [log_row, mac, ip](const MIB_IPNETTABLE &mibnt) {
        bool found = false;
        for (DWORD i = 0; !found && i < mibnt.dwNumEntries; i++) {
            const MIB_IPNETROW &row = mibnt.table[i];
            log_row(i, row);
            if (row.dwAddr == ip) {
                found = true;
                std::memcpy(mac, row.bPhysAddr, MAC_LEN);
            }
        }
        return found ? 0 : -1;
    };
    auto dolookup = [find_loop](ULONG sz) {
		std::vector<char> buf(sz);
		MIB_IPNETTABLE *mibnt = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
		return (GetIpNetTable(mibnt, &sz, FALSE) == NO_ERROR) ? find_loop(*mibnt) : -1;
    };
	ULONG sz = 0;
	return (GetIpNetTable(NULL, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER) ? dolookup(sz) : -1;
}

std::string Adapter::str() const
{
    constexpr char nomac[] = "no MAC     ";
    std::string gwip_str = (gw_ip_ != 0) ? ipv4_ntoa(gw_ip_) : "no gateway";
    std::string gwmac_str = gotgw_ ? gw_mac_.str() : nomac;
    std::string srcmac_str = gotsrc_ ? src_mac_.str() : nomac;
    std::string friendly = quoted(utf8_narrow(aa_.FriendlyName));
    std::string description = quoted(utf8_narrow(aa_.Description));
    std::ostringstream ss;
    ss << srcmac_str << " " << ipv4_ntoa(src_ip_) 
            << " " << gwmac_str << " " << gwip_str
        << "\n     " << aa_.AdapterName 
        << "\n     " << friendly 
        << "\n     "
        << description;
    return ss.str();
}

class AdapterTable
{
public:
    int initialize();
    int find_iface(MACAddr &gw_mac, DWORD &gw_ip, MACAddr &src_mac, DWORD src_ip);

private:
    IP_ADAPTER_ADDRESSES *addresses();

private:
    std::vector<char> buf_;
};

int AdapterTable::initialize()
{
    constexpr ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | 
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    auto doget = [this, flags](ULONG sz) {
        buf_.resize(sz);
        return (GetAdaptersAddresses(AF_INET, flags, NULL, addresses(), &sz) == NO_ERROR) ? 0 : -1;
    };
    ULONG sz = 0;
    return (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &sz) == ERROR_BUFFER_OVERFLOW) ?
        doget(sz) : -1;
}

IP_ADAPTER_ADDRESSES *AdapterTable::addresses()
{
    return reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf_.data());
}

int AdapterTable::find_iface(MACAddr &gw_mac, DWORD &gw_ip, MACAddr &src_mac, DWORD src_ip)
{
    bool found = false;
    IP_ADAPTER_ADDRESSES *paa = addresses();
    for (int i = 0; !found && paa != nullptr; i++, paa = paa->Next) {
        Adapter adpt(*paa);
        if (adpt.src_ip() == src_ip && !adpt.src_mac().is_null() && !adpt.gw_mac().is_null()) {
            found = true;
            gw_mac = adpt.gw_mac();
            gw_ip = adpt.gw_ip();
            src_mac = adpt.src_mac();
        }
    }
    return found ? 0 : -1;
}

class Ipv4Wrapper
{
public:
    int initialize(std::string &pcap_dev, errbuf_t &errbuf);
    int sendto(pcap_t *p, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);

private:
    DWORD src_ip_ = 0;
    DWORD gw_ip_ = 0;
    MACAddr src_mac_;
    MACAddr gw_mac_;
};

int Ipv4Wrapper::initialize(std::string &pcap_dev, errbuf_t &errbuf)
{
    pcap_if_t *interfaces;
	int devs_ret = pcap_findalldevs(&interfaces, errbuf.data());
    if (devs_ret == -1) {
        LOG(3) << "guh. pcap_findalldevs() failed";
        return -1;
    }
    // FIXME: massive assumption the first device is the one we want
    pcap_if_t &pcif = interfaces[0];
    pcap_dev = pcif.name;
    // FIXME: massive assumption the first ipv4 adress we find is the
	// one we want
	src_ip_ = 0;
	for (pcap_addr *pcad = pcif.addresses; src_ip_ == 0 && pcad != nullptr; pcad = pcad->next) {
		ADDRESS_FAMILY family = pcad->addr->sa_family;
		if (family == AF_INET) {
			const struct sockaddr_in *sin = reinterpret_cast<const struct sockaddr_in*>(pcad->addr);
			src_ip_ = sin->sin_addr.S_un.S_addr;
		}
	}
    if (src_ip_ == 0) {
        LOG(3) << "guh. failed to determine source ip";
    }
    AdapterTable at;
    if (at.initialize() < 0) {
        LOG(3) << "guh. failed to query adapters";
        return -1;
    }
    if (at.find_iface(gw_mac_, gw_ip_, src_mac_, src_ip_) < 0) {
        LOG(3) << "guh. failed to find interface details";
    }
    LOG(3) << "source: " << ipv4_ntoa(src_ip_) << " " << src_mac_.str();
	LOG(3) << "gateway: " << ipv4_ntoa(gw_ip_) << " " << gw_mac_.str();
    return 0;
}

int Ipv4Wrapper::sendto(pcap_t *p, const char *buf, int len, int flags, 
    const struct sockaddr *to, int tolen)
{
    std::vector<char> ethbuf(len + EHDR_LEN);
    char *eb = ethbuf.data();
    std::memcpy(eb, gw_mac_.data(), MAC_LEN);
    std::memcpy(eb+MAC_LEN, src_mac_.data(), MAC_LEN);
    eb[2*MAC_LEN+0] = 0x08; // ipv4 magic number
    eb[2*MAC_LEN+1] = 0x00;
    std::memcpy(eb+EHDR_LEN, buf, len);
    return pcap_sendto(p, ethbuf.data(), len+14);
}

#endif

#define LX_SOL_IP	        0
#define LX_SOL_SOCKET       1       // 0xffff 
#define LX_SO_BROADCAST     6       // 0x0020
#define LX_SO_BINDTODEVICE	25      // doesn't exist
#define LX_IP_HDRINCL       3       // 2
#define LX_AF_PACKET	    17
#define SOCKFD_PACKET_MAGIC 12345

class ServerCtx
{
public:
    void Run();

private:
    int map_socket(socketd_t sd, int domain, int type, int protocol);
    int rpc_socket(int domain, int type, int protocol);
    int rpc_setsockopt(int sock_id, int level, int optname, const std::vector<char> &opt);
    ssize_t rpc_sendto(int sock_id, const rpc_pcap_pktdata_t &bufv, int flags, std::vector<char> &addrv);
    std::string rpc_pcap_lib_version();
    rpc_pcap_lookupdev_ret_t rpc_pcap_lookupdev();
    int win32_init(std::string &pcap_dev, errbuf_t &errbuf);
    rpc_pcap_basic_ret_t rpc_pcap_open_live(const std::string &device, int snaplen, 
        int promisc, int to_ms);
    rpc_pcap_compile_ret_t rpc_pcap_compile(int pcap_id, const std::string &filter_exp, 
        int optimize, bpf_u_int32 netmask);
    int rpc_pcap_setfilter(int pcap_id, int filter_id);
    int rpc_pcap_freecode(int filter_id);
    int rpc_pcap_datalink(int pcap_id);
    int rpc_pcap_close(int pcap_id);
    rpc_pcap_next_ret_t rpc_pcap_next_ex(int pcap_id);
    rpc_pcap_basic_ret_t rpc_pcap_setnonblock(int pcap_id, int nonblock);

private:
    std::unique_ptr<rpc::server> svr_;
    sockmap_t sm_;
    pcapmap_t pcm_;
    int unique_id_ = 1000;
    struct bpf_program filter_;
#ifdef WIN32
    // FIXME: Sloppy. Define an opague api and implement a Linux equivalent
    Ipv4Wrapper wrap_;
#endif
};

void ServerCtx::Run()
{
    svr_ = std::make_unique<rpc::server>(5000);
    svr_->bind("echo", [](const std::string &msg) -> std::string {
        LOG(3) << "echo: " << msg;
        return msg;
    });
    svr_->bind("socket", [this](int domain, int type, int protocol) -> int {
        return rpc_socket(domain, type, protocol);
    });
    svr_->bind("setsockopt", [this](int sock_id, int level, int optname, 
            const std::vector<char> &opt) -> int {
        return rpc_setsockopt(sock_id, level, optname, opt);
    });
    svr_->bind("sendto", [this](int sock_id, const rpc_pcap_pktdata_t &bufv, int flags, 
        std::vector<char>addrv) -> ssize_t {
        return rpc_sendto(sock_id, bufv, flags, addrv);
    });
    svr_->bind("pcap_lib_version", [this]() -> std::string {
        return rpc_pcap_lib_version();
    });
    svr_->bind("pcap_lookupdev", [this]() -> rpc_pcap_lookupdev_ret_t {
        return rpc_pcap_lookupdev();
    });
    svr_->bind("pcap_open_live", [this](const std::string &device, int snaplen, int promisc, 
            int to_ms) -> rpc_pcap_basic_ret_t {
        return rpc_pcap_open_live(device, snaplen, promisc, to_ms);
    });
    svr_->bind("pcap_compile", [this](int pcap_id, const std::string &str, 
            int optimize, bpf_u_int32 netmask) -> rpc_pcap_compile_ret_t {
        return rpc_pcap_compile(pcap_id, str, optimize, netmask);
    });
    svr_->bind("pcap_setfilter", [this](int pcap_id, int filter_id) -> int {
        return rpc_pcap_setfilter(pcap_id, filter_id);
    });
    svr_->bind("pcap_freecode", [this](int filter_id) -> int {
        return rpc_pcap_freecode(filter_id);
    });
    svr_->bind("pcap_datalink", [this](int pcap_id) -> int {
        return rpc_pcap_datalink(pcap_id);
    });
    svr_->bind("pcap_close", [this](int pcap_id) -> int {
        return rpc_pcap_close(pcap_id);
    });
    svr_->bind("pcap_next_ex", [this](int pcap_id) -> rpc_pcap_next_ret_t {
        return rpc_pcap_next_ex(pcap_id);
    });
    svr_->bind("pcap_setnonblock", [this](int pcap_id, int nonblock) -> rpc_pcap_basic_ret_t {
        return rpc_pcap_setnonblock(pcap_id, nonblock);
    });
    
    svr_->run();
}

int ServerCtx::map_socket(socketd_t sd, int domain, int type, int protocol)
{
    int id = unique_id_++;
    sm_[id] = { sd, id, domain, type, protocol };
    return id;
}

int ServerCtx::rpc_socket(int domain, int type, int protocol)
{
    socketd_t sd = -1;
    switch(domain){
    case AF_INET:
        sd = socket(domain, type, protocol);
        break;
    case LX_AF_PACKET:
        sd = SOCKFD_PACKET_MAGIC;
        break;
    default:
        LOG(3) << "rpc_socket() got unexpected domain from client: " << domain;
        break;
    }
    int ret = (sd != -1) ? map_socket(sd, domain, type, protocol) : -1;
    LOG() << "socket(" << domain << " , " << type << " , " 
        << protocol << ") = " << ret << " [sd:" << sd << "] (" << errorno_str(ret) << ")";    
    return ret;
}


#ifdef WIN32
static int setsockopt_win32(socketd_t sd, int level, int optname, const char * optval, socklen_t optlen)
{
    int ret = -1;
    if (level == LX_SOL_SOCKET && optname == LX_SO_BROADCAST) {
        LOG() << "SO_BROADCAST shimmed. level: " << level << " optname: " << optname;
        ret = setsockopt(sd, SOL_SOCKET, SO_BROADCAST, optval, optlen);
    } else if (level == LX_SOL_IP && optname == LX_IP_HDRINCL) {
        LOG() << "IP_HDRINCL shimmed. level: " << level << " optname: " << optname;
        ret = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, optval, optlen);
    } else if (level == LX_SOL_SOCKET && optname == LX_SO_BINDTODEVICE) {
        LOG() << "SO_BINDTODEVICE stubbed";
        ret = 0;
    } else {
        LOG(3) << "win32 setsockopt() opt not handled";
    }
    return ret;
}
#endif

static int mysetsockopt(socketd_t sd, int level, int optname, const char * optval, socklen_t optlen)
{
#ifdef WIN32
    return setsockopt_win32(sd, level, optname, optval, optlen);
#else
    return setsockopt(sd, level, optname, optval, optlen);
#endif
}

/**
 * If this is a LX_AF_PACKET then we work under the incorrect but practical 
 * assumption that libpcap has a packet stream all primed for sending raw 
 * ethernet frames with pcap_sendpacket(), and there are no socket options 
 * worth mucking with further.
 **/
int ServerCtx::rpc_setsockopt(int sock_id, int level, int optname, const std::vector<char> &opt)
{
    int ret = -1;
    socketd_t sd = -1;
    auto it = sm_.find(sock_id);
    if (it != sm_.end()) {
        const sockdeets_t &deets = it->second;
        sd = deets.sd_;
        ret = (deets.domain_ != LX_AF_PACKET) ? 
            mysetsockopt(sd, level, optname, opt.data(), (socklen_t)opt.size()) : 0;
    }
    LOG() << "setsockopt(" << sock_id << " [sd: " << sd << "], " 
        << level << ", " << optname << ", "
        << tohex_short(opt.data(), opt.size()) 
        << " len: " << opt.size() << "]) = " << ret;
    return ret;
}

/**
 * Sloppy hack for now.
 * 
 * In theory we keep a map pf pcap instances around in the for 
 * the (nonexistent) case that multiple simultaneous clients
 * are doing operations. When we are sending a pcap_sendpacket()
 * we don't much care what instance does the job, only that it
 * is open and active.
 **/
ssize_t ServerCtx::rpc_sendto(int sock_id, const rpc_pcap_pktdata_t &bufv, int flags, 
        std::vector<char> &addrv)
{
    ssize_t ret = -1;
    socketd_t sd = -1;
    size_t length = bufv.size();
    socklen_t sa_len = (socklen_t)addrv.size();
    const struct sockaddr *sa = reinterpret_cast<const struct sockaddr *>(addrv.data());
    auto it = sm_.find(sock_id);
    if (it != sm_.end()) {
        const sockdeets_t &deets = it->second;
        sd = deets.sd_;
        pcap_t *p = pcm_.begin()->second;
        LOG() << "sendto domain: " << deets.domain_ << " type: " << deets.type_ 
            << "(" << AF_INET << ", " << SOCK_RAW << ")";
        const char *bd = reinterpret_cast<const char*>(bufv.data());
        if (deets.domain_ == LX_AF_PACKET) {
            ret = pcap_sendto(p, bd, length);
#ifdef WIN32
        } else if (deets.domain_ == AF_INET && deets.type_ == SOCK_RAW) {
            ret = wrap_.sendto(p, bd, (int)length, flags, sa, sa_len);
#endif
        } else {
            ret = sendto(deets.sd_, bd, (int)length, flags, sa, sa_len);
        }
    }
    LOG() << "rpc_sendto(" << sock_id << " [sd: " << sd << "], " << "[buf]" << ", "  
        << length << ", \"" << sockaddr_to_str(sa) << "\", " << sa_len << ") = " 
        << ret;
    return ret;
}

std::string ServerCtx::rpc_pcap_lib_version()
{
    return pcap_lib_version();
}

rpc_pcap_lookupdev_ret_t ServerCtx::rpc_pcap_lookupdev()
{
    errbuf_t errbuf;
    char *pd = pcap_lookupdev(errbuf.data());
    rpc_pcap_lookupdev_ret_t ret;
    if (pd != NULL) {
        std::string device = pd;
        LOG(3) << "rpc_pcap_lookupdef() found: " << device;
        ret = std::make_tuple(0, device, errbuf.str());
    } else {
        LOG(3) << "rpc_pcap_lookupdef() failed";
        ret = std::make_tuple(-1, std::string(""), errbuf.str());
    }
    return ret;
}

rpc_pcap_basic_ret_t ServerCtx::rpc_pcap_open_live(const std::string &device, int snaplen, 
    int promisc, int to_ms)
{
    LOG(3) << "pcap_open_live(" << device << ", " << snaplen << ", " 
        << promisc << ", " << to_ms << ")";
#ifdef WIN32
    errbuf_t errbuf;
    std::string pcap_dev;
    if (wrap_.initialize(pcap_dev, errbuf) < 0) {
        return std::make_tuple(-1, errbuf.str());
    }
    const char *dev = pcap_dev.c_str();
#else
    const char *dev = device.c_str();
#endif
    LOG(3) << "using interface: " << dev;
    pcap_t * p = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf.data());
    if (p == NULL) {
        LOG(3) << "oops pcap_open_live() returned NULL";
        return std::make_tuple(-1, errbuf.str());
    }
    // We are **always** nonblocking even if the client wanted blocking
    // pcap_next() semantics. See comment at pcap_next_ex_loop.
    pcap_setnonblock(p, 1, errbuf.data());
    int id = unique_id_++;
    pcm_[id] = p;
    return std::make_tuple(id, errbuf.str());
}

/**
 * The compiled BPF program is returned to the client by value, and 
 * then passed back to us just so we can pcap_setfilter() it a moment 
 * later. It would probably be better if (a) we just kept a reference
 * (cache) of the compiled program and passed back an id, or (b)
 * just compile the thing on the client with a pcap_open_dead().
 **/ 
rpc_pcap_compile_ret_t ServerCtx::rpc_pcap_compile(int pcap_id, const std::string &filter_exp, int optimize, 
        bpf_u_int32 netmask)
{
    //std::string fe = "icmp";
    //int compile_ret = pcap_compile(pcap_, &filter_, fe.c_str(), optimize, netmask);
    auto it = pcm_.find(pcap_id);
    rpc_bpf_program_t program;
    if (it == pcm_.end()) {
        return std::make_tuple(-1, -1, program);
    }
    pcap_t *p = it->second;
    int ret = pcap_compile(p, &filter_, filter_exp.c_str(), optimize, netmask);
    LOG() << "rpc_pcap_compile(" << pcap_id << ", " << filter_exp << ", " 
        << optimize << ", " << tohex_field(netmask) << ") = " << ret;
    int filter_id = -1;
    if (ret == 0) {
        LOG() << "pcap_compile() success (filter bf_len = " << filter_.bf_len << ")";
        filter_id = 0;  // FIXME: only one filter up in the air at once for now
        program.resize(filter_.bf_len);
        for (u_int i = 0; i < filter_.bf_len; i++) {
            const bpf_insn & insn = filter_.bf_insns[i];
            program[i] = std::make_tuple(insn.code, insn.jt, insn.jf, insn.k);
        }
    } else {
        LOG(3) << "pcap_compile() )failed";
    }
    return std::make_tuple(ret, filter_id, program); 
}

int ServerCtx::rpc_pcap_setfilter(int pcap_id, int filter_id)
{
    auto it = pcm_.find(pcap_id);
    int ret = (it != pcm_.end()) ? pcap_setfilter(it->second, &filter_) : -1;
    LOG() << "pcap_setfilter(" << pcap_id << ", " << filter_id << ") = " << ret;
    return ret;
}

int ServerCtx::rpc_pcap_freecode(int filter_id)
{
    int ret = 0;
    pcap_freecode(&filter_);
    LOG() << "pcap_freecode(" << filter_id << ") = " << ret;
    return ret;
}

int ServerCtx::rpc_pcap_datalink(int pcap_id)
{
    auto it = pcm_.find(pcap_id);
    int ret = (it != pcm_.end()) ? pcap_datalink(it->second) : -1;
    LOG() << "pcap_datalink(" << pcap_id << ") = " << ret;
    return ret;
}

int ServerCtx::rpc_pcap_close(int pcap_id)
{
    auto pcclose = [this](pcapmap_t::iterator &it) -> int {
        pcap_close(it->second);
        pcm_.erase(it);
        return 0;
    };
    auto it = pcm_.find(pcap_id);
    int ret = (it != pcm_.end()) ? pcclose(it) : -1;
    LOG() << "pcap_close(" << pcap_id << ") = " << ret;
    return ret;
}

static void myusleep(long us)
{
    // only in C++11 would this syntax seem sensible for usleep()
    std::this_thread::sleep_for(std::chrono::microseconds(us));
}

rpc_pcap_next_ret_t ServerCtx::rpc_pcap_next_ex(int pcap_id)
{
    //LOG(3) << "entering rpc_pcap_next_ex()";
    rpc_pcap_next_ret_t rpc_ret;
    struct pcap_pkthdr *pkthdr;
    const u_char * pktdata;
    auto it = pcm_.find(pcap_id);
    int ret = -1;
    if (it != pcm_.end() && (ret = pcap_next_ex(it->second, &pkthdr, &pktdata)) == 1) {
        //LOG(3) << "pcap_next_ex() success len: " << pkthdr->len << " caplen: " << pkthdr->caplen;
        long tv_sec = pkthdr->ts.tv_sec;
        long tv_usec = pkthdr->ts.tv_usec;
        rpc_pcap_pktdata_t rpc_pktdata;
        rpc_pktdata.resize(pkthdr->len);
        std::memcpy(rpc_pktdata.data(), pktdata, pkthdr->len);
        rpc_pcap_pkthdr_t rpc_pkthdr = std::make_tuple(tv_sec, tv_usec, pkthdr->caplen, pkthdr->len);
        //LOG(3) << "rpc_pcap_next_ex() returning packet len: " << pkthdr->len;
        rpc_ret = std::make_tuple(ret, rpc_pktdata, rpc_pkthdr);
    } else {
        // std::string err = (it != pcm_.end()) ? pcap_geterr(it->second) : "?";
        // LOG(3) << "pcap_next_ex() error: " << ret << " " << err;
        rpc_ret = std::make_tuple(ret, rpc_pcap_pktdata_t(), rpc_pcap_pkthdr_t());
    }
    return rpc_ret;
}

rpc_pcap_basic_ret_t ServerCtx::rpc_pcap_setnonblock(int pcap_id, int nonblock)
{
    errbuf_t errbuf;
    auto it = pcm_.find(pcap_id);
    int ret = (it != pcm_.end()) ? pcap_setnonblock(it->second, nonblock, errbuf.data()) : -1;
    LOG() << "rpc_pcap_nonblock(" << pcap_id << ", " << nonblock << ") = " << ret;
    return std::make_tuple(ret, errbuf.str());
}

static void logmsg(const std::string & msg)
{
    std::cout << msg;
}

int main(int argc, const char *argv[])
{
    LOG::set_handler(logmsg);
    LOG(3) << "starting wslpcapsvr";
    //dump_interfaces();
    ServerCtx svr;
    svr.Run();
    return 0;
}
