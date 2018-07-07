#pragma once
#include <map>
#include <pcap.h>
#include <tuple>
#include <vector>

#ifdef WIN32
typedef SOCKET socketd_t;
#else
typedef int socketd_t;
#endif

struct sockdeets_t
{
    socketd_t sd_;
    int id_;
    int domain_;
    int type_;
    int prot_;
};
typedef std::map<socketd_t, sockdeets_t> sockmap_t;

// basic return type, and int return code and error string
typedef std::tuple<int, std::string> rpc_pcap_basic_ret_t;
typedef std::tuple<int, std::string, std::string> rpc_pcap_lookupdev_ret_t;

typedef std::tuple<u_short, u_char, u_char, uint32_t> rpc_bpf_insn_t;
typedef std::vector<rpc_bpf_insn_t> rpc_bpf_program_t;
typedef std::tuple<int, int, rpc_bpf_program_t> rpc_pcap_compile_ret_t;

// timeval secs, timeval usecs, caplen, len
typedef std::tuple<long, long, bpf_u_int32, bpf_u_int32> rpc_pcap_pkthdr_t;
typedef std::vector<u_char> rpc_pcap_pktdata_t;
typedef std::tuple<int, rpc_pcap_pktdata_t, rpc_pcap_pkthdr_t> rpc_pcap_next_ret_t;
