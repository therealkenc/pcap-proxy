#include "logging.hpp"
#include <iomanip>

#ifdef WIN32
#include <process.h>
int mygetpid() { return _getpid(); }
#else
#include <unistd.h>
int mygetpid() { return getpid(); }
#endif


int LOG::level_ = 3;
fnlogmsg LOG::handler_ = nullhandler;

void nullhandler(const std::string & msg)
{
}

LOG::~LOG()
{
    static std::mutex m;
    std::lock_guard<std::mutex> guard(m);
    if (msg_level_ < LOG::level_) {
        return;
    }
    std::stringstream ss;
#ifdef WIN32
    std::string label = "pcap-shim: ";
#else
    std::string label = "\033[33mpcap-shim:\033[0m ";
#endif
    ss << label << std::setfill('0') << std::setw(4) 
        << mygetpid() << " " << msg_.str() << "\n" << std::flush;
    std::string msg = ss.str();
    handler_(msg);
}
