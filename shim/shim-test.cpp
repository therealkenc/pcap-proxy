#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include <tuple>

typedef std::tuple<int, std::string> sometupl;

int main(int argc, const char* argv[])
{
    std::cout << "running wslshim-test foo\n";
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //int op = 1;
    //int ret = setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &op, sizeof(op));
    close(sd);
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = pcap_lookupdev(errbuf);
    std::cout << "device: " << ((device != NULL) ? device : "NULL") << "\n";
    pcap_t* p = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

    return 0;
}
