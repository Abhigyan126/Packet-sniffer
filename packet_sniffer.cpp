#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <sstream>

#define BUFFER_SIZE 65536

std::map<int, std::string> protocol_names = {
    {IPPROTO_TCP, "TCP"},
    {IPPROTO_UDP, "UDP"},
    {IPPROTO_ICMP, "ICMP"},
    {IPPROTO_ICMPV6, "ICMPv6"},
    {IPPROTO_IP, "IP"},
    {IPPROTO_IPV6, "IPv6"}
};

void log_packet(const u_char *packet, ssize_t packet_len, std::ofstream &incoming_logfile, std::ofstream &outgoing_logfile, const std::string &local_ip, const std::string &local_ip6) {
    struct ether_header *eth = (struct ether_header *)packet;

    // Ethernet Header
    std::ostringstream oss;
    oss << "Ethernet Header:" << std::endl;
    oss << "   |-Source Address      : ";
    for(int i = 0; i < ETHER_ADDR_LEN; i++) oss << std::hex << (int)eth->ether_shost[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    oss << std::endl;
    oss << "   |-Destination Address : ";
    for(int i = 0; i < ETHER_ADDR_LEN; i++) oss << std::hex << (int)eth->ether_dhost[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    oss << std::endl;
    oss << "   |-Protocol            : " << std::hex << ntohs(eth->ether_type) << std::endl;

    bool is_incoming = false;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) { // If IPv4 packet
        struct ip *iph = (struct ip*)(packet + sizeof(struct ether_header));
        struct sockaddr_in src, dst;
        src.sin_addr = iph->ip_src;
        dst.sin_addr = iph->ip_dst;

        oss << "IP Header:" << std::endl;
        oss << "   |-Source IP           : " << inet_ntoa(src.sin_addr) << std::endl;
        oss << "   |-Destination IP      : " << inet_ntoa(dst.sin_addr) << std::endl;
        oss << "   |-Protocol            : " << protocol_names[iph->ip_p] << std::endl;

        is_incoming = (inet_ntoa(dst.sin_addr) == local_ip);
    } else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) { // If IPv6 packet
        struct ip6_hdr *ip6h = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6h->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst, INET6_ADDRSTRLEN);

        oss << "IPv6 Header:" << std::endl;
        oss << "   |-Source IP           : " << src << std::endl;
        oss << "   |-Destination IP      : " << dst << std::endl;
        oss << "   |-Protocol            : " << protocol_names[ip6h->ip6_nxt] << std::endl;

        is_incoming = (std::string(dst) == local_ip6);
    }

    std::string output = oss.str();
    if (is_incoming) {
        incoming_logfile << output;
    } else {
        outgoing_logfile << output;
    }
}

std::string get_local_ip() {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen("ipconfig getifaddr en0", "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    result.erase(result.find_last_not_of(" \n\r\t")+1); // Trim newline
    return result;
}

std::string get_local_ip6() {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen("ifconfig en0 | grep 'inet6 ' | awk '{print $2}'", "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    result.erase(result.find_last_not_of(" \n\r\t")+1); // Trim newline
    return result;
}

int main() {
    char interface[] = "en0"; // Change this to your interface name

    // Get local IP addresses
    std::string local_ip = get_local_ip();
    std::string local_ip6 = get_local_ip6();

    // Open BPF device
    int bpf = open("/dev/bpf0", O_RDWR);
    if (bpf < 0) {
        perror("open");
        return 1;
    }

    // Set buffer size
    int buffer_size = BUFFER_SIZE;
    if (ioctl(bpf, BIOCSBLEN, &buffer_size) < 0) {
        perror("BIOCSBLEN");
        close(bpf);
        return 1;
    }

    // Set interface to capture packets
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(bpf, BIOCSETIF, &ifr) < 0) {
        perror("BIOCSETIF");
        close(bpf);
        return 1;
    }

    // Enable immediate mode
    u_int opt = 1;
    if (ioctl(bpf, BIOCIMMEDIATE, &opt) < 0) {
        perror("BIOCIMMEDIATE");
        close(bpf);
        return 1;
    }

    // Allocate buffer
    char *buffer = new char[buffer_size];

    // Open log files
    std::ofstream incoming_logfile("incoming_packet_log.txt");
    std::ofstream outgoing_logfile("outgoing_packet_log.txt");
    if (!incoming_logfile.is_open() || !outgoing_logfile.is_open()) {
        perror("logfile");
        delete[] buffer;
        close(bpf);
        return 1;
    }

    while (true) {
        ssize_t packet_len = read(bpf, buffer, buffer_size);
        if (packet_len < 0) {
            perror("read");
            break;
        }

        log_packet((u_char *)buffer, packet_len, incoming_logfile, outgoing_logfile, local_ip, local_ip6);
    }

    delete[] buffer;
    close(bpf);
    incoming_logfile.close();
    outgoing_logfile.close();
    return 0;
}
