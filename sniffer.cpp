#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <ctime>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// ── Port map ──────────────────────────────────────────────────────────────────
std::unordered_map<int, std::string> portMap;

void loadServices(const std::string& path = "C:\\Windows\\System32\\drivers\\etc\\services") {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[WARN] Could not open services file: " << path << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string name, portProto;
        if (!(iss >> name >> portProto)) continue;
        size_t slash = portProto.find('/');
        if (slash == std::string::npos) continue;
        try {
            int port = std::stoi(portProto.substr(0, slash));
            if (portMap.find(port) == portMap.end())
                portMap[port] = name;
        } catch (...) { continue; }
    }
    std::cout << "[INFO] Loaded " << portMap.size() << " service entries." << std::endl;
}

std::string getServiceName(unsigned short port_netorder) {
    int port = ntohs(port_netorder);
    auto it = portMap.find(port);
    if (it != portMap.end()) return it->second;
    switch (port) {
        case 80:    return "http";
        case 443:   return "https";
        case 53:    return "dns";
        case 22:    return "ssh";
        case 21:    return "ftp";
        case 20:    return "ftp-data";
        case 25:    return "smtp";
        case 587:   return "smtp";
        case 110:   return "pop3";
        case 143:   return "imap";
        case 993:   return "imaps";
        case 995:   return "pop3s";
        case 3306:  return "mysql";
        case 5432:  return "postgresql";
        case 8080:  return "http-alt";
        case 8443:  return "https-alt";
        case 67:    return "dhcp";
        case 68:    return "dhcp";
        case 123:   return "ntp";
        case 3389:  return "rdp";
        case 5900:  return "vnc";
        case 6379:  return "redis";
        case 27017: return "mongodb";
        default:    return std::to_string(port);
    }
}

std::string resolveService(unsigned short src_net, unsigned short dst_net) {
    int srcPort = ntohs(src_net);
    int dstPort = ntohs(dst_net);
    bool srcKnown = (srcPort < 1024) || (portMap.count(srcPort) > 0);
    bool dstKnown = (dstPort < 1024) || (portMap.count(dstPort) > 0);
    if (dstKnown) return getServiceName(dst_net);
    if (srcKnown) return getServiceName(src_net);
    return std::to_string(dstPort);
}

// ── Headers ───────────────────────────────────────────────────────────────────
struct EthernetHeader {
    unsigned char  dest[6];
    unsigned char  src[6];
    unsigned short type;
};

struct IPHeader {
    unsigned char  iph_ihl:4, iph_ver:4;
    unsigned char  iph_tos;
    unsigned short iph_len;
    unsigned short iph_id;
    unsigned short iph_offset;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short iph_chksum;
    struct in_addr iph_src;
    struct in_addr iph_dest;
};

struct TCPHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned int   seq_num;
    unsigned int   ack_num;
    unsigned short res1:4, doff:4, flags:6, res2:2;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

struct UDPHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
};

// ── Helpers ───────────────────────────────────────────────────────────────────
std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

std::string macToStr(const unsigned char mac[6]) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string hexWord(unsigned short val) {
    char buf[7];
    snprintf(buf, sizeof(buf), "0x%04x", val);
    return std::string(buf);
}

// ── logPacket — now carries all header fields ─────────────────────────────────
struct EthInfo {
    std::string src_mac;
    std::string dst_mac;
};

struct IPInfo {
    unsigned char  ver;
    unsigned char  ihl;
    unsigned char  tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short offset;    // raw field (flags + frag offset)
    unsigned char  ttl;
    unsigned short checksum;
};

struct TCPInfo {
    unsigned int   seq;
    unsigned int   ack;
    unsigned short flags;     // raw 6-bit flags field
    unsigned char  data_offset;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

struct UDPInfo {
    unsigned short length;
    unsigned short checksum;
};

struct ICMPInfo {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
};

void logPacket(
    const EthInfo&  eth,
    const IPInfo&   ip,
    const std::string& src_ip,
    const std::string& dst_ip,
    const std::string& protocol,
    const std::string& src_port,
    const std::string& dst_port,
    const std::string& service,
    int size,
    const unsigned char* payload, int payload_len,
    const TCPInfo*  tcp  = nullptr,
    const UDPInfo*  udp  = nullptr,
    const ICMPInfo* icmp = nullptr)
{
    // Payload → hex string (capped at 256 bytes)
    std::string hex_payload;
    if (payload && payload_len > 0) {
        std::ostringstream hex;
        int cap = std::min(payload_len, 256);
        for (int i = 0; i < cap; i++) {
            hex << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i];
            if (i < cap - 1) hex << " ";
        }
        hex_payload = hex.str();
    }

    time_t now = time(0);
    char ts[20];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

    // IP flags breakdown
    unsigned short ip_flags  = (ntohs(ip.offset) >> 13) & 0x7;
    unsigned short ip_frag   =  ntohs(ip.offset) & 0x1FFF;
    bool flag_df = (ip_flags >> 1) & 1;
    bool flag_mf = (ip_flags)      & 1;

    std::ofstream file("packets.json", std::ios::app);
    file << "{"

         // ── timestamp ──
         << "\"time\":\""       << ts                         << "\","

         // ── Ethernet ──
         << "\"eth_src\":\""    << eth.src_mac                << "\","
         << "\"eth_dst\":\""    << eth.dst_mac                << "\","

         // ── IP ──
         << "\"src_ip\":\""     << jsonEscape(src_ip)         << "\","
         << "\"dst_ip\":\""     << jsonEscape(dst_ip)         << "\","
         << "\"ip_ver\":"       << (int)ip.ver                << ","
         << "\"ip_ihl\":"       << (int)ip.ihl                << ","
         << "\"ip_ihl_bytes\":" << (int)(ip.ihl * 4)          << ","
         << "\"ip_tos\":"       << (int)ip.tos                << ","
         << "\"ip_total_len\":" << ntohs(ip.total_len)        << ","
         << "\"ip_id\":\""      << hexWord(ntohs(ip.id))      << "\","
         << "\"ip_flag_df\":"   << (flag_df ? "true" : "false") << ","
         << "\"ip_flag_mf\":"   << (flag_mf ? "true" : "false") << ","
         << "\"ip_frag_off\":"  << ip_frag                    << ","
         << "\"ip_ttl\":"       << (int)ip.ttl                << ","
         << "\"ip_checksum\":\"" << hexWord(ntohs(ip.checksum)) << "\","

         // ── protocol / ports / service ──
         << "\"protocol\":\""   << protocol                   << "\","
         << "\"src_port\":\""   << jsonEscape(src_port)       << "\","
         << "\"dst_port\":\""   << jsonEscape(dst_port)       << "\","
         << "\"service\":\""    << jsonEscape(service)        << "\","
         << "\"size\":"         << size                       << ",";

    // ── TCP fields ──
    if (tcp) {
        unsigned short f = tcp->flags;
        file << "\"tcp_seq\":"       << ntohl(tcp->seq)             << ","
             << "\"tcp_ack\":"       << ntohl(tcp->ack)             << ","
             << "\"tcp_doff\":"      << (int)tcp->data_offset       << ","
             << "\"tcp_doff_bytes\":" << (int)(tcp->data_offset * 4) << ","
             << "\"tcp_window\":"    << ntohs(tcp->window)          << ","
             << "\"tcp_checksum\":\"" << hexWord(ntohs(tcp->checksum)) << "\","
             << "\"tcp_urg_ptr\":"   << ntohs(tcp->urgent_ptr)      << ","
             << "\"tcp_flag_urg\":"  << ((f & 0x20) ? "true":"false") << ","
             << "\"tcp_flag_ack\":"  << ((f & 0x10) ? "true":"false") << ","
             << "\"tcp_flag_psh\":"  << ((f & 0x08) ? "true":"false") << ","
             << "\"tcp_flag_rst\":"  << ((f & 0x04) ? "true":"false") << ","
             << "\"tcp_flag_syn\":"  << ((f & 0x02) ? "true":"false") << ","
             << "\"tcp_flag_fin\":"  << ((f & 0x01) ? "true":"false") << ",";
    }

    // ── UDP fields ──
    if (udp) {
        file << "\"udp_length\":"    << ntohs(udp->length)             << ","
             << "\"udp_checksum\":\"" << hexWord(ntohs(udp->checksum)) << "\",";
    }

    // ── ICMP fields ──
    if (icmp) {
        file << "\"icmp_type\":"     << (int)icmp->type                  << ","
             << "\"icmp_code\":"     << (int)icmp->code                  << ","
             << "\"icmp_checksum\":\"" << hexWord(ntohs(icmp->checksum)) << "\",";
    }

    // ── payload ──
    file << "\"payload_len\":"  << payload_len                      << ","
         << "\"payload\":\""    << jsonEscape(hex_payload)          << "\""
         << "}\n";

    file.flush();
}

// ── Packet handler ────────────────────────────────────────────────────────────
void packet_handler(unsigned char* /*param*/,
                    const struct pcap_pkthdr* header,
                    const unsigned char* pkt_data) {

    static int packet_count = 0;

    if (header->len < 14) return;
    EthernetHeader* eth = (EthernetHeader*)pkt_data;
    if (ntohs(eth->type) != 0x0800) return;

    EthInfo ethInfo;
    ethInfo.src_mac = macToStr(eth->src);
    ethInfo.dst_mac = macToStr(eth->dest);

    IPHeader* iph = (IPHeader*)(pkt_data + 14);
    int ip_header_len = iph->iph_ihl * 4;
    if (ip_header_len < 20) return;

    IPInfo ipInfo;
    ipInfo.ver       = iph->iph_ver;
    ipInfo.ihl       = iph->iph_ihl;
    ipInfo.tos       = iph->iph_tos;
    ipInfo.total_len = iph->iph_len;
    ipInfo.id        = iph->iph_id;
    ipInfo.offset    = iph->iph_offset;
    ipInfo.ttl       = iph->iph_ttl;
    ipInfo.checksum  = iph->iph_chksum;

    std::string src_ip  = inet_ntoa(iph->iph_src);
    std::string dst_ip  = inet_ntoa(iph->iph_dest);
    int         pkt_size = header->len;

    // ── TCP ──
    if (iph->iph_protocol == 6) {
        if (header->len < (unsigned)(14 + ip_header_len + 20)) return;
        TCPHeader* tcph = (TCPHeader*)(pkt_data + 14 + ip_header_len);
        int tcp_header_len = tcph->doff * 4;

        TCPInfo tcpInfo;
        tcpInfo.seq         = tcph->seq_num;
        tcpInfo.ack         = tcph->ack_num;
        tcpInfo.flags       = tcph->flags;
        tcpInfo.data_offset = tcph->doff;
        tcpInfo.window      = tcph->window;
        tcpInfo.checksum    = tcph->checksum;
        tcpInfo.urgent_ptr  = tcph->urgent_ptr;

        int total_headers_len = 14 + ip_header_len + tcp_header_len;
        int payload_len       = (int)header->len - total_headers_len;
        if (payload_len < 0) payload_len = 0;
        const unsigned char* payload = (payload_len > 0) ? (pkt_data + total_headers_len) : nullptr;

        std::string src_port = std::to_string(ntohs(tcph->src_port));
        std::string dst_port = std::to_string(ntohs(tcph->dest_port));
        std::string service  = resolveService(tcph->src_port, tcph->dest_port);

        std::cout << "\n[" << ++packet_count << "] TCP  "
                  << src_ip << ":" << src_port
                  << " -> " << dst_ip << ":" << dst_port
                  << "  service=" << service
                  << "  size=" << pkt_size << "B";

        logPacket(ethInfo, ipInfo, src_ip, dst_ip, "TCP",
                  src_port, dst_port, service, pkt_size,
                  payload, payload_len, &tcpInfo, nullptr, nullptr);
    }
    // ── UDP ──
    else if (iph->iph_protocol == 17) {
        if (header->len < (unsigned)(14 + ip_header_len + 8)) return;
        UDPHeader* udph = (UDPHeader*)(pkt_data + 14 + ip_header_len);

        UDPInfo udpInfo;
        udpInfo.length   = udph->length;
        udpInfo.checksum = udph->checksum;

        int total_headers_len = 14 + ip_header_len + 8;
        int payload_len       = (int)header->len - total_headers_len;
        if (payload_len < 0) payload_len = 0;
        const unsigned char* payload = (payload_len > 0) ? (pkt_data + total_headers_len) : nullptr;

        std::string src_port = std::to_string(ntohs(udph->src_port));
        std::string dst_port = std::to_string(ntohs(udph->dest_port));
        std::string service  = resolveService(udph->src_port, udph->dest_port);

        std::cout << "\n[" << ++packet_count << "] UDP  "
                  << src_ip << ":" << src_port
                  << " -> " << dst_ip << ":" << dst_port
                  << "  service=" << service
                  << "  size=" << pkt_size << "B";

        logPacket(ethInfo, ipInfo, src_ip, dst_ip, "UDP",
                  src_port, dst_port, service, pkt_size,
                  payload, payload_len, nullptr, &udpInfo, nullptr);
    }
    // ── ICMP ──
    else if (iph->iph_protocol == 1) {
        ICMPInfo icmpInfo = {0, 0, 0};
        if (header->len >= (unsigned)(14 + ip_header_len + 4)) {
            const unsigned char* icmp_ptr = pkt_data + 14 + ip_header_len;
            icmpInfo.type     = icmp_ptr[0];
            icmpInfo.code     = icmp_ptr[1];
            icmpInfo.checksum = (icmp_ptr[2] << 8) | icmp_ptr[3];
        }

        std::cout << "\n[" << ++packet_count << "] ICMP "
                  << src_ip << " -> " << dst_ip
                  << "  type=" << (int)icmpInfo.type
                  << "  size=" << pkt_size << "B";

        logPacket(ethInfo, ipInfo, src_ip, dst_ip, "ICMP",
                  "-", "-", "icmp", pkt_size,
                  nullptr, 0, nullptr, nullptr, &icmpInfo);
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    loadServices();

    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        std::cerr << "Error: " << errbuf << std::endl;
        return 1;
    }

    // --list mode: print numbered interface list and exit
    if (argc >= 2 && std::string(argv[1]) == "--list") {
        int i = 0;
        for (d = alldevs; d; d = d->next)
            std::cout << ++i << ". " << (d->description ? d->description : d->name) << std::endl;
        pcap_freealldevs(alldevs);
        return 0;
    }

    int inum = 0;
    if (argc >= 2) {
        inum = std::atoi(argv[1]);
    } else {
        int i = 0;
        for (d = alldevs; d; d = d->next)
            std::cout << ++i << ". " << (d->description ? d->description : d->name) << std::endl;
        std::cout << "\nEnter Interface (1-" << i << "): ";
        std::cin >> inum;
    }

    int i = 0;
    for (d = alldevs; d; d = d->next)
        if (++i == inum) break;

    if (!d) {
        std::cerr << "Invalid interface number." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_t* adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, -1, NULL, errbuf);
    if (!adhandle) {
        std::cerr << "Unable to open adapter: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    std::cout << "\n--- Sniffing on: " << (d->description ? d->description : d->name) << " ---\n";
    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}
