#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <chrono>
#include <thread>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <ctime>

using namespace std;

// Forward declarations
class Node;
class Queue;

// Node class containing packet info
class Node {
public:
    static int counter;
    int packetNO;
    time_t timestamp;
    ssize_t sizeOfPacket;
    unsigned char* data;
    string sourceIP;
    string destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    Node* next;
    Node* prev;

    Node(const unsigned char* packetData, ssize_t size) {
        packetNO = ++counter;
        data = new unsigned char[size];
        memcpy(data, packetData, size);
        sizeOfPacket = size;
        timestamp = time(nullptr);
        sourceIP = "";
        destIP = "";
        sourcePort = 0;
        destPort = 0;
        prev = nullptr;
        next = nullptr;
    }

    ~Node() {
        if (data) delete[] data;
    }

    void displayInfo() {
        cout << "-------------------------" << endl;
        cout << "Packet Number : " << packetNO << endl;
        cout << "Time Stamp : " << timestamp << endl;
        cout << "Size of packet : " << sizeOfPacket << " bytes ";
        cout << " Source IP : " << sourceIP;
        cout << " Destination IP : " << destIP << endl;
    }
};
int Node::counter = 0;

// Queue class to store packets
class Queue {
private:
    Node* start = nullptr;
    Node* top = nullptr;

public:
    bool isEmpty() {
        return start == nullptr;
    }

    void InQueue(Node* newnode) {
        if (isEmpty()) {
            start = top = newnode;
            start->next = nullptr;
            start->prev = nullptr;
        } else {
            newnode->prev = top;
            top->next = newnode;
            top = newnode;
            top->next = nullptr;
        }
    }

    Node* deQueue() {
        if (isEmpty()) return nullptr;
        Node* temp = start;
        if (start == top) {
            start = top = nullptr;
        } else {
            start = start->next;
            start->prev = nullptr;
        }
        return temp;
    }

    Node* traverseNext(bool reset = false) {
        static Node* tempStart = nullptr;
        if (reset || tempStart == nullptr) tempStart = start;
        if (isEmpty() || tempStart == nullptr) return nullptr;
        Node* current = tempStart;
        tempStart = tempStart->next;
        return current;
    }

    void displayPackets() {
        Node* curr = start;
        while (curr) {
            curr->displayInfo();
            curr = curr->next;
        }
    }

    ~Queue() {
        Node* curr = start;
        while (curr) {
            Node* temp = curr;
            curr = curr->next;
            delete temp;
        }
    }
};

// LayersStack and StringNodes
class StringNodes {
public:
    string layer;
    StringNodes* next;
    StringNodes* prev;
    StringNodes(string lyr = "") : layer(lyr), next(nullptr), prev(nullptr) {}
};

class LayersStack {
private:
    StringNodes* top = nullptr;

public:
    bool isempty() {
        return top == nullptr;
    }

    void add(const string& layer) {
        StringNodes* newnode = new StringNodes(layer);
        if (top == nullptr) {
            top = newnode;
        } else {
            newnode->prev = top;
            top->next = newnode;
            top = newnode;
        }
    }

    string remove() {
        if (isempty()) return "-1";
        string layer = top->layer;
        StringNodes* temp = top;
        top = top->prev;
        if (top) top->next = nullptr;
        delete temp;
        return layer;
    }

    void displayStack() {
        StringNodes* temp = top;
        cout << "<--- Layers Dissected For this Packet --->\n";
        while (temp) {
            cout <<"-->" << temp->layer << "\n";
            temp = temp->prev;
        }
    }

    ~LayersStack() {
        while (top) {
            StringNodes* temp = top;
            top = top->prev;
            delete temp;
        }
    }
};

// PacketCapture class
class PacketCapture {
public:
    int rawSocket;
    string interfaceName;
    bool isSocketOpen;

    PacketCapture(const string& intfName) : interfaceName(intfName), rawSocket(-1), isSocketOpen(false) {}

    bool OpenSocket() {
        rawSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rawSocket < 0) {
            perror("Socket Creation Failed");
            return false;
        }
        isSocketOpen = true;
        return true;
    }

    bool connectToInterface() {
        if (!isSocketOpen) return false;
        struct ifreq ifr {};
        strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
        if (ioctl(rawSocket, SIOCGIFINDEX, &ifr) < 0) {
            perror("Interface Index Error");
            return false;
        }
        struct sockaddr_ll saddrll {};
        saddrll.sll_family = AF_PACKET;
        saddrll.sll_protocol = htons(ETH_P_ALL);
        saddrll.sll_ifindex = ifr.ifr_ifindex;
        if (bind(rawSocket, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0) {
            perror("Bind Error");
            return false;
        }
        cout << "[+] Bound to interface: " << interfaceName << endl;
        return true;
    }

    void startCapture(Queue& PacketQueue, int duration = 60) {
        if (!isSocketOpen) return;
        cout << "[*] Starting packet capture for " << duration << " seconds...\n";
        unsigned char buffer[65536];
        struct sockaddr saddr {};
        socklen_t saddrLen = sizeof(saddr);
        auto startTime = chrono::steady_clock::now();
        int packetCount = 0;

        while (chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - startTime).count() < duration) {
            ssize_t packetSize = recvfrom(rawSocket, buffer, sizeof(buffer), 0, &saddr, &saddrLen);
            if (packetSize < 0) break;
            Node* newnode = new Node(buffer, packetSize);
            PacketQueue.InQueue(newnode);
            packetCount++;
            cout << "[Packet Received] Packet ID: " << newnode->packetNO << " | Size: " << packetSize << " bytes\n";
        }
        cout << "[*] Capture finished. Total packets: " << packetCount << endl;
    }

    void CloseSocket() {
        if (isSocketOpen) {
            ::close(rawSocket);
            isSocketOpen = false;
            cout << "[+] Socket closed successfully.\n";
        }
    }

    ~PacketCapture() { CloseSocket(); }
};



class packetDissection {
private:
    LayersStack newStack;

public:
    void dissectPacket(unsigned char* buffer, ssize_t size, Node* node) {
        if (!buffer || size <= 0) return;
        cout << "Starting dissection of Packet Number : " << node->packetNO << "\n";
        newStack.add("Ethernet");
        parseEthernet(buffer, size, node);
        cout << "Dissection complete for Packet Number : " << node->packetNO << "\n";
    }

private:
    void parseEthernet(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct ether_header)) return;
        struct ether_header* eth = (struct ether_header*)buffer;
        uint16_t etherType = ntohs(eth->ether_type);

        if (etherType == ETHERTYPE_IP) {
            newStack.add("IPv4");
            parseIPv4(buffer + sizeof(struct ether_header), size - sizeof(struct ether_header), node);
        } else if (etherType == ETHERTYPE_IPV6) {
            newStack.add("IPv6");
            parseIPv6(buffer + sizeof(struct ether_header), size - sizeof(struct ether_header), node);
        } else if (etherType == ETHERTYPE_ARP) {
            newStack.add("ARP");
        } else {
            newStack.add("Other");
        }
    }

    void parseIPv4(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct iphdr)) return;
        struct iphdr* ip = (struct iphdr*)buffer;
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;
        node->sourceIP = string(inet_ntoa(src));
        node->destIP = string(inet_ntoa(dst));

        if (ip->protocol == IPPROTO_TCP) {
            newStack.add("TCP");
            parseTCP(buffer + ip->ihl * 4, size - ip->ihl * 4, node);
        } else if (ip->protocol == IPPROTO_UDP) {
            newStack.add("UDP");
            parseUDP(buffer + ip->ihl * 4, size - ip->ihl * 4, node);
        } else {
            newStack.add("OtherTransport");
        }
    }

    void parseIPv6(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct ip6_hdr)) return;
        struct ip6_hdr* ip6 = (struct ip6_hdr*)buffer;
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
        node->sourceIP = string(src);
        node->destIP = string(dst);
        newStack.add("IPv6Transport");
    }

    void parseTCP(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct tcphdr)) return;
        struct tcphdr* tcp = (struct tcphdr*)buffer;
        node->sourcePort = ntohs(tcp->source);
        node->destPort = ntohs(tcp->dest);
        newStack.add("TCPPorts");
    }

    void parseUDP(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct udphdr)) return;
        struct udphdr* udp = (struct udphdr*)buffer;
        node->sourcePort = ntohs(udp->source);
        node->destPort = ntohs(udp->dest);
        newStack.add("UDPPorts");
    }

public:
    void displayDissection() { newStack.displayStack(); }

    
};


//Filter class which is responsible for filtering , replayin and error handling
class Filter {
private:
    Queue* replayQueue;
    Queue* failedQueue;
    const int maxRetries = 2;
    const int maxsize = 1500;
    int FailedPackets = 0;

public:
    Filter() {
        replayQueue = new Queue();
        failedQueue = new Queue();
    }

    void filterPackets(Queue &packetQueue, const string& srcIP, const string& destIP) {
        cout << "Filtering on the basis of the source IP and destination IP...\n";

        Node* node = packetQueue.traverseNext(true);
        while (node != nullptr) {
            if (node->sizeOfPacket > maxsize) {
                ++FailedPackets;
                cout << "Packet size greater than 1500 bytes, sending to failed queue.\n";
                failedQueue->InQueue(node);
            }
            else if (node->sourceIP == srcIP && node->destIP == destIP) {
                replayQueue->InQueue(node);
            }
            node = packetQueue.traverseNext();
        }

        cout << "Filtering complete. Packets added to Replay. Total failed packets: " << FailedPackets << "\n";
    }

    void replayPackets(int rawSocket, struct sockaddr* destAddr, socklen_t addrLen) {
        Node* node = replayQueue->deQueue();
        while (node != nullptr) {
            bool success = false;
            int retries = 0;

            int delayMs = node->sizeOfPacket / 1000;
            cout << "Replaying Packet ID " << node->packetNO<< " | Estimated delay: " << delayMs << " ms\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));

            while (!success && retries < maxRetries) {
                ssize_t sentBytes = sendto(rawSocket, node->data, node->sizeOfPacket, 0, destAddr, addrLen);
                if (sentBytes == node->sizeOfPacket) {
                    success = true;
                    cout << "[+] Packet replayed successfully\n";
                }
                else {
                    ++retries;
                    cout << "[!] Replay failed, retry " << retries << "\n";
                }
            }

            if (!success) {
                failedQueue->InQueue(node);
                cout << "[!] Packet moved to failed queue after retries\n";
            }

            node = replayQueue->deQueue();
        }
    }

    void displayFiltered() { replayQueue->displayPackets(); }
    void displayFailed() { failedQueue->displayPackets(); }


~Filter() {
    delete replayQueue;
    delete failedQueue;
}

};



    




int main() {
    string interfaceName;
    cout << "Enter network interface to capture packets (e.g., eth0): ";
    cin >> interfaceName;

    PacketCapture pc(interfaceName);
    if (!pc.OpenSocket()) return -1;
    if (!pc.connectToInterface()) return -1;

    Queue packetQueue;
    packetDissection dissector;
    Filter filter;

    struct sockaddr_ll destAddr {};
    socklen_t addrLen = sizeof(destAddr); // used for replay (can customize later if sending to specific interface)

    int choice;
    bool exitProgram = false;

    while (!exitProgram) {
        cout << "\n--- Packet Sniffer Menu ---\n";
        cout << "1. Capture packets\n";
        cout << "2. Dissect all captured packets\n";
        cout << "3. Display all captured packets\n";
        cout << "4. Filter packets by source/destination IP\n";
        cout << "5. Display filtered packets\n";
        cout << "6. Replay filtered packets\n";
        cout << "7. Display failed packets\n";
        cout << "8. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1: {
            
                cout << "---- 60 seconds capturing ----- ";
                pc.startCapture(packetQueue);
                break;
            }
            case 2: {
                Node* node = packetQueue.traverseNext(true);
                while (node != nullptr) {
                    dissector.dissectPacket(node->data, node->sizeOfPacket, node);
                    dissector.displayDissection();
                    node = packetQueue.traverseNext();
                    
                }
                break;
            }
            case 3: {
                cout << "[*] Displaying all captured packets:\n";
                packetQueue.displayPackets();
                break;
            }
            case 4: {
                string srcIP, destIP;
                cout << "Enter Source IP to filter: ";
                cin >> srcIP;
                cout << "Enter Destination IP to filter: ";
                cin >> destIP;
                filter.filterPackets(packetQueue, srcIP, destIP);
                break;
            }
            case 5: {
                cout << "[*] Displaying filtered packets:\n";
                filter.displayFiltered();
                break;
            }
            case 6: {
                cout << "[*] Replaying filtered packets...\n";
                filter.replayPackets(pc.rawSocket, (struct sockaddr*)&destAddr, addrLen);
                break;
            }
            case 7: {
                cout << "[*] Displaying failed packets:\n";
                filter.displayFailed();
                break;
            }
            case 8:
                exitProgram = true;
                break;
            default:
                cout << "Invalid choice. Try again.\n";
        }
    }

    pc.CloseSocket();
    cout << "[+] Exiting program.\n";
    return 0;
}