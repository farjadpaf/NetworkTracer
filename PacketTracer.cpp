#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>

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
    Node* traversePtr = nullptr; 

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
        if (reset) traversePtr = start;
        if (!traversePtr) return nullptr;
        Node* current = traversePtr;
        traversePtr = traversePtr->next;
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
            cout << "--"<<temp->layer << "\n";
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
class PacketCapture{

public:
int rawSocket ; // used to identify the socket connection
string interfaceName ; //Name of the internet interface
bool isSocketOPen; //to see if the socket is open

public:
        PacketCapture(const string& intfName ): interfaceName(intfName) , rawSocket(-1) , isSocketOPen(false) 
        {} 
        
    // create a raw Socket 
    bool OpenSocket(){
        rawSocket = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
        if(rawSocket<0){
            perror("Socket Creation Failed");
            return false;
        }isSocketOPen = true ;
        return true ;
    }
    //bind to interface 
    bool connectToInterface(){
        if(!isSocketOPen) return false ;

        struct ifreq ifr {} ;   //interface required struct 
        strncpy(ifr.ifr_name , interfaceName.c_str(), IFNAMSIZ -1 ) ; //copying interface name into the struct object

        if (ioctl(rawSocket , SIOCGIFINDEX , &ifr)<0){//getting the index of the Interfacename and adding it to the .ifrindex of the ifr
            perror("Interface Index Error ") ;
            return false ;
        }

        struct  sockaddr_ll saddrll {} ;

        saddrll.sll_family = AF_PACKET ;
        saddrll.sll_protocol = htons(ETH_P_ALL);
        saddrll.sll_ifindex = ifr.ifr_ifindex ;

       
    //Binding socket to the given interface
        if (bind(rawSocket, (struct sockaddr*)&saddrll, sizeof(saddrll)) < 0) {
            perror("Bind Error");
            return false;
        }

        cout << "[+] Bound to interface: " << interfaceName << endl;
        return true;
    }

    

    // start capturing packets
void startCapture(Queue& PacketQueue) {
    if (!isSocketOPen) {
        cerr << "[-] Socket is not open!" << endl;
        return;
    }

    cout << " Starting continuous packet capturing for 60 seconds...\n";

    unsigned char buffer[65536];
    struct sockaddr saddr {};
    socklen_t saddrLen = sizeof(saddr);

    // Record the start time using chrono
    auto startTime = chrono::steady_clock::now();
    int packetCount = 0;

    while (chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - startTime).count() <60) {
        ssize_t packetSize = recvfrom(rawSocket, buffer, sizeof(buffer), 0, &saddr, &saddrLen);
        if (packetSize < 0) {
            perror("Packet Receive Failed");
            break;
        }

        Node* newnode = new Node(buffer, packetSize);
        PacketQueue.InQueue(newnode);
        packetCount++;

        cout << "[Packet Received] Packet ID : " << newnode->packetNO
             << " | Size: " << packetSize << " bytes\n";
    }

    cout << "[*] 60-second capture finished. Total packets captured: " << packetCount << endl;


}




    //  Close the socket safely
    void CloseSocket() {
        if (isSocketOPen) {
            close(rawSocket);
            isSocketOPen = false;
            cout << " Socket closed successfully.\n";
        }
    }

    //  Destructor to ensure cleanup
    ~PacketCapture() {
        CloseSocket();
    } };



//Packet dissection class to convert the packet data into useful info and save the layers into the stack
class packetDissection {
private:
    LayersStack newStack;

public:
    void dissectPacket(unsigned char* buffer, ssize_t size, Node* node) {
        if (!buffer || size <= 0) return;

        cout << "Starting dissection of Packet Number : " << node->packetNO<< "\n";
        newStack.add("Ethernet");
        parseEthernet(buffer, size, node);
        cout << "Dissection complete for Packet Number : " << node->packetNO << "\n";
    }

private:
    void parseEthernet(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct ether_header)) {
            cerr << "Ethernet header too small for a ethernet header \n";
            return;
        }

        struct ether_header* eth = (struct ether_header*)buffer;
        uint16_t etherType = ntohs(eth->ether_type);
        cout<<"<---------------------------------->\n";
        cout << "Layer: Ethernet\n";
        cout << "  Source MAC Address : ";
        for (int i = 0; i < 6; i++) {
            printf("%02X", eth->ether_shost[i]);
            if (i < 5) cout << ":";
        }
        cout << "\n  Destination MAC Address : ";
        for (int i = 0; i < 6; i++) {
            printf("%02X", eth->ether_dhost[i]);
            if (i < 5) cout << ":";
        }
        cout << "\n  EtherType: 0x" << hex << etherType << dec << "\n";

        if (etherType == ETHERTYPE_IP) {
            newStack.add("IPv4");
            parseIPv4(buffer + sizeof(struct ether_header), size - sizeof(struct ether_header), node);
        }
        else if (etherType == ETHERTYPE_IPV6) {
            newStack.add("IPv6");
            parseIPv6(buffer + sizeof(struct ether_header), size - sizeof(struct ether_header), node);
        }
        else {
            cout << "  [!] Unknown or unsupported EtherType\n";
        }
    }

    //parsing ipv4
    void parseIPv4(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct iphdr)) {
            cerr << "IPv4 header too small for a ipv4 header \n";
            return;
        }

        struct iphdr* ip = (struct iphdr*)buffer;
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;

        node->sourceIP = inet_ntoa(src);
        node->destIP = inet_ntoa(dst);

        cout << "Layer: IPv4\n";
        cout << "  Source IP: " << node->sourceIP << "\n";
        cout << "  Destination IP: " << node->destIP << "\n";
        cout << "  Protocol: " << (int)ip->protocol << "\n";

        int ipHeaderLength = ip->ihl * 4;

        if (ip->protocol == IPPROTO_TCP) {
            newStack.add("TCP");
            parseTCP(buffer + ipHeaderLength, size - ipHeaderLength, node);
        }
        else if (ip->protocol == IPPROTO_UDP) {
            newStack.add("UDP");
            parseUDP(buffer + ipHeaderLength, size - ipHeaderLength, node);
        }
    }
    //parsing ipv6

    void parseIPv6(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct ip6_hdr)) {
            cerr << "IPv6 header too small for a ippv6 header\n";
            return;
        }

        struct ip6_hdr* ip6 = (struct ip6_hdr*)buffer;
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

        node->sourceIP = string(src);
        node->destIP = string(dst);

        cout << "Layer: IPv6\n";
        cout << "  Source IP: " << node->sourceIP << "\n";
        cout << "  Destination IP: " << node->destIP << "\n";
        cout << "  Next Header: " << (int)ip6->ip6_nxt << "\n";

        if (ip6->ip6_nxt == IPPROTO_TCP) {
            newStack.add("TCP");
            parseTCP(buffer + sizeof(struct ip6_hdr), size - sizeof(struct ip6_hdr), node);
        }
        else if (ip6->ip6_nxt == IPPROTO_UDP) {
            newStack.add("UDP");
            parseUDP(buffer + sizeof(struct ip6_hdr), size - sizeof(struct ip6_hdr), node);
        }
    }
    //parsing tcp
    void parseTCP(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct tcphdr)) {
            cerr << "TCP header too small for a tcp header\n";
            return;
        }

        struct tcphdr* tcp = (struct tcphdr*)buffer;
        node->sourcePort = ntohs(tcp->source);
        node->destPort = ntohs(tcp->dest);

        cout << "Layer: TCP\n";
        cout << "  Source Port: " << node->sourcePort << "\n";
        cout << "  Destination Port: " << node->destPort << "\n";
        cout << "  Sequence Number: " << ntohl(tcp->seq) << "\n";
    }
    //parsing udp
    void parseUDP(unsigned char* buffer, ssize_t size, Node* node) {
        if (size < sizeof(struct udphdr)) {
            cerr << "UDP header too small for a udp header\n";
            return;
        }

        struct udphdr* udp = (struct udphdr*)buffer;
        node->sourcePort = ntohs(udp->source);
        node->destPort = ntohs(udp->dest);

        cout << "Layer: UDP\n";
        cout << "  Source Port: " << node->sourcePort << "\n";
        cout << "  Destination Port: " << node->destPort << "\n";
        cout << "  Length: " << ntohs(udp->len) << "\n";
    }
public:
    //displaying layers
    void displayLayers() {
        cout << "\n[+] Packet Layers (Top Layer  → Bottom Layer):\n";
        newStack.displayStack();
    }
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
    cout << "Enter network interface to capture packets (e.g., lo): ";
    cin >> interfaceName;

    PacketCapture pc(interfaceName);
    if (!pc.OpenSocket()) return -1;
    if (!pc.connectToInterface()) return -1;

    Queue packetQueue;
    packetDissection dissector;
    Filter filter;

    struct sockaddr_ll destAddr {};
    socklen_t addrLen = sizeof(destAddr); // used for replay 

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
                
    
                pc.startCapture(packetQueue);
                break;
            }
            case 2: {
                Node* node = packetQueue.traverseNext(true);
                while (node != nullptr) {
                    dissector.dissectPacket(node->data, node->sizeOfPacket, node);
                    dissector.displayLayers();
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
