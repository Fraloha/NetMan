#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdint.h>

#define MAC_ADDRESS_LENGTH 8
#define MAX_COMMAND_LENGTH 100
#define HARD_CODED_ADDRESS "192.168.30.43"
#define THREAD_WORKERS 32
#define MAX_HOST_SUBNET 256
#define OFFSET i + batch

typedef struct {
    IPAddr target;
    IPAddr src;
    BYTE mac[MAC_ADDRESS_LENGTH];
    BOOL found;
} RECORD_NETWORK_DATA;

RECORD_NETWORK_DATA info[MAX_HOST_SUBNET - 1];

void print_mac(BYTE *mac_address) {
    for (long unsigned int i = 0; i < MAC_ADDRESS_LENGTH; i++) {
            printf("%02X", (unsigned int) *(mac_address + i));
            if (i < MAC_ADDRESS_LENGTH - 1) {
                printf("-");
            }
    }
}

char* get_mac_string(BYTE *mac_address, size_t length) {

    if (length == 0)
        return "N/A";

    char *string = calloc(32, sizeof(char));
    char buffer[3];
    for (long unsigned int i = 0; i < length; i++) {
            sprintf(buffer, "%02X", (unsigned int) *(mac_address + i));
            strcat(string, buffer);
            if (i < length - 1) {
                //sprintf(string + i + 1, "-");
                strcat(string, "-");
            }
    }
    return string;
}



//Arp Sweep Thread
DWORD WINAPI ArpSweepThread(LPVOID param) {
    ULONG length = MAC_ADDRESS_LENGTH;
    RECORD_NETWORK_DATA *data = (RECORD_NETWORK_DATA *)param;

    int res = SendARP(data->target, data->src, data->mac, &length);

    if (res == NO_ERROR)  data->found = TRUE;
    else data->found = FALSE;

    return data->found;
}

void ARP_sweep_seq(const char *srcIP, int subnet_prefix) {
    IPAddr src;
    char ipStr[INET_ADDRSTRLEN]; 

    inet_pton(AF_INET, srcIP, &src);
    unsigned int subnet_mask = (0xFFFFFFFF << (32 - subnet_prefix)) & 0xFFFFFFFF;
    IPAddr start_ip = htonl(ntohl(src) & subnet_mask);
    unsigned int current_host = ntohl(start_ip);

    unsigned long total_hosts = (1 << (32 - subnet_prefix)) - 2;
    
    for(unsigned long i = 1; i <= total_hosts; i++) {
        IPAddr target = htonl(current_host + i);
        BYTE *mac_addr = malloc(sizeof(char) * MAC_ADDRESS_LENGTH);
        ULONG length = MAC_ADDRESS_LENGTH;

        int res = SendARP(target, src, (PULONG)mac_addr, &length);
        if (res == NO_ERROR) {
            inet_ntop(AF_INET, &target, ipStr, INET_ADDRSTRLEN);
            printf("Host : %s\t", ipStr);
            print_mac(mac_addr);
            printf("\n");
        }
        free(mac_addr);
    }
}

void ARP_sweep(const char *srcIP, int subnet_prefix) {
    IPAddr src;
    IPAddr start_ip;
    char ipStr[INET_ADDRSTRLEN];
    unsigned int subnet_mask = (0xFFFFFFFF << (32 - subnet_prefix)) & 0xFFFFFFFF;
    IPAddr start_ip = htonl(ntohl(src) & subnet_mask);

    inet_pton(AF_INET, srcIP, &src);
    unsigned int current_host = ntohl(start_ip);
    unsigned long total_hosts = (1 << (32 - subnet_prefix)) - 2;

    unsigned long thread_workers = 0;

    if (total_hosts < THREAD_WORKERS) thread_workers = total_hosts;
    else thread_workers = THREAD_WORKERS;

    for(unsigned long batch = 1; batch < total_hosts; batch+=thread_workers) {
        HANDLE *t = calloc(thread_workers, sizeof(HANDLE));
        for(unsigned long i = 0; i < thread_workers; i++) {
            IPAddr target = htonl(current_host + OFFSET);

            info[OFFSET].src = src;
            info[OFFSET].target = target;

            t[i] = CreateThread(NULL, 0, ArpSweepThread, &info[OFFSET], 0, NULL);
        }

        //Closing all the threads.
        for(int i = 0; i < thread_workers; i++) {

            if (t[i] == NULL)  continue;

            WaitForSingleObject(t[i], INFINITE);
            CloseHandle(t[i]);

            if (info[OFFSET].found == TRUE) {
                inet_ntop(AF_INET, &(info[OFFSET].target), ipStr, INET_ADDRSTRLEN);
                printf("Host : %s\t", ipStr);
                print_mac(info[OFFSET].mac);
                printf("\n");
            }
        }
    }
}

void show_info(IP_ADAPTER_ADDRESSES *adapter) {
    char IPV4[16];

    while (adapter != NULL) {
        printf("Adapter Name: %s\n", adapter->AdapterName);
        wprintf(L"Description: %ls\n", (wchar_t *)adapter->Description);

        
        PIP_ADAPTER_UNICAST_ADDRESS addressCursor = adapter->FirstUnicastAddress;
        if (addressCursor != NULL) //Skipping 0.0.0.0 address. addressCursor = addressCursor->Next;

        printf("IP address: ");
        while (addressCursor != NULL) {
            struct sockaddr_in *sa_in = (struct sockaddr_in *) addressCursor->Address.lpSockaddr;
            inet_ntop(AF_INET, &sa_in->sin_addr, IPV4, 16);
            printf("%s\n", IPV4);
            addressCursor = addressCursor->Next;
        }


        printf("MAC Address: ");
        print_mac(adapter->PhysicalAddress);
        printf("\n");
        printf("MAC Address: ");
        printf("%s\n", get_mac_string(adapter->PhysicalAddress, adapter->PhysicalAddressLength));
        
        printf("\n\n");
        adapter = adapter->Next;
    }
}

void print_help() {
    printf("Usage: netdiscovery [options]\n");
    printf("Options:\n");
    printf("  -h, --help                Show this help message and exit\n");
    printf("  -show-interfaces          Show information about network interfaces\n");
    printf("  -interface <IP_ADDRESS>   Specify the source IP address for ARP sweep\n");
    printf("  -arp-sweep                Perform an ARP sweep on the specified interface\n");
    printf("  -mt                       Use multi-threading for ARP sweep (optional)\n");
}

int main(int argc, char *argv[]) {
    
    IP_ADAPTER_ADDRESSES *adapterAddresses = NULL;
    IP_ADAPTER_ADDRESSES *adapterCursor = NULL;
    ULONG outBufLen = 15000; // Initial buffer size for adapter information.
    BOOL test = FALSE;
    const char *interfaceAddress = NULL;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Errore inizializzazione Winsock.\n");
        return 1;
    }

    adapterAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
    if (adapterAddresses == NULL) {
        printf("Error allocating adapter buffer.\n");
        return 1;
    }


    ULONG adapterErrorCode;
    do{

        adapterErrorCode = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapterAddresses, &outBufLen);

        if (adapterErrorCode == ERROR_BUFFER_OVERFLOW){
            adapterAddresses = (IP_ADAPTER_ADDRESSES *) realloc(adapterAddresses, outBufLen);
        }

    } while (adapterErrorCode != ERROR_SUCCESS);

    adapterCursor = adapterAddresses;

    if (argc == 1 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) print_help();
    else if (argc == 2 && strcmp(argv[1], "-show-interfaces") == 0) show_info(adapterCursor);
    else if (argc >= 3 && strcmp(argv[1], "-interface") == 0) {
        interfaceAddress = argv[2];
        int subnet_prefix = adapterCursor->FirstUnicastAddress->OnLinkPrefixLength; // Store the initial IP address for later use
        if (argc == 4 && strcmp(argv[3], "-arp-sweep") == 0)
            ARP_sweep_seq(interfaceAddress, subnet_prefix);
        else if (argc == 5 && strcmp(argv[3], "-arp-sweep") == 0 && strcmp(argv[4], "-mt") == 0)
            ARP_sweep(interfaceAddress, subnet_prefix);
    } else printf("Invalid command or option. Use -h or --help for usage information.\n");

    free(adapterAddresses);
    WSACleanup();
    return 0;
}