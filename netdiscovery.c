#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")

#define MAC_ADDRESS_LENGTH 6
#define MAX_COMMAND_LENGTH 100
#define HARD_CODED_ADDRESS "192.168.30.43"

typedef struct {
    IPAddr target;
    IPAddr src;
} THREAD_DATA;

//Arp Sweep Thread
DWORD WINAPI ArpSweepThread(LPVOID param) {
    unsigned int value = 1;

    BYTE mac_addr[6];
    char ipStr[INET_ADDRSTRLEN];
    ULONG length = MAC_ADDRESS_LENGTH;
    THREAD_DATA *data = (THREAD_DATA *)param;
    int res = SendARP(data->target, data->src, (PULONG) mac_addr, &length);

    if (res == NO_ERROR) {
        value = value ^ value;
        inet_ntop(AF_INET, &data->target, ipStr, INET_ADDRSTRLEN);
        printf("[+] Host trovato : %s\n", ipStr);
    }

    free(data);
    return value;
}


void ARP_sweep(const char *srcIP) {
    IPAddr *src;
    IPAddr *start_ip;
    THREAD_DATA *thread_data = malloc(sizeof(THREAD_DATA));

    inet_pton(AF_INET, srcIP, src);
    inet_pton(AF_INET, "192.168.30.0", start_ip);
    unsigned int current_host = ntohl(*start_ip);

    thread_data->src = *src;
    for(unsigned long i = 1; i < 254; i++) {
        IPAddr target = htonl(current_host + i);
        /*
        BYTE mac_addr[6];
        ULONG length = MAC_ADDRESS_LENGTH;
        int res = SendARP(target, *src, (PULONG) mac_addr, &length);
        */
        DWORD thread_ID = i;
        thread_data->target = target;
        HANDLE t = CreateThread(NULL, 0, ArpSweepThread, thread_data, 0, &thread_ID);

        //Print the address retrieved.
        /*
        if (res == NO_ERROR) {
            char ipStr[INET_ADDRSTRLEN];
            struct in_addr sa_in;
            sa_in.S_un.S_addr = target;
            inet_ntop(AF_INET, &sa_in, ipStr, INET_ADDRSTRLEN);
            printf("[+] Host trovato: %s\n", ipStr);
        }
        */


    }
}

void show_info(IP_ADAPTER_ADDRESSES *adapter) {
    char IPV4[16];

    while (adapter != NULL) {
        printf("Adapter Name: %s\n", adapter->AdapterName);
        wprintf(L"Description: %s\n", adapter->Description);

        //Skipping 0.0.0.0 address.
        PIP_ADAPTER_UNICAST_ADDRESS addressCursor = adapter->FirstUnicastAddress->Next;

        printf("IP address: ");
        while (addressCursor != NULL) {
            struct sockaddr_in *sa_in = (struct sockaddr_in *) addressCursor->Address.lpSockaddr;
            inet_ntop(AF_INET, &sa_in->sin_addr, IPV4, 16);
            printf("%s\n", IPV4);
            addressCursor = addressCursor->Next;
        }


        printf("MAC Address: ");
        for (int i = 0; i < adapter->PhysicalAddressLength; i++) {
            printf("%02X", adapter->PhysicalAddress[i]);
            if (i < adapter->PhysicalAddressLength - 1) {
                printf("-");
            }
        }
        printf("\n\n");
        adapter = adapter->Next;
    }
}


int main(int argc, char *argv[]) {
    
    IP_ADAPTER_ADDRESSES *adapterAddresses = NULL;
    IP_ADAPTER_ADDRESSES *adapterCursor = NULL;
    ULONG outBufLen = 15000; // Initial buffer size for adapter information.
    
    IPAddr local_ip;

    adapterAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
    if (adapterAddresses == NULL) {
        printf("Error allocating adapter buffer.\n");
        return 1;
    }

    ULONG adapterErrorCode = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapterAddresses, &outBufLen);

    // Checking if the adapter information was retrieved successfully.
    if (adapterErrorCode == ERROR_SUCCESS) {
        adapterCursor = adapterAddresses;
    } else {
        printf("Error retrieving adapter information: %lu\n", adapterErrorCode);
        free(adapterAddresses);
        return 1;
    }

    if (argc < 1) {
        printf("Work in progress...\n");
        return 0;
    } else {
        printf("%s", argv[1]);
        if (strcmp("-help", argv[1]) == 0) {

        }
        else if (strcmp("-showinterface", argv[1]) == 0)  show_info(adapterCursor);
        else if (strcmp("-arpsweep", argv[1]) == 0)       ARP_sweep(HARD_CODED_ADDRESS);
        else                                              printf("It's not a command...");
    }

    free(adapterAddresses);
    return 0;
}