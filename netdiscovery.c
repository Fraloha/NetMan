#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#define MAC_ADDRESS_LENGTH 6
#define MAX_COMMAND_LENGTH 100
#define HARD_CODED_ADDRESS "192.168.30.43"
#define THREAD_WORKERS 255

typedef struct {
    IPAddr target;
    IPAddr src;
} THREAD_DATA;

typedef struct {
    BYTE *mac;
    IPAddr ip;
    unsigned int result;
} NETWORK_INFO;


void print_mac(BYTE *mac_address) {
    for (long unsigned int i = 0; i < MAC_ADDRESS_LENGTH; i++) {
            printf("%02X", (unsigned int) mac_address[i]);
            if (i < MAC_ADDRESS_LENGTH - 1) {
                printf("-");
            }
        }
}

//Arp Sweep Thread
DWORD WINAPI ArpSweepThread(LPVOID param) {
    NETWORK_INFO *info = malloc(sizeof(NETWORK_INFO));

    BYTE *mac_addr = malloc(sizeof(char) * MAC_ADDRESS_LENGTH);
    ULONG length = MAC_ADDRESS_LENGTH;
    THREAD_DATA *data = (THREAD_DATA *)param;

    int res = SendARP(data->target, data->src, (PULONG)mac_addr, &length);

    if (res == NO_ERROR) {
        info->ip = data->target;
        info->mac = mac_addr;
        info->result = data->target;
    } else {
        if (info != NULL)
            free(info);
        info = NULL;
    }

    free(data);
    return (DWORD)(uintptr_t)info;
}


void ARP_sweep(const char *srcIP) {
    IPAddr src;
    IPAddr start_ip;
    HANDLE t[THREAD_WORKERS];
    char ipStr[INET_ADDRSTRLEN]; 

    inet_pton(AF_INET, srcIP, &src);
    inet_pton(AF_INET, "192.168.30.0", &start_ip);
    unsigned int current_host = ntohl(start_ip);
    
    for(unsigned long i = 1; i <= 254; i++) {
        IPAddr target = htonl(current_host + i);
        DWORD thread_ID = i;

        THREAD_DATA *thread_data = malloc(sizeof(THREAD_DATA));
        thread_data->src = src;
        thread_data->target = target;

        t[i - 1] = CreateThread(NULL, 0, ArpSweepThread, thread_data, 0, &thread_ID);
    }

    //Closing all the threads.
    for(int i = 0; i <= THREAD_WORKERS - 1; i++) {
        DWORD thread_result;
        NETWORK_INFO *thread_info;

        WaitForSingleObject(t[i], INFINITE);
        GetExitCodeThread(t[i], &thread_result);
        CloseHandle(t[i]);

        printf("thread result : %ld\t", thread_result);
        if (thread_result != 0) {
            //printf("%d\t%ld\n",i, exit);
            thread_info = (NETWORK_INFO *)(uintptr_t)thread_result;
            inet_ntop(AF_INET, &(thread_info->ip), ipStr, INET_ADDRSTRLEN);
            printf("Host : %s\t", ipStr);
            print_mac(thread_info->mac);
            printf("\n\n");

            free(thread_info->mac);
            free(thread_info);
        }
        printf("\n");
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
        print_mac(adapter->PhysicalAddress);
        /*-for (long unsigned int i = 0; i < adapter->PhysicalAddressLength; i++) {
            printf("%02X", adapter->PhysicalAddress[i]);
            if (i < adapter->PhysicalAddressLength - 1) {
                printf("-");
            }
        }*/
        printf("\n\n");
        adapter = adapter->Next;
    }
}


int main(int argc, char *argv[]) {
    
    IP_ADAPTER_ADDRESSES *adapterAddresses = NULL;
    IP_ADAPTER_ADDRESSES *adapterCursor = NULL;
    ULONG outBufLen = 15000; // Initial buffer size for adapter information.

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

    ULONG adapterErrorCode = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapterAddresses, &outBufLen);

    // Checking if the adapter information was retrieved successfully.
    if (adapterErrorCode == ERROR_SUCCESS) {
        adapterCursor = adapterAddresses;
    } else {
        printf("Error retrieving adapter information: %lu\n", adapterErrorCode);
        free(adapterAddresses);
        return 1;
    }

    if (argc < 2) {  
        printf("Work in progress...\n");
        return 0;
    } else {
        if (strcmp("-help", argv[1]) == 0) {

        }
        else if (strcmp("-showinterface", argv[1]) == 0)  show_info(adapterCursor);
        else if (strcmp("-arpsweep", argv[1]) == 0)       ARP_sweep(HARD_CODED_ADDRESS);
        else                                              printf("It's not a command...");
    }

    free(adapterAddresses);
    return 0;
}