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

char* get_mac_string(BYTE *mac_address) {
    char *string = malloc(sizeof(char) * 16);
    for (long unsigned int i = 0; i < 16; i++) {
            sprintf(string + i, "%02X", (unsigned int) *(mac_address + i));
            if (i < MAC_ADDRESS_LENGTH - 1) {
                sprintf(string + i + 1, "-");
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

void ARP_sweep_seq(const char *srcIP) {
    IPAddr src;
    IPAddr start_ip;
    char ipStr[INET_ADDRSTRLEN]; 

    inet_pton(AF_INET, srcIP, &src);
    inet_pton(AF_INET, "192.168.30.0", &start_ip);
    unsigned int current_host = ntohl(start_ip);
    
    for(unsigned long i = 1; i <= 254; i++) {
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

void ARP_sweep(const char *srcIP) {
    IPAddr src;
    IPAddr start_ip;
    char ipStr[INET_ADDRSTRLEN]; 

    inet_pton(AF_INET, srcIP, &src);
    inet_pton(AF_INET, "192.168.30.0", &start_ip);
    unsigned int current_host = ntohl(start_ip);

    for(unsigned long batch = 1; batch < MAX_HOST_SUBNET - 1; batch+=THREAD_WORKERS) {
        HANDLE *t = calloc(THREAD_WORKERS, sizeof(HANDLE));
        for(unsigned long i = 0; i < THREAD_WORKERS; i++) {
            IPAddr target = htonl(current_host + OFFSET);
            DWORD thread_ID = OFFSET;

            info[OFFSET].src = src;
            info[OFFSET].target = target;

            t[i] = CreateThread(NULL, 0, ArpSweepThread, &info[OFFSET], 0, &thread_ID);
        }

        //Closing all the threads.
        for(int i = 0; i < THREAD_WORKERS; i++) {
            DWORD thread_result;

            if (t[i] == NULL)  continue;

            WaitForSingleObject(t[i], INFINITE);
            GetExitCodeThread(t[i], &thread_result);
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
        printf("\n");
        printf("MAC Address: ");
        printf("%s\n", get_mac_string(adapter->PhysicalAddress));
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
        else if (strcmp("-arpsweep", argv[1]) == 0) {
            if (argc < 3) {
                ARP_sweep_seq(HARD_CODED_ADDRESS);
            } else if (strcmp("-mt", argv[2]) == 0 || strcmp("-multi-threaded", argv[2]) == 0)
                ARP_sweep(HARD_CODED_ADDRESS);
        }
        else                                              printf("It's not a command...");
    }

    free(adapterAddresses);
    return 0;
}