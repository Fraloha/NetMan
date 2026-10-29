# Windows Network Discovery Tool (ARP Sweep)

Un tool di network discovery leggero e performante scritto in **C (C11)** nativo per sistemi **Windows**, progettato per eseguire scansioni ARP multithreaded ad alta velocità su sottoreti locali (es. `/24`).

Il progetto fa uso delle API di Windows (Win32 Threads, IP Helper API) e di Winsock2 per identificare rapidamente i dispositivi attivi e recuperare i relativi indirizzi MAC e IP.

---

## 🚀 Caratteristiche Principali

* **Multithreading Nativo Win32:** Sfrutta `CreateThread` per interrogare in parallelo ogni singolo host della sottorete (es. 254 thread concorrenti per un'intera classe C), riducendo drasticamente i tempi di scansione rispetto a un approccio sequenziale.
* **Gestione Dinamica dei Dati:** Passaggio sicuro di puntatori a strutture dati allocate dinamicamente (`NETWORK_INFO` e `THREAD_DATA`) tra thread e main thread tramite conversioni sicure compatibili con architetture a **64-bit** (`uintptr_t`).
* **Risoluzione ARP ad Alte Prestazioni:** Integrazione con la funzione `SendARP` della libreria `iphlpapi` per l'invio e la ricezione di pacchetti ARP mirati.
* **Pulizia della Memoria e Stabilità:** Gestione robusta dei leak di memoria sia nei rami di successo che di fallimento (`SendARP`), con attesa sicura tramite `WaitForSingleObject` e chiusura pulita degli handle (`CloseHandle`).
* **Utility di Interfaccia di Rete:** Funzionalità integrata (`-showinterface`) per ispezionare gli adattatori di rete locali, gli indirizzi IPv4 e i MAC address associati tramite `GetAdaptersAddresses`.

---

## 🛠️ Requisiti di Sistema e Tooling

* **Sistema Operativo:** Windows 10 / 11 (o Windows Server).
* **Compilatore:** GCC (tramite **MinGW-w64 / MSYS2** con supporto a C11).
* **Librerie di Sistema (Linker Flags):**
  * `-lws2_32` (Winsock 2)
  * `-liphlpapi` (IP Helper API)

---

## 📥 Compilazione

Per compilare il progetto tramite GCC (MSYS2 / MinGW-w64), apri il terminale nella cartella del codice sorgente ed esegui il seguente comando:

```bash
gcc -g -Wall -Wextra netdiscovery.c -o netdiscovery.exe -lws2_32 -liphlpapi