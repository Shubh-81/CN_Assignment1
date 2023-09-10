# Computer Networks Assignment 1

This assignment is completed by **Shubh Agarwal (21110205)** and **Atal Gupta (21110037)**.

## Prerequisites

Before running the programs, please ensure that you have `pcap.h` installed on your system. You can install it using the following command:

```bash
sudo apt-get install libpcap-dev
```

## Problem Statements and Solutions

### Problem 1a

The first problem involves creating a program that opens a raw socket and sniffs all the packets going through your network interface. The program should identify the source IP, destination IP, source port, and destination port of different TCP flows.

The solution for this problem is provided in the file `1.c`.

To compile the code for Problem 1a, use the following command:

```bash
gcc <file_name.c>
```

To run the compiled program for Problem 1a:

```bash
sudo ./a.out
```

### Problem 1b

The second problem involves an analysis of different flows while performing tcpreplay using the provided packet capture (pcap file - 0.pcap).

The solution for this problem is provided in the file `1b.c`.

To compile the code for Problem 1b, use the following command:

```bash
gcc <file_name.c> -lpcap
```

To run the compiled program for Problem 1b:

```bash
./a.out <path_to_pcap_file>
```

### Problem 3

The third problem extends the code from Part I to include the functionality that links the client application TCP port number to the corresponding process ID of that application.

The solution for this problem is provided in the file `3.c`.

To compile the code for Problem 3, use the following command:

```bash
gcc <file_name.c>
```

To run the compiled program for Problem 3:

```bash
sudo ./a.out
```
