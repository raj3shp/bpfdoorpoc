# bpfdoorpoc
[bpfdoor](https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/) malware implements an interesting technique for C&C communication using BPF with raw network socket.

This is a proof of concept code for this BPF technique.

>  Loads a Berkeley Packet Filter (BPF) sniffer allowing it to efficiently watch traffic and work in front of any locally running firewalls to see packets (hence BPFDoor).

### Usage:

- Compile and run (as root)

```
gcc bpfdoorpoc.c -o bpfdoorpoc
./bpfdoorpoc

``` 
- bpfdoorpoc listens on a raw network socket. 
- Compile and run the client to send the MAGICBYTE (X) and the IP to reverse shell to bpfdoorpoc

```
gcc client.c -o client
./client
```

### Generating [BPF filters](https://www.kernel.org/doc/html/latest/networking/filter.html)

The filter program is in the form of instructions for a virtual machine, which are interpreted, or compiled into machine code by a just-in-time (JIT) mechanism and executed, in the kernel.

Simple way to generate BPF filters for network traffic, use `tcpdump` with `-dd` flag

```
tcpdump udp and dst port 53 -dd

{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 4, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 0, 11, 0x00000011 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 8, 9, 0x00000035 },
{ 0x15, 0, 8, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 6, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 4, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000035 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
```

### Detecting bpfdoor

[chkrootkit](https://www.chkrootkit.org/) detects this malware with following trick:

```
egrep packet_recvmsg /proc/*/stack
```

It seems that `packet_recvmsg` kernel function is invoked when a process opens a raw network socket. And this is super rare to expect from a user-space process.
