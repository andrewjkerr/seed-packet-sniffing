# Packet Sniffing and Spoofing Lab
## Team 3

## Problem 1

## Problem 2

You need root in order for `sniffex` to run because `sniffex` will need to access a network device which a non-root user cannot do.

![imgs/sniffexfailure.png](imgs/sniffexfailure.png)

The code that causes this to fail is:

```c
/* find a capture device if not specified on command-line */
dev = pcap_lookupdev(errbuf);
if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n",
        errbuf);
    exit(EXIT_FAILURE);
}
```
