CFLAGS=-g -Os -Wall
INCLUDES=-I/usr/local/include/srtp
LIBRARIES=-lpcap -lgcrypt -lsrtp

all:
	$(CC) -g decrypt-srtp.c -o decrypt-srtp $(INCLUDES) $(LIBRARIES)
check:
	./decrypt-srtp -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-srtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-rtp.pcap
