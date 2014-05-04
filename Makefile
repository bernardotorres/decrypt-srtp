CFLAGS=-g -Os -Wall

all:
	$(CC) -g decrypt-srtp.c -o decrypt-srtp -I /usr/local/include/srtp/ -l pcap  -lgcrypt -lsrtp
check:
	./srtp-decrypt -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz < ./marseillaise-srtp.pcap | text2pcap -t "%M:%S." -u 10000,10000 - - > ./marseillaise-rtp.pcap
