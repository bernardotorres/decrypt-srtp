
decrypt-srtp
============

Decrypt RTP streams embedded in PCAP captures using libsrtp.
It needs the Master Key exchanged by other means to do its job.
Deciphered RTP is dumped in such a way that output can be fed to text2pcap, to recreate a deciphered capture.

Usage: 
```
./decrypt-srtp [-d <debug>]* [-k <key> [-a][-e]]
or     ./decrypt-srtp -l
where  -a use message authentication
       -e <key size> use encryption (use 128 or 256 for key size)
       -g Use AES-GCM mode (must be used with -e)
       -k <key> sets the srtp master key as hex
       -b <key> sets the srtp master key as base64
       -f <filter> sets the pcap filter (e.g.: "port 1234")
       -l list debug modules
       -d <debug> turn on debugging for module <debug>
```

dependencies
============

SRTP part has been taken from VLC project. It depends on libsrtp for (de/)ciphering.
Pcap processing is based on libpcap.

Typically, on Debian,
```
# apt-get install libpcap-dev
```

caveats
=======

Isolating a single RTP flow from a network capture is a hard job, too hard to be done in this tool. Hence, srtp-decrypt expects to process a single RTP flow.
Network capture shall not contain ICMP, ARP or reverse RTP flow for example, as those packets will not be deciphered correctly by the tool.
Moreover, RTP offset in frames is expected to be constant, by default 42, but can be set to 46 in case of 802.1q tagging.


Based on:
* https://github.com/gteissier/srtp-decrypt

* https://github.com/cisco/libsrtp/blob/master/test/rtpw.c
