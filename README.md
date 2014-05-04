decrypt-srtp
============

Decrypt RTP streams embedded in PCAP captures using libsrtp

Usage: 
```
./decrypt-srtp [-d <debug>]* [-k <key> [-a][-e]]
or     ./decrypt-srtp -l
where  -a use message authentication
       -e <key size> use encryption (use 128 or 256 for key size)
       -g Use AES-GCM mode (must be used with -e)
       -k <key>  sets the srtp master key as hex
       -b <key>  sets the srtp master key as base64
       -f <filter> sets the pcap filter
       -l list debug modules
       -d <debug> turn on debugging for module <debug>
```


Based on:
* https://github.com/gteissier/srtp-decrypt

* https://github.com/cisco/libsrtp/blob/master/test/rtpw.c
