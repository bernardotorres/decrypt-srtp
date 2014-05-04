#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include "rtp.h"
#include "rtp_priv.h"
#include "srtp.h"

#include <pcap.h>

#define MAX_FILTER 256
#define MAX_WORD_LEN     128  
#define MAX_KEY_LEN      96

srtp_t srtp_ctx = NULL;
srtp_policy_t policy;

rtp_msg_t message;

/* 
 * srtp_print_packet(...) is for debugging only 
 * it prints an RTP packet to the stdout
 *
 * note that this function is *not* threadsafe
 */

#include <stdio.h>

#define MTU 2048


static const char b64chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char shiftb64(unsigned char c) {
  char *p = strchr(b64chars, c);
  assert(p);
  return p-b64chars;
}

static void decode_block(unsigned char *in, unsigned char *out) {
  unsigned char shifts[4];
  int i;

  for (i = 0; i < 4; i++) {
    shifts[i] = shiftb64(in[i]);
  }

  out[0] = (shifts[0]<<2)|(shifts[1]>>4);
  out[1] = (shifts[1]<<4)|(shifts[2]>>2);
  out[2] = (shifts[2]<<6)|shifts[3];
}

char packet_string[MTU];

char *
srtp_packet_to_string(srtp_hdr_t *hdr, int pkt_octet_len) {
  int octets_in_rtp_header = 12;
  uint8_t *data = ((uint8_t *)hdr)+octets_in_rtp_header;
  int hex_len = pkt_octet_len-octets_in_rtp_header;

  /* sanity checking */
  if ((hdr == NULL) || (pkt_octet_len > MTU))
    return NULL;

  /* write packet into string */
  sprintf(packet_string,
          "(s)rtp packet: {\n"
          "   version:\t%d\n"
          "   p:\t\t%d\n"
          "   x:\t\t%d\n"
          "   cc:\t\t%d\n"
          "   m:\t\t%d\n"
          "   pt:\t\t%x\n"
          "   seq:\t\t%x\n"
          "   ts:\t\t%x\n"
          "   ssrc:\t%x\n"
          "   data:\t%s\n"
          "} (%d octets in total)\n",
          hdr->version,
          hdr->p,
          hdr->x,
          hdr->cc,
          hdr->m,
          hdr->pt,
          hdr->seq,
          hdr->ts,
          hdr->ssrc,
          octet_string_hex_string(data, hex_len),
          pkt_octet_len);

  return packet_string;
}


void
usage(char *string) {

  printf("usage: %s [-d <debug>]* [-k <key> [-a][-e]]\n"
         "or     %s -l\n"
         "where  -a use message authentication\n"
         "       -e <key size> use encryption (use 128 or 256 for key size)\n"
         "       -g Use AES-GCM mode (must be used with -e)\n"
         "       -k <key>  sets the srtp master key as hex\n"
         "       -b <key>  sets the srtp master key as base64\n"
         "       -f <filter> sets the pcap filter\n"
         "       -l list debug modules\n"
         "       -d <debug> turn on debugging for module <debug>\n",
         string, string);
  exit(1);

}

static void decode_sdes(unsigned char *in,
  unsigned char *key) {
  int i;
  size_t len = strlen((char *) in);
  assert(len == 40);
  unsigned char raw[30];

  for (i = 0; 4*i < len; i++) {
    decode_block(in+4*i, raw+3*i);
  }
 
 
  memcpy(key, octet_string_hex_string(raw, 30), 60);
}


static void hexdump(const void *ptr, size_t size) {
  int i, j;
  const unsigned char *cptr = ptr;

  for (i = 0; i < size; i += 16) {
    printf("%04x ", i);
    for (j = 0; j < 16 && i+j < size; j++) {
      printf("%02x ", cptr[i+j]);
    }
    printf("\n");
  }
}

static int rtp_offset = 42; /* 14 + 20 + 8 */;
static int frame_nr = -1;
static struct timeval start_tv = {0, 0};

static void handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr,
  const u_char *bytes) {
  int pktsize;
  struct timeval delta;
  int octets_recvd;
  err_status_t stat;
  int *len = NULL;
  void *msg = NULL;
  frame_nr += 1;
  if (start_tv.tv_sec == 0 && start_tv.tv_sec == 0) {
    start_tv = hdr->ts;
  } 

  if (hdr->caplen < rtp_offset) {
    fprintf(stderr, "frame %d dropped: too short\n", frame_nr);
    return;
  }
  const void *rtp_packet = bytes + rtp_offset;

  memcpy((void *)&message, rtp_packet, hdr->caplen - rtp_offset);
  pktsize = hdr->caplen - rtp_offset;
  octets_recvd = pktsize;

  if (octets_recvd == -1) {
    printf("octects less than 1.\n");
    //*len = 0;
    //return -1;
    return;
  }

  /* verify rtp header */
  if (message.header.version != 2) {
    printf("rtp version is not 2.\n");
    //*len = 0;
    return; //return -1;
  }
  if(srtp_ctx == NULL){
    policy.ssrc.type  = ssrc_specific;
    policy.ssrc.value = htonl(message.header.ssrc);
    srtp_create(&srtp_ctx, &policy);
 }
  stat = srtp_unprotect(srtp_ctx, &message.header, &octets_recvd);
  if (stat) {
    fprintf(stderr,
            "error: srtp unprotection failed with code %d%s\n", stat,
            stat == err_status_replay_fail ? " (replay check failed)" :
            stat == err_status_bad_param ? " (bad param)" :
            stat == err_status_no_ctx ? " (no context)" :
            stat == err_status_cipher_fail ? " (cipher failed)" :
            stat == err_status_key_expired ? " (key expired)" :
            stat == err_status_auth_fail ? " (auth check failed)" : "");
    //return -1;
    return;
  }
  //strncpy(msg, rtp_packet, octets_recvd);

  //printf(srtp_packet_to_string(&message.header, octets_recvd));
  timersub(&hdr->ts, &start_tv, &delta);
  printf("%02ld:%02ld.%06lu\n", delta.tv_sec/60, delta.tv_sec%60, delta.tv_usec);
  hexdump(&message.header, pktsize);
}

int main(int argc, char **argv) {
  int c;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle;

  int sock, ret;
  struct in_addr rcvr_addr;
  struct sockaddr_in name;
  struct ip_mreq mreq;
  struct sockaddr_in local;
  sec_serv_t sec_servs = sec_serv_none;
  unsigned char ttl = 5;
  int key_size = 128;
  int gcm_on = 0;
  char *input_key;
  char *address = NULL;
  unsigned short port = 0;
  rtp_sender_t snd;
  err_status_t status;
  int len;
  struct bpf_program fp;
  int do_list_mods = 0;
  char key[MAX_KEY_LEN];
  bpf_u_int32 pcap_mask;
  bpf_u_int32 pcap_net;
  char filter_exp[MAX_FILTER] = "";
  uint32_t ssrc;


  status = srtp_init();


  /* check args */
  while (1) {
    c = getopt(argc, argv, "f:s:b:k:rsae:ld:");
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'b':
      decode_sdes(optarg, input_key);
      break;
    case 'k':
      input_key = (unsigned char *) optarg;
      break;
    case 's':
      hex_string_to_octet_string((uint8_t *)&ssrc, (uint8_t *)optarg, 8);
      ssrc = htonl(ssrc);
      fprintf(stderr, "Setting ssrc as %x\n", ssrc);
      break;
    case 'f':
      memcpy(filter_exp, optarg, strlen(optarg));
      break;
    case 'e':
      key_size = atoi(optarg);
      if (key_size != 128 && key_size != 256) {
        printf("error: encryption key size must be 128 or 256 (%d)\n", key_size);
        exit(1);
      }
	  input_key = malloc(key_size);
      sec_servs |= sec_serv_conf;
      break;
    case 'a':
      sec_servs |= sec_serv_auth;
      break;
    case 'd':
      status = crypto_kernel_set_debug_module(optarg, 1);
      if (status) {
        printf("error: set debug module (%s) failed\n", optarg);
        exit(1);
      }
      break;
    case 'l':
      do_list_mods = 1;
      break;
    default:
      usage(argv[0]);
    }
  }

  if (do_list_mods) {
    status = crypto_kernel_list_debug_modules();
    if (status) {
        printf("error: list of debug modules failed\n");
        exit(1);
    }
    return 0;
  }
  if ((sec_servs && !input_key) || (!sec_servs && input_key)) {
    /* 
     * a key must be provided if and only if security services have
     * been requested 
     */
    fprintf(stderr, "Key was not provided!\n");
    usage(argv[0]);
  }


  /* report security services selected on the command line */
  printf("security services: ");
  if (sec_servs & sec_serv_conf)
    printf("confidentiality ");
  if (sec_servs & sec_serv_auth)
    printf("message authentication");
  if (sec_servs == sec_serv_none)
    printf("none");
  printf("\n");


  /* set up the srtp policy and master key */
  if (sec_servs) {
    /* 
     * create policy structure, using the default mechanisms but 
     * with only the security services requested on the command line,
     * using the right SSRC value
     */
    switch (sec_servs) {
    case sec_serv_conf_and_auth:
      if (gcm_on) {
#ifdef OPENSSL
        switch (key_size) {
        case 128:
          crypto_policy_set_aes_gcm_128_8_auth(&policy.rtp);
          crypto_policy_set_aes_gcm_128_8_auth(&policy.rtcp);
          break;
        case 256:
          crypto_policy_set_aes_gcm_256_8_auth(&policy.rtp);
          crypto_policy_set_aes_gcm_256_8_auth(&policy.rtcp);
          break;
        }
#else
        printf("error: GCM mode only supported when using the OpenSSL crypto engine.\n");
        return 0;
#endif
      } else {
        switch (key_size) {
        case 128:
          printf("Setting default aes_cm_128_hmac_sha1_80 policy\n");
          crypto_policy_set_rtp_default(&policy.rtp);
          crypto_policy_set_rtcp_default(&policy.rtcp);
          break;
        case 256:
          crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy.rtp);
          crypto_policy_set_rtcp_default(&policy.rtcp);
          break;
        }
      }
      break;
    case sec_serv_conf:
      if (gcm_on) {
          printf("error: GCM mode must always be used with auth enabled\n");
          return -1;
      } else {
        switch (key_size) {
        case 128:
          crypto_policy_set_aes_cm_128_null_auth(&policy.rtp);
          crypto_policy_set_rtcp_default(&policy.rtcp);
          break;
        case 256:
          crypto_policy_set_aes_cm_256_null_auth(&policy.rtp);
          crypto_policy_set_rtcp_default(&policy.rtcp);
          break;
        }
      }
      break;
    case sec_serv_auth:
      if (gcm_on) {
#ifdef OPENSSL
        switch (key_size) {
        case 128:
          crypto_policy_set_aes_gcm_128_8_only_auth(&policy.rtp);
          crypto_policy_set_aes_gcm_128_8_only_auth(&policy.rtcp);
          break;
        case 256:
          crypto_policy_set_aes_gcm_256_8_only_auth(&policy.rtp);
          crypto_policy_set_aes_gcm_256_8_only_auth(&policy.rtcp);
          break;
        }
#else
        printf("error: GCM mode only supported when using the OpenSSL crypto engine.\n");
        return 0;
#endif
      } else {
        printf("Setting null_cipher_hmac_sha1_80 policy.\n");
        crypto_policy_set_null_cipher_hmac_sha1_80(&policy.rtp);
        crypto_policy_set_rtcp_default(&policy.rtcp);
      }
      break;
    default:
      printf("error: unknown security service requested\n");
      return -1;
    }
    }
    policy.key  = (uint8_t *) key;
    policy.ekt  = NULL;
    policy.next = NULL;
    policy.window_size = 128;
    policy.allow_repeat_tx = 0;
    policy.rtp.sec_serv = sec_servs;
    policy.rtp.auth_tag_len = 0;
    policy.rtcp.sec_serv = sec_servs;  /* we don't do RTCP anyway */

    /*
     * read key from hexadecimal on command line into an octet string
     */
    len = hex_string_to_octet_string(key, input_key, policy.rtp.cipher_key_len*2);

    /* check that hex string is the right length */
    if (len < policy.rtp.cipher_key_len*2) {
      fprintf(stderr,
              "error: too few digits in key/salt "
              "(should be %d hexadecimal digits, found %d)\n",
              policy.rtp.cipher_key_len*2, len);
      exit(1);
    }
    if (strlen(input_key) > policy.rtp.cipher_key_len*2) {
      fprintf(stderr,
              "error: too many digits in key/salt "
              "(should be %d hexadecimal digits, found %u)\n",
              policy.rtp.cipher_key_len*2, (unsigned)strlen(input_key));
      exit(1);
    }

    fprintf(stderr, "set master key/salt to %s/%s\n", octet_string_hex_string(key, 16),
      octet_string_hex_string(key+16, 14));
  
    pcap_handle = pcap_open_offline("-", errbuf);

    if (!pcap_handle) {
        fprintf(stderr, "libpcap failed to open file '%s'\n", errbuf);
        exit(1);
    }
    assert(pcap_handle != NULL);
    if ((pcap_compile(pcap_handle, &fp, filter_exp, 1, pcap_net)) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(pcap_handle));
        return (2);
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1){
      fprintf(stderr, "couldn't install filter %s: %s\n", filter_exp,
          pcap_geterr(pcap_handle));
      return (2);
    }
    pcap_loop(pcap_handle, 0, handle_pkt, NULL);


    return 0;
}
