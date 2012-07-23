#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h> //for interface-specific structures
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <unistd.h>

int hexlify(const void *raw, size_t len, char **out)
{
   size_t i;
   u_int8_t *byte;
   char *ptr;

   byte = (u_int8_t *)raw;
   *out = (char*)malloc(len*2+1);
   
   if( NULL == *out )
   {
      perror("hexlify");
      return EXIT_FAILURE;
   }

   ptr = *out;

   for( i = 0 ; i < len ; ++ i )
   {
      snprintf(ptr, 3, "%0.2x", *byte);
      ++byte;
      ptr+=2;
   }
   *ptr = 0;

   return EXIT_SUCCESS;
}

void print_packet(const char *head, const void *packet, size_t len)
{
   size_t i;
   char *out;

   hexlify(packet, len, &out);

   printf("%s: %s\n", head, out);
   free(out);
}

struct ARP {
   struct ether_header etherHdr;
   struct arphdr arpHdr;
   struct ether_addr hsrc;
   struct in_addr psrc;
   struct ether_addr hdst;
   struct in_addr pdst;
} __attribute__((packed));

void make_arp(struct ARP *arp, unsigned short int op, 
        struct in_addr psrc, struct ether_addr hsrc, 
        struct in_addr pdst, struct ether_addr hdst)
{
   memset(arp, 0, sizeof(struct ARP));
   if( ARPOP_REQUEST == op )
      memset(&(arp->etherHdr.ether_dhost), 0xFF, ETH_ALEN);
   else
      memcpy(arp->etherHdr.ether_dhost, &hdst, ETH_ALEN);

   memcpy(arp->etherHdr.ether_shost, &hsrc, ETH_ALEN);
   arp->etherHdr.ether_type = htons(ETHERTYPE_ARP);

   arp->arpHdr.ar_hrd = htons(ARPHRD_ETHER);
   arp->arpHdr.ar_pro = htons(ETHERTYPE_IP);
   arp->arpHdr.ar_hln = 6;
   arp->arpHdr.ar_pln = 4;
   arp->arpHdr.ar_op  = htons(op);
   memcpy(&arp->psrc, &psrc, sizeof(struct in_addr));
   memcpy(arp->hsrc.ether_addr_octet, &hsrc, ETH_ALEN);
   memcpy(&arp->pdst, &pdst, sizeof(struct in_addr));
   if( ARPOP_REQUEST == op )
      memset(arp->hdst.ether_addr_octet, 0xFF, ETH_ALEN);
   else
      memcpy(arp->hdst.ether_addr_octet, &hdst, ETH_ALEN);
}

int __get_if_req(int sockfd, const char *ifName, int request, struct ifreq *if_req)
{
   memset(if_req, 0, sizeof(struct ifreq));
   strncpy(if_req->ifr_name, ifName, IFNAMSIZ-1);
   return ioctl(sockfd, request, if_req);
}

int get_if_addr(int sockfd)//, const char *ifName, struct in_addr *ip)
{
      struct ifconf if_req;
      memset(&if_req, 0, sizeof(struct ifconf));
      if( ioctl(sockfd, SIOCGIFCONF, &if_req) < 0 )
      {
         perror("get_if_addr");
         exit(0);
      }
      print_packet("IP", &(if_req.ifc_req->ifr_addr), 4);
}

int get_if_hwaddr(int sockfd, const char *ifName, struct ether_addr *hsrc)
{
   struct ifreq if_req;
   if( __get_if_req(sockfd, ifName, SIOCGIFHWADDR, &if_req) < 0 )
   {
      perror("get_if_hwaddr");
      return EXIT_FAILURE;
   }
   memcpy(hsrc, &(if_req.ifr_hwaddr.sa_data), ETH_ALEN);
   return EXIT_SUCCESS;
}

int get_if_idx(int sockfd, const char *ifName, int *idx)
{
   struct ifreq if_req;
   if( __get_if_req(sockfd, ifName, SIOCGIFINDEX, &if_req) < 0 )
   {
      perror("get_if_idx");
      return EXIT_FAILURE;
   }
   *idx = if_req.ifr_ifindex;
   return EXIT_SUCCESS;
}

int send_raw_packet(int sockfd, const char *ifName, void *packet, size_t len)
{
   struct sockaddr_ll socket_address;

   /* Zero-ize the structure */
   memset(&socket_address, 0, sizeof(struct sockaddr_ll));

   /* Index of the network device */
   get_if_idx(sockfd, ifName, &(socket_address.sll_ifindex));

   /* Address length*/
   socket_address.sll_halen = ETH_ALEN;

   /* Customization to understand */
   //socket_address.sll_protocol = htons(ETH_P_IP);  

   /*ARP hardware identifier is ethernet*/
   //socket_address.sll_hatype   = ARPHRD_ETHER;
      
   /*target is another host*/
   //socket_address.sll_pkttype  = PACKET_OTHERHOST;

   /* Indicates that it is raw socket */
   //socket_address.sll_family   = PF_PACKET;

   /* Get the MAC address of the interface to send on */
   get_if_hwaddr(sockfd, ifName, (struct ether_addr *)&(socket_address.sll_addr));

   // send packet
   print_packet("Packet to send", packet, len);

   if( sendto(sockfd, (void*)packet, len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0 )
   {
      perror("Send failed");
      return EXIT_FAILURE;
   }
   return EXIT_SUCCESS;
}

void father_signal_handler(int sig)
{
   printf("Father received signal %d\n", sig);
   exit(0);
}

void child_signal_handler(int sig)
{
   printf("Child received signal %d\n", sig);
   exit(0);
}

struct prn_t;

typedef int (*inspect_t)(struct prn_t *, char*, size_t);

struct prn_t{
   unsigned long max_count;
   unsigned long count;
   inspect_t inspect;
} prn_t;

struct ip_prn_t {
   struct prn_t prn;
   struct in_addr ip;
   struct ether_addr mac;
} ip_prn_t;

int look_for_ip(struct prn_t *self, char *packet, size_t len)
{
   struct ARP arp;
   char *mac, *ip;
   struct ip_prn_t *self_ = (struct ip_prn_t *)self;
   if( 0x06 == packet[13] && 0x08 == packet[12] ) // is arp
   {
      memcpy(&arp, packet, sizeof(struct ARP));
      if(arp.arpHdr.ar_op == htons(ARPOP_REPLY))
      {
         hexlify(&(arp.hsrc), ETH_ALEN, &mac);
         ip = (char *)inet_ntoa(arp.psrc);
         printf("%s is-at %s\n", ip, mac);
         free(mac);
         if( 0 == memcmp(&(arp.psrc), (struct in_addr*)&(self_->ip), 4))
         {
            memcpy(&(self_->mac), &(arp.hsrc), ETH_ALEN);
            return 1;
         }
      }
   }
   if( self->max_count != 0 && ++(self->count) >= self->max_count )
      return 1;
   return 0;
}

int sniff(struct prn_t *prn)
{
   int sockfd, ok;
   size_t recv_len;
   unsigned char buffer[ETH_FRAME_LEN];
   if( -1 == (sockfd = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) )
   {
      perror("Raw socket creation");
      return EXIT_FAILURE;
   }
   
   ok = 0;

   while( ! ok )
   {
      recv_len = recv(sockfd, buffer, ETH_FRAME_LEN-1, 0);
      ok = prn->inspect(prn, buffer, recv_len);
   }

   return EXIT_SUCCESS;
}

int arp_who_has(const unsigned char *ifName, struct in_addr pdst)
{
   int sockfd, status;
   struct in_addr psrc;
   struct ether_addr hsrc, hdst;
   struct ARP arp;

   if( -1 == (sockfd = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) )
   {
      perror("Raw socket creation");
      return EXIT_FAILURE;
   }

   //get_if_addr(sockfd);
   get_if_hwaddr(sockfd, ifName, &hsrc);
   memset(&hdst, 0xFF, ETH_ALEN);

   if( 0 == inet_aton("192.168.1.110", (struct in_addr *)&psrc) )
   {
      puts("Error for psrc");
      return EXIT_FAILURE;
   }

   make_arp(&arp, ARPOP_REQUEST, psrc, hsrc, pdst, hdst);
   while(1)
   {
      send_raw_packet(sockfd, ifName, &arp, sizeof(struct ARP));
      sleep(2);
   }
}

void do_arp_scan(const unsigned char *ifName, struct in_addr ip, struct ether_addr *mac)
{
   pid_t pid;
   int status;
   struct ip_prn_t prn;

   pid = fork();
   switch(pid)
   {
      case -1:
         perror("do_arp_scan");
         exit(1);
         break;
      case 0:
         // keep on sending who-has requests
         while(1)
         {
            arp_who_has(ifName, ip);
            sleep(2);
         }
         break;
      default:
         memset(&prn, 0, sizeof(struct ip_prn_t));
         prn.ip = ip;
         prn.prn.max_count=10;
         prn.prn.count=0;
         prn.prn.inspect = look_for_ip;

         sniff((struct prn_t *)&prn);

         print_packet("mac", &(prn.mac), ETH_ALEN);
         
         // once found, kill the child
         kill(pid, SIGKILL);
         waitpid(pid, &status, 0);
         break;
   }
}

#if 0
int arp_scan(struct in_addr ip, struct ether_addr *mac)
{
   pid_t pid;
   int p[2];

   if( -1 == pipe(p) )
   {
      perror("Cannot create pipe");
      exit(0);
   }

   pid = fork();
   switch(pid)
   {
      case -1: 
         perror("Fork arp-scan");
         exit(-1);
         break;
      case 0:
         do_arp_scan(ip, mac);
         write(p[1], *mac, ETH_ALEN);
         exit(0);
      default:
         close(p[1]);
         break;
   }
   return EXIT_SUCCESS;
}
#endif


int main(int argc, char **argv)
{
#if 0
   int sockfd, status;
   struct in_addr psrc, pdst;
   struct ether_addr hsrc, hdst;
   struct ARP arp;
   pid_t pid;
   const char *ifName = "eth0";


   if( -1 == (sockfd = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) )
   {
      perror("Raw socket creation");
      return EXIT_FAILURE;
   }

   get_if_hwaddr(sockfd, ifName, &hsrc);
   memset(&hdst, 0xFF, ETH_ALEN);
   print_packet("Src mac addr", &hsrc, ETH_ALEN);
   print_packet("Dst mac addr", &hdst, ETH_ALEN);

   if( 0 == inet_aton("192.168.1.110", (struct in_addr *)&psrc) )
   {
      puts("Error for psrc");
      return EXIT_FAILURE;
   }

   if( 0 == inet_aton("192.168.1.13", (struct in_addr *)&pdst) )
   {
      puts("Error for pdst");
      return EXIT_FAILURE;
   }

   pid = fork();
   make_arp(&arp, ARPOP_REQUEST, psrc, hsrc, pdst, hdst);
   
   if( 0 == pid )
   {
      /* Register Ctrl+C */
      signal(SIGINT, child_signal_handler);

      while( 1 )
      {
        send_raw_packet(sockfd, ifName, &arp, sizeof(struct ARP));
        sleep(2);
      }
   }
   else
   {
      /* Register Ctrl+C */
      signal(SIGINT, father_signal_handler);
      sniff();
      waitpid(pid, &status, 0);
      printf("Child ended");
   }
#endif
   struct in_addr pdst;
   struct ether_addr hdst;

   if( 0 == inet_aton("192.168.1.13", (struct in_addr *)&pdst) )
   {
      puts("Error for pdst");
      return EXIT_FAILURE;
   }

   do_arp_scan("eth0", pdst, &hdst);

   return EXIT_SUCCESS;
}

