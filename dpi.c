#include "dpi.h"
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdint.h>

void dpi_pkt_ip(dpi_result *res , dpi_pkt *pkt);

void dpi_pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
// 初始化
dpi_result* dpi_init(const char *pcapfile)
{
    // pcap 打开文件
    char errbuf[PCAP_ERRBUF_SIZE]={0};//错误信息buffer
    pcap_t *handle = pcap_open_offline(pcapfile,errbuf);
    if(!handle)
    {
        //出错处理
        DPI_LOG_ERROR("Error in pcap_open_offline : %s\n",errbuf);
        return NULL;
    }
    //创建一个句柄
    dpi_result *res = malloc(sizeof(dpi_result));
    //重置为0
    memset(res,0,sizeof(*res));
    //将pcap打开文件产生的句柄也存到res句柄中，方便之后的调用
    res->pcap_handle = handle;

    //创建一个链表
    res->tcp_connection_list = dpi_list_create();

    return res;
}

//启动执行报文解析的函数
void dpi_loop(dpi_result *res)
{
    pcap_loop((pcap_t*)res->pcap_handle,0,dpi_pcap_callback,(u_char*)res);
}


//3 资源释放
void dpi_destroy(dpi_result *res)
{
    if(!res)
        return;
    //释放pcap的句柄
    pcap_close(res->pcap_handle);
    //释放链表
    dpi_list_destroy(res->tcp_connection_list);
    //释放自己的句柄
    free(res);
}

//pcap回调函数
void dpi_pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *data)
{
    dpi_result *res = (dpi_result*)user;
    //以太网报文数量自增
    res->ether_count ++;

    if(h->caplen!=h->len)
        return;

    //创建一个 pkt结构体，标识解析路径
    dpi_pkt pkt;
    memset(&pkt,0,sizeof(pkt));
    pkt.ether_len = h->caplen; //以太网报文长度记录
    pkt.ether_packet = (struct ether_header*)data; //以太网报文起始地址

    //解析ip报文
    pkt.ip_len = pkt.ether_len-sizeof(*pkt.ether_packet);  //计算ip报文的长度
    pkt.ip_packet = (struct iphdr*)((char*)pkt.ether_packet +  sizeof(*pkt.ether_packet)); //计算ip报文的起始位置

    //判断以太网之上是不是ip报文
    if(pkt.ether_packet->ether_type == htons(0x0800))
    {
        //调用解析ip报文的函数
        dpi_pkt_ip(res,&pkt);
    }

}
