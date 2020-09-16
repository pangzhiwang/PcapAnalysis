#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>

//声明一下函数
int dpi_ssh_analyze(dpi_pkt *pkt);
int dpi_tftp_analyze(dpi_pkt *pkt);
int dpi_ntp_analyze(dpi_pkt *pkt);

 //定义一个函数指针，专门用来识别协议报文
dpi_protocol_analyze_func_t  dpi_tcp_analyze_funcs[ProtocolTCPEnd]=
{
    dpi_ssh_analyze
};

dpi_protocol_analyze_func_t  dpi_udp_analyze_funcs[ProtocolUDPEnd]=
{
    dpi_tftp_analyze,
    dpi_ntp_analyze
};

void dpi_pkt_tcp(dpi_result *res , dpi_pkt *pkt);
void dpi_pkt_udp(dpi_result *res , dpi_pkt *pkt);

//解析ip报文的函数
void dpi_pkt_ip(dpi_result *res , dpi_pkt *pkt)
{
    //ip报文计数++
    res->ip_count++;
    //ip版本号要为4
    if(pkt->ip_packet->version != 4)
    {
        DPI_LOG_DEBUG("IP version not eq 4\n");
        return ;
    }
    //ip首部长度要记住
    int ihl = pkt->ip_packet->ihl << 2; //单位是4，所以要乘以4
    //ip报文总长度
    int ip_totlen = ntohs(pkt->ip_packet->tot_len);
    //判断片偏移是否为0
    if((pkt->ip_packet->frag_off & htons(0x01ff)) != 0)
    {
        DPI_LOG_DEBUG("IP frag off  not eq 0\n");
        return;
    }

    //根据ip报文是什么协议来进行分支
    switch(pkt->ip_packet->protocol)
    {
    case IPPROTO_TCP:
        //tcp
        //计算数据的长度以及起始位置
        pkt->tcp_len = ip_totlen - ihl; 
        //如果数据区域没有数据，跳过
        if(pkt->tcp_len<=0)
            return;
        pkt->tcp_packet = (struct tcphdr*)((char*)pkt->ip_packet + ihl);
        dpi_pkt_tcp(res,pkt);
        break;
    case IPPROTO_UDP:
        //udp
        pkt->udp_len = ip_totlen - ihl; 
        //如果数据区域没有数据，跳过
        if(pkt->udp_len<=0)
            return;
        pkt->udp_packet = (struct udphdr*)((char*)pkt->ip_packet + ihl);
        dpi_pkt_udp(res,pkt);
        break;
    default:
        break;
    }


}
//TCP的解析函数
void dpi_pkt_tcp(dpi_result *res , dpi_pkt *pkt)
{
    res->tcp_count++;
    //计算tcp头部长度
    int tcphl = pkt->tcp_packet->doff * 4 ;

    //计算数据区域的长度
    pkt->payload_len = pkt->tcp_len - tcphl;  //数据区域长度=tcp报文总长度-tcp头长
    pkt->payload = (uint8_t*)pkt->tcp_packet + tcphl;


    //先查看一下该报文是不是已经被标识的连接
    //是则直接对应协议报文的数量++
    dpi_list_node *node = res->tcp_connection_list->sentinal.next;
    for(;node!=&res->tcp_connection_list->sentinal;node=node->next)
    {
        dpi_tcp_connection *con = node->data;
        //判断已经识别的连接跟当前的报文是否同一个
        //匹配源ip和目标ip，以及源端口和目标端口
        if(con->src_ip == pkt->ip_packet->saddr
                &&con->dst_ip == pkt->ip_packet->daddr
                &&con->src_port == pkt->tcp_packet->source
                &&con->dst_port == pkt->tcp_packet->dest)
        {
            //报文匹配了该连接
            res->tcp_payload_count[con->protocol]++;
            return ;
        }

        //连接的反方向判定
        if(con->src_ip == pkt->ip_packet->daddr
                &&con->dst_ip == pkt->ip_packet->saddr
                &&con->src_port == pkt->tcp_packet->dest
                &&con->dst_port == pkt->tcp_packet->source)
        {
            //报文匹配了该连接
            res->tcp_payload_count[con->protocol]++;
            return ;
        }
    }
    


    //否：继续遍历每一个协议，去识别该报文是什么协议
    int i;
    for(i=0;i<ProtocolTCPEnd;++i)
    {
        if(dpi_tcp_analyze_funcs[i](pkt))
        {
            //匹配了对应的协议
            res->tcp_payload_count[i]++;

            //标记一下该连接是什么协议
            //创建连接的结构体
            dpi_tcp_connection *con = malloc(sizeof(dpi_tcp_connection));
            //TODO:判错 
            //记录当前报文的连接信息包括源和目的ip和端口
            con->src_ip = pkt->ip_packet->saddr;
            con->src_port = pkt->tcp_packet->source;
            con->dst_ip = pkt->ip_packet->daddr;
            con->dst_port = pkt->tcp_packet->dest;
            con->protocol = i; //该连接的协议是什么也要保存
            //将连接的信息丢到链表中
            dpi_list_append(res->tcp_connection_list,con);

            break;
        }
    }
}
//UDP的解析函数
void dpi_pkt_udp(dpi_result *res , dpi_pkt *pkt)
{
    //udp报文数量++
    res->udp_count++;
    
    uint16_t udp_len = ntohs(pkt->udp_packet->len);
    
    //计算应用数据的起始位置以及长度
    pkt->payload_len = udp_len - sizeof(struct udphdr);
    pkt->payload = (unsigned char*)pkt->udp_packet + sizeof(struct udphdr);

    //遍历每个协议分析函数，如果是某个协议的报文，对应的协议报文数量++
    int i;
    for(i=0;i<ProtocolUDPEnd;++i)
    {
        if(dpi_udp_analyze_funcs[i](pkt))
        {
            //如果该报文是某个协议的报文，对应报文数量++
            res->udp_payload_count[i]++;
        }
    }


}
