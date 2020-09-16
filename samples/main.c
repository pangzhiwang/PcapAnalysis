#include <stdio.h>
#include <pcap/pcap.h>
#include "dpi.h"

void usage(const char *argv0)
{
    fprintf(stderr,"usage : %s <pcap_file>\n",argv0);
}

void displayResult(dpi_result *res)
{
    printf("==============================================\n");
    printf("以太网报文数量:%u\n",res->ether_count);
    printf("IP报文数量:%u\n",res->ip_count);
    printf("TCP报文数量:%u\n",res->tcp_count);
    printf("UDP报文数量:%u\n",res->udp_count);
    printf("SSH报文数量:%u\n",res->tcp_payload_count[SSH]);
    printf("TFTP报文数量:%u\n",res->udp_payload_count[TFTP]);
    printf("NTP报文数量:%u\n",res->udp_payload_count[NTP]);
    printf("==============================================\n");
    //遍历tcp连接链表，输出每个连接的信息 
    dpi_list_node *node = res->tcp_connection_list->sentinal.next;
    while(node!=&res->tcp_connection_list->sentinal)
    {
        dpi_tcp_connection *con = node->data;
        //使用以下函数来讲一个IP 4自己的地址转换为点分十进制的字符串
        //char *inet_ntoa(struct in_addr in);
        struct in_addr in;
        in.s_addr = con->src_ip;
        printf("src:%s:%d\t",inet_ntoa(in),ntohs(con->src_port));
        in.s_addr = con->dst_ip;
        printf("dst:%s:%d\tprotocol: %d\n",inet_ntoa(in),ntohs(con->dst_port),
                con->protocol);
        node = node->next;
    }
    printf("==============================================\n");
}

int main(int argc , char **argv)
{
    //如果main函数没有参数，就提示
    if(argc!=2)
    {
        usage(argv[0]);
        return -1;
    }

    //1 初始化
    dpi_result *res = dpi_init(argv[1]);
    if(!res)
    {
        fprintf(stderr,"Error in dpi_init\n");
        return -1;
    }
    //2 业务处理
    dpi_loop(res);
    //打印结果集
    displayResult(res);
    //3 资源释放
    dpi_destroy(res);

    return 0;
}
