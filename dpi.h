#pragma once
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "util/dpi_list.h"

#define DPI_LOG_DEBUG(...) do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_INFO(...) do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_ERROR(...) do{fprintf(stderr,__VA_ARGS__);}while(0)
//支持的TCP协议分析
typedef enum dpi_protocol_tcp
{
    SSH,
    //FTP,
    ProtocolTCPEnd
}dpi_protocol_tcp;

//支持的UDP协议分析
typedef enum dpi_protocol_udp
{
    TFTP,
    NTP,
    ProtocolUDPEnd
}dpi_protocol_udp;

//dpi连接的定义
typedef struct dpi_tcp_connetion
{
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    dpi_protocol_tcp protocol;    //该链接对应的协议是什么协议
}dpi_tcp_connection;
//句柄定义
typedef struct dpi_result
{
    void *pcap_handle;
    unsigned int ether_count;        //以太网报文数量
    unsigned int ip_count;           //ip报文数量
    unsigned int tcp_count;          //tcp 报文数量
    unsigned int udp_count;          //udp报文数量
    unsigned int tcp_payload_count[ProtocolTCPEnd]; //TCP应用协议报文的数量数组
    unsigned int udp_payload_count[ProtocolUDPEnd]; //UDP应用协议报文的数量数组
    dpi_list *tcp_connection_list;   //存储tcp连接的链表
}dpi_result;

//一个报文的解析信息
typedef struct dpi_pkt
{
    uint32_t ether_len;         //以太网报文长度
    struct ether_header *ether_packet;     //以太网报文的地址
    uint32_t ip_len;            //ip报文长度
    struct iphdr  *ip_packet;   //ip网报文的地址
    union {
        struct {
            uint32_t tcp_len;           //tcp报文长度
            struct tcphdr *tcp_packet;  //tcp报文的地址
        };
        struct {
            uint32_t udp_len;           //udp报文长度
            struct udphdr *udp_packet;  //udp报文的地址
        };
    };
    uint32_t payload_len;       //数据区域的长度
    uint8_t *payload;           //指向数据区域的指针
}dpi_pkt;

// 初始化
dpi_result* dpi_init(const char *pcapfile);

//启动执行报文解析的函数
void dpi_loop(dpi_result *res);


// 资源释放
void dpi_destroy(dpi_result *res);

 //定义一个函数指针，专门用来识别协议报文
typedef int (*dpi_protocol_analyze_func_t)(dpi_pkt *pkt);

//函数指针数组
extern dpi_protocol_analyze_func_t  dpi_tcp_analyze_funcs[ProtocolTCPEnd];
extern dpi_protocol_analyze_func_t  dpi_udp_analyze_funcs[ProtocolUDPEnd];
