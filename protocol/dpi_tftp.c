#include "dpi.h"
#include <string.h>
#define DPI_TFTP_NETASCII "netascii"
#define DPI_TFTP_OCTET "octet"
#define DPI_TFTP_MAIL "mail"

typedef struct dpi_tftp_header
{
    uint16_t opcode;
    uint16_t errCode;
}dpi_tftp_header;

//该函数用来识别tftp报文
int dpi_tftp_analyze(dpi_pkt *pkt)
{
    dpi_tftp_header *tftp = (dpi_tftp_header*)pkt->payload;
    //WRQ|RRQ报文
    //整个报文至少9个字节
    if(pkt->payload_len>=9)
    {
        //opcode : 1|2
        if(tftp->opcode == htons(1) || tftp->opcode == htons(2))
        {
            //最后几个字节肯定是   netascii | octet | mail   前后都夹着一个\0
            if(pkt->payload_len>=strlen(DPI_TFTP_NETASCII)+4)
            {
                char *begin = (char*)pkt->payload + pkt->payload_len - 1 - strlen(DPI_TFTP_NETASCII);
                if(memcmp(begin,DPI_TFTP_NETASCII,strlen(DPI_TFTP_NETASCII))==0)
                {
                    //判断成功
                    return 1;
                }
            }
            if(pkt->payload_len>=strlen(DPI_TFTP_OCTET)+4)
            {
                char *begin = (char*)pkt->payload + pkt->payload_len - 1 - strlen(DPI_TFTP_OCTET);
                if(memcmp(begin,DPI_TFTP_OCTET,strlen(DPI_TFTP_OCTET))==0)
                {
                    //判断成功
                    return 1;
                }
            }
            if(pkt->payload_len>=strlen(DPI_TFTP_MAIL)+4)
            {
                char *begin = (char*)pkt->payload + pkt->payload_len - 1 - strlen(DPI_TFTP_MAIL);
                if(memcmp(begin,DPI_TFTP_MAIL,strlen(DPI_TFTP_MAIL))==0)
                {
                    //判断成功
                    return 1;
                }
            }
        }
    }

    //data报文
    //opcode : 3
    //长度: 4 - 516字节
    if(pkt->payload_len>=4 && pkt->payload_len <=516 && tftp->opcode == htons(3))
    {
        return 1; 
    }
    //ack报文
    //opcode : 4
    //长度恒为4 
    if(pkt->payload_len==4&&tftp->opcode==htons(4)) 
    {
        return 1;
    }
    //error报文
    //opcode : 5
    //errorcode : 0-7
    //长度： >=5 字节
    if(pkt->payload_len>=5&&tftp->opcode==htons(5))
    {
        if(tftp->errCode>=htons(0) && tftp->errCode <=htons(7))
        {
            //最后一个字节是\0
            if(*(pkt->payload+pkt->payload_len-1) == '\0')
                return 1;
        }
    }
    
    return 0;
}
