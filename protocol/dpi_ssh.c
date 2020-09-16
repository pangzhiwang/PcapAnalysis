#include "dpi.h"
#include <string.h>

//ssh协议报文分析函数
int dpi_ssh_analyze(dpi_pkt *pkt)
{
    // 如果 报文前面4个字节是 SSH- 那么就是ssh报文
    // 保护措施，数据区域长度要>4字节
    if(pkt->payload_len<=4)
    {
        return 0;
    }

    if(memcmp("SSH-",pkt->payload,4)==0)
    {
        return 1;
    }
    return 0;
}
