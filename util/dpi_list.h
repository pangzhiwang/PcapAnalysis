#pragma once
#include <stdint.h>

//节点的定义：
typedef struct dpi_list_node
{
    void *data;             //泛化，能够存储任何类型数据的指针
    struct dpi_list_node *prev;
    struct dpi_list_node *next;
}dpi_list_node;

//链表的定义：
typedef struct dpi_list
{
    uint32_t size;      //链表当前长度
    dpi_list_node sentinal;     //哨兵节点，肯定存在，链表的起始位置
}dpi_list;

//创建一个链表
dpi_list *dpi_list_create();    //创建一个链表
//将数据追加到链表中
int dpi_list_append(dpi_list *list , void *data);
//释放链表
void dpi_list_destroy(dpi_list *list);
