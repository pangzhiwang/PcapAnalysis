#include "dpi_list.h"
#include <stdlib.h>
#include <string.h>

//创建一个链表
dpi_list *dpi_list_create()    //创建一个链表
{
    dpi_list *list = malloc(sizeof(dpi_list));
    if(list)
    {
        memset(list,0,sizeof(*list));
        //哨兵节点，prev 和 next指针都指向自己
        list->sentinal.next = &list->sentinal;
        list->sentinal.prev = &list->sentinal;
    }

    return list;
}
//将数据追加到链表中
int dpi_list_append(dpi_list *list , void *data)
{
    dpi_list_node *node = malloc(sizeof(dpi_list_node)); //当前新增加的节点
    if(!node)
        return -1;
    //链表长度++
    list->size++;
    node->data = data;
    dpi_list_node *last_node = list->sentinal.prev; //链表最后一个节点
    //链表最后一个节点的next指针指向当前新增节点
    last_node->next = node;
    //当前新增的节点的prev也要指向链表最后一个节点
    node->prev = last_node;
    //哨兵节点的prev要指向当前新增的节点（因为它成为了最后一个节点)
    list->sentinal.prev = node;
    //新增的节点的next要指向哨兵节点
    node->next = &list->sentinal;
    return 0;
}

//释放链表
void dpi_list_destroy(dpi_list *list)
{
    //遍历整个链表
    dpi_list_node *begin = list->sentinal.next;
    while(begin!=&list->sentinal)
    {
        //释放每个节点的数据区域（都是堆内存分配）
        if(begin->data)
            free(begin->data);
        dpi_list_node *tmp = begin;
        begin = begin->next;
        //释放每个节点的内存
        free(tmp);
    }
    //释放链表结构体
    free(list);
}
