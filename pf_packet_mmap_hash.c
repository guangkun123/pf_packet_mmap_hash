#include <stdio.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <poll.h>
#include <linux/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
//#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <search.h>
#include <getopt.h>

#define ETH_HDR_LEN 14

struct timeval begin;

char *format = "%n,%M,%m,%a,%h,%S,%999M,%999a,%999S,%99M,%99a,%99S";

char nic[20], ip[20];
struct flow {
   unsigned char src_ip[4];
   unsigned char dst_ip[4];
   unsigned char sp[2];
   unsigned char dp[2];
   unsigned int last;
   //unsigned char data[51];
};

unsigned char bip[4];
//int max_size = 1865535;
int max_size = 1865535;
struct flow *flow_head,*flow_cur;

typedef struct node_list {
    int *data;
    int size;
    int used;
    int count;
    int max;
    int min;
    int avg;
    int med;
    //int std;
    int p95max;
    int p95avg;
    int p95med;
    //int p95std;
    int p99max;
    int p99avg;
    int p99med;
    //int p99std;
    int p999max;
    int p999avg;
    int p999med;
    //int p999std;
} LIST;

struct port_node {
    int n;
    int port;
    LIST *list;
    struct port_node *next;
};

struct port_list {
    struct port_node *head;
    int size;
};

struct port_list *pl;

void list_init(struct port_node *node){
    node->list = (struct node_list *) malloc(sizeof(struct node_list));
    node->list->size = 300;
    node->list->used = 0;
    node->list->min = 0;
    node->list->max = 0;
    node->list->avg = 0;
    node->list->med = 0;
    //node->list->std = 0;
    node->list->p95max = 0;
    node->list->p95avg = 0;
    node->list->p95med = 0;
    //node->list->p95std = 0;
    node->list->p99max = 0;
    node->list->p99avg = 0;
    node->list->p99med = 0;
    //node->list->p99std = 0;
    node->list->p999max = 0;
    node->list->p999avg = 0;
    node->list->p999med = 0;
    //node->list->p999std = 0;
    node->list->data = (int *)malloc(sizeof(int) * node->list->size);
    memset(node->list->data, 0, node->list->size * sizeof(int));
}

LIST *get_list_from_port(int port){
    if (pl->head == NULL){
        struct port_node *node = pl->head = (struct port_node *)malloc(sizeof(struct port_node));
        node->n = pl->size;
        node->port = port;
        node->next = NULL;
        list_init(node);
        pl->size++;
        return node->list;
    }

    struct port_node *cur = pl->head;
    while (cur){
        if (cur->port == port){
            return cur->list;
        }
        if (cur->next == NULL) {break;}
        cur = cur->next;
    }
    
        cur->next = (struct port_node *)malloc(sizeof(struct port_node));
        cur->next->n = pl->size;
        cur->next->port = port;
        cur->next->next = NULL;
        pl->size++;
        list_init(cur->next);
        return cur->next->list;
}


int textCompare(const void *a, const void *b) {
  return *(int*)a - *(int*)b;
}

static unsigned long isqrt(unsigned long x)
{
    if (x < 1) return 1;
    //printf("isqrt:%d\n", x);
    unsigned long op, res, one;

    op = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument.
    one = 1;
    while (one < op) one <<= 2;
    while (one > op) one >>= 2;

    while (one) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    
    return res;
    
}

void list_print_data(struct port_node *node){
    unsigned long sum = 0;
    unsigned long min = 0;
    unsigned long var = 0;
    //unsigned long p95var = 0;
    //unsigned long p99var = 0;
    //unsigned long p999var = 0;
    //printf("=============list_print_data============\n");
    if (node->list->used < 6){
        return;
    }
    qsort(node->list->data, node->list->used, sizeof(int), textCompare);
    int *cur = node->list->data;
    int n = 0;
    node->list->min = *(cur+n);
    while (n < node->list->used){
        //printf("%d:%d:%d;", node->list->used, n, *(cur+n));
        sum = sum + *(cur+n);
        var += *(cur+n) * *(cur+n);
        if (*(cur+n) < node->list->min) {
            node->list->min = *(cur+n);
        }
        if (*(cur+n) > node->list->max) {
            node->list->max = *(cur+n);
        }
        if (n == node->list->used * 95 / 100){
            node->list->p95max = *(cur+n);
            node->list->p95med = *(cur+n/2);
            node->list->p95avg = sum / (n+1);
            //p95var = var / (n+1);
            //p95var -= node->list->p95avg * node->list->p95avg;
            //node->list->p95std = isqrt(p95var);
        }
        if (n == node->list->used * 99 / 100){
            node->list->p99max = *(cur+n);
            node->list->p99med = *(cur+n/2);
            node->list->p99avg = sum / (n+1);
            //p99var = var / (n+1);
            //p99var -= node->list->p99avg * node->list->p99avg;
            //node->list->p99std = isqrt(p99var);
        }
        if (n == node->list->used * 999 / 1000){
            node->list->p999max = *(cur+n);
            node->list->p999med = *(cur+n/2);
            node->list->p999avg = sum / (n+1);
            //p999var = var / (n+1);
            //p999var -= node->list->p99avg * node->list->p99avg;
            //node->list->p999std = isqrt(p999var);
        }
        //if (n >= node->list->used * 99 / 100) {
        //    //"/usr/local/sinasrv2/bin/tcprstat_new -t 3 -f %n,%M,%m,%a,%h,%S,%95M,%95a,%95S,%99M,%99a,%99S --no-header"
        //    //56533:26342,960191,10,156,38,7885,152,43,23,1295,56,92
        //    printf("%d:%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%u\n", node->port, node->list->used, 111,22,11,33,33,44,44,44, *(cur+n), sum/n,55);
        //}
        n++;
    }
    node->list->avg = sum / node->list->used;
    node->list->med = *(cur+node->list->used/2);
    //var /= node->list->used;
    //var -= node->list->avg * node->list->avg;
    //node->list->std = isqrt(var);
}

void output(struct port_node *node){
    if (node->list->used < 6){
        return;
    }
    char *c;
    //printf("%s,%d\n", format, strlen(format));
    printf("%d:", node->port);
    for (c = format; c[0]; c ++){
        if (c[0] == '%') {
            int r = 100;
            c ++;
            
            if (c[0] >= '0' && c[0] <= '9') {
                r = 0;
                while (c[0] >= '0' && c[0] <= '9') { //%95×ª»»ÎªÊý×Ö95´æÈër,Èç¹ûÃ»ÓÐ%95ÕâÐ©Êý×Ö£¬Ôòr=100
                    r *= 10;
                    r += c[0] - '0';
                    
                    c ++;
                    
                }
                
            }

            if (c[0] == 'n'){
               printf("%d", node->list->used);
            }
            if (c[0] == 'M'){
               if (r == 100) printf("%d", node->list->max);
               if (r == 95) printf("%d", node->list->p95max);
               if (r == 99) printf("%d", node->list->p99max);
               if (r == 999) printf("%d", node->list->p999max);
            }
            if (c[0] == 'm'){
               printf("%d", node->list->min);
            }
            if (c[0] == 'a'){
               if (r == 100) printf("%d", node->list->avg);
               if (r == 95) printf("%d", node->list->p99avg);
               if (r == 99) printf("%d", node->list->p99avg);
               if (r == 999) printf("%d", node->list->p999avg);
            }
            if (c[0] == 'S'){
               if (r == 100) printf("%d", node->list->avg);
               if (r == 95) printf("%d", node->list->p99avg);
               if (r == 99) printf("%d", node->list->p99avg);
               if (r == 999) printf("%d", node->list->p999avg);
            }
            //if (c[0] == 'S'){
            //   if (r == 100) printf("%d", node->list->std);
            //   if (r == 95) printf("%d", node->list->p99std);
            //   if (r == 99) printf("%d", node->list->p99std);
            //   if (r == 999) printf("%d", node->list->p999std);
            //}
            if (c[0] == 'h'){
               if (r == 100) printf("%d", node->list->med);
               if (r == 95) printf("%d", node->list->p99med);
               if (r == 99) printf("%d", node->list->p99med);
               if (r == 999) printf("%d", node->list->p999med);
            }
        }
        else{
            fputc(c[0], stdout);
        }

    }
                fputc('\n', stdout);
}

void port_list_print(struct port_list *pl){
    //printf("=============port_list_print============\n");
    //printf("port size: %d\n", pl->size );
    struct port_node *cur = pl->head;
    while (cur){
        //list_print(cur);
        list_print_data(cur);
        output(cur);
        cur = cur->next;
    }
}


void list_add_data(LIST *list, int a){
    //printf("=============list_add_data============\n");
    if (list->used >= list->size){
        list->size = list->size * 2;
        int *tmp = (int *)malloc(sizeof(int) * list->size);
        memset(tmp, 0, list->size * sizeof(int));
        memcpy(tmp, list->data, list->used * sizeof(int));
        free(list->data);
        list->data = tmp;
    }

    list->data[list->used] = a;
    list->used ++;
    //printf("=============list_add_data end============\n");
}

void hash_print(int mn, struct flow * hash_head, int hash_used){
    int i = 0;
    for(i = 0; i < hash_used; i++){
        //if (i % 9 != 0) continue;
        printf("#%d# %d %d.%d.%d.%d:%d \n ", mn, i, (hash_head + i)->src_ip[0], (hash_head + i)->src_ip[1], (hash_head + i)->src_ip[2], (hash_head + i)->src_ip[3], (hash_head + i)->sp[0]<<8|(hash_head + i)->sp[1]);
    }
}

unsigned long hash(unsigned char *ip, char *sp)
{
    unsigned long hash = 5381;
    int i, c;

    for(i = 0; i < 4; i++){
        c = *(ip + i);
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    for(i = 0; i < 2; i++){
        c = *(sp + i);
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

void flow_exec(){
    struct flow *cur = flow_head;
    //bip[0] = 

    //printf("bip:%d.%d.%d.%d\n",bip[0], bip[1], bip[2], bip[3]);
    unsigned long hash_value;
    int hash_index = 0;
    int hash_size = 300000;
    int i = 0;
    //int mn = 0;
    struct flow ***hash_head = (struct flow ***)malloc(hash_size * sizeof(struct flow ***));
    memset(hash_head, 0, hash_size * sizeof(struct flow ***));
    while (cur->last){
        //cur->
        if (memcmp(cur->dst_ip, bip, 4) == 0){
            //printf("#in pack %d  %d.%d.%d.%d:%d ===> ",cur->last, cur->src_ip[0], cur->src_ip[1], cur->src_ip[2], cur->src_ip[3], cur->sp[0]<<8|cur->sp[1]);
            //printf("%d.%d.%d.%d:%d \n",cur->dst_ip[0], cur->dst_ip[1], cur->dst_ip[2], cur->dst_ip[3], cur->dp[0]<<8|cur->dp[1]);
            hash_value = hash(cur->src_ip, cur->sp);
            hash_index = hash_value % hash_size;
            if (*(hash_head + hash_index) == 0){
                struct flow ** hash_arr = (struct flow **)malloc(2 * sizeof(struct flow **));
                memset(hash_arr, 0, 2 * sizeof(struct flow **));
                *hash_arr = cur;
                *(hash_head + hash_index) = hash_arr;
            }else if (*(hash_head + hash_index) != 0){
                struct flow ** hash_arr = *(hash_head + hash_index);
                for(i = 0; *(hash_arr + i) != 0; i++){
                    if ((memcmp(cur->src_ip, (*(hash_arr + i))->src_ip, 4) == 0) && (memcmp(cur->sp, (*(hash_arr + i))->sp, 2) == 0)){
                        *(hash_arr + i) = cur;
                        break;
                    }
                }
                if (*(hash_arr + i) == 0){
                    *(hash_arr + i) = cur;
                    struct flow ** hash_tmp = (struct flow **)malloc((i + 2) * sizeof(struct flow **));
                    memset(hash_tmp, 0, (i + 2) * sizeof(struct flow **));
                    memcpy(hash_tmp, hash_arr, (i + 1) * sizeof(struct flow **));
                    free(hash_arr);
                    *(hash_head + hash_index) = hash_tmp;
                }
            }
             
      }
      if (memcmp(cur->src_ip, bip, 4) == 0){
	    //printf("#out pack %d %d.%d.%d.%d:%d <===", cur->last, cur->dst_ip[0], cur->dst_ip[1], cur->dst_ip[2], cur->dst_ip[3], cur->dp[0]<<8|cur->dp[1]);
	    //printf("%d.%d.%d.%d:%d \n",cur->src_ip[0], cur->src_ip[1], cur->src_ip[2], cur->src_ip[3], cur->sp[0]<<8|cur->sp[1]);
            hash_value = hash(cur->dst_ip, cur->dp);
            hash_index = hash_value % hash_size;
            if (*(hash_head + hash_index) != 0){
                struct flow ** hash_arr = *(hash_head + hash_index);
                int find_index = -1;
                for(i = 0; *(hash_arr + i) != 0; i++){
	    //printf("before src  \n");
	    //printf("#src pack %d %d.%d.%d.%d:%d \n", (*(hash_arr + i))->last, (*(hash_arr + i))->dst_ip[0], (*(hash_arr + i))->dst_ip[1], (*(hash_arr + i))->dst_ip[2], (*(hash_arr + i))->dst_ip[3], (*(hash_arr + i))->dp[0]<<8|(*(hash_arr + i))->dp[1]);
	    //printf("#src pack %d \n", (*(hash_arr + i))->last);
	    //printf("after src  \n");
                    if ((memcmp(cur->dst_ip, (*(hash_arr + i))->src_ip, 4) == 0) && (memcmp(cur->dp, (*(hash_arr + i))->sp, 2) == 0)){
                        find_index = i;
                        //printf("find index\n");
                        LIST *list = get_list_from_port(cur->sp[0]<<8|cur->sp[1]);   
                        int sla = cur->last - (*(hash_arr + i))->last;
                        list_add_data(list, sla);
                    }
                }
                if ( (find_index >= 0) && (i - find_index == 1) ){
                    free(*(hash_head + hash_index));
                    *(hash_head + hash_index) = 0;
                } else if ( (find_index >= 0) && (i - find_index > 1) ){
                    //printf("before find_index > 1 \n");
                    struct flow ** hash_tmp = (struct flow **)malloc(i * sizeof(struct flow **));
                    memset(hash_tmp, 0, i * sizeof(struct flow **));
                    memcpy(hash_tmp, hash_arr, find_index * sizeof(struct flow **));
                    memcpy(hash_tmp + find_index, hash_arr + find_index + 1, (i - find_index) * sizeof(struct flow **));
                    //printf("before free hash_arr \n");
                    free(hash_arr);
                    //printf("after free hash_arr \n");
                    *(hash_head + hash_index) = hash_tmp;
                }
             }
       }
       cur++;
    }
        //mn++;
        //if (mn % 11359 != 0) continue;
        //hash_print(mn, hash_head, hash_used);
}

int fn = 0;
unsigned int c_max_last = 0;
void CallBackPacket(struct tpacket_hdr *pHead)
{
    if (pHead->tp_len <= pHead->tp_mac){ return; }
    //unsigned char *ethhead;
    unsigned char *iphead;
    //ethhead = (unsigned char *)pHead + pHead->tp_mac;
    iphead = (unsigned char *)pHead + pHead->tp_net;

    unsigned int c_last;
    //iphead = ethhead + ETH_HDR_LEN;
    //unsigned short iphdrlen;
    //printf("iphdrlen:%d\n",iphdrlen);

    //unsigned char *data = iphead + 54;
    //int size = pHead->tp_len - 54;
    // header length as 32-bit
    if (iphead[9] != 6) return;

    c_last = (pHead->tp_sec - begin.tv_sec) * 1000 * 1000 + (pHead->tp_usec - begin.tv_usec) / 1;
    int dp, sp;
    sp = iphead[20]<<8|iphead[21];
    dp = iphead[22]<<8|iphead[23];
    //if (dp != 53682 && sp != 53682){
    //    return;
    //}
    //if (dp == 53662 ) {
        //printf("%d %d.%d.%d.%d:%d ===> ", c_last, iphead[12], iphead[13], iphead[14], iphead[15],sp);
        //printf("%d.%d.%d.%d:%d \n", iphead[16], iphead[17], iphead[18], iphead[19], dp);
        //PrintData(data, size);
    //}
    //if (sp == 53682) {
    //    printf("%d %d.%d.%d.%d:%d <===", c_last, iphead[16], iphead[17], iphead[18], iphead[19], dp);
    //    printf("%d.%d.%d.%d:%d \n",iphead[12], iphead[13], iphead[14], iphead[15], sp);
    //}
    //memcpy(flow_cur->data, data, size);

    flow_cur->last = c_last;

    //printf("fn: %d, flow_cur->last: %d, max_last: %d, c_last: %d, pHead->tp_sec:%u, pHead->tp_usec:%u \n", fn, flow_cur->last, c_max_last, c_last, pHead->tp_sec, pHead->tp_usec);
    if (c_last > 3000 * 1000 || fn > max_size){
        //printf("fn:%d, last:%d\n", fn, last);
        //flow_print();
        flow_exec();
        port_list_print(pl);
        exit(0);
    }
    //if (c_last > c_max_last){
    //    c_max_last = c_last;
    //}else if (c_last < c_max_last){
    //////}else {
    //    return;
    ////    //printf("pHead->tp_sec:%u, begin.tv_sec:%ld, last:%d\n",pHead->tp_sec, begin.tv_sec, c_last);
    ////    //printf("pHead->tp_len:%d, pHead->tp_mac:%d, PORT [%d]->[%d]\n", pHead->tp_len, pHead->tp_mac,(iphead[20]<<8|iphead[21]), (iphead[22]<<8|iphead[23]));
    //}
    //printf("fn: %d, flow_cur->last: %d, max_last: %d, c_last: %d, pHead->tp_sec:%u, pHead->tp_usec:%u \n", fn, flow_cur->last, c_max_last, c_last, pHead->tp_sec, pHead->tp_usec);
    memcpy(flow_cur->src_ip, iphead+12, 12);
    //memcpy(flow_cur->src_ip, iphead+12, 4);
    //memcpy(flow_cur->dst_ip, iphead+16, 4);

    //memcpy(flow_cur->sp, iphead+20, 2);
    //memcpy(flow_cur->dp, iphead+22, 2);


    //if (flow_cur->last != c_last){
    //    printf("error: flow_cur->last: %d, c_last: %d\n", flow_cur->last, c_last);
    //}
    flow_cur++;
    fn++;

    //printf(" PORT [%d]->[%d]\n", (iphead[20]<<8|iphead[21]), (iphead[22]<<8|iphead[23]));
}

void get_nic_and_ip(char* nic, char *ip){
    struct ifaddrs * ifAddrStruct = NULL, * ifa = NULL;
    void * tmpAddrPtr = NULL;
    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa ->ifa_addr->sa_family == AF_INET) { // Check it is IPv4
            char mask[INET_ADDRSTRLEN];
            void* mask_ptr = &((struct sockaddr_in*) ifa->ifa_netmask)->sin_addr;
            inet_ntop(AF_INET, mask_ptr, mask, INET_ADDRSTRLEN);
            if (strcmp(mask, "255.0.0.0") != 0) {
                tmpAddrPtr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                //printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
                strcpy(nic, ifa->ifa_name);
                strcpy(ip, addressBuffer);
                memcpy(bip, tmpAddrPtr, 4);
            }
        }
    }
    if (ifAddrStruct != NULL)
        freeifaddrs(ifAddrStruct);
}

struct option long_options[] = {
    { "format", required_argument, NULL, 'f' },
    { "no-header", no_argument, NULL, 'S' },
    { "interval", no_argument, NULL, 't' },
    { NULL, 0, NULL, '\0' }
};
char *short_options = "Stf:";
int main(int argc, char *argv[]) {

    char c;
    int fd = 0, ret = 0;
    char *buff = NULL;

    while (( c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1){

        switch (c) {

        case 'f':
            format = optarg;
            break;

        default:
            break;
        }
    } 


     get_nic_and_ip(nic,ip);
        gettimeofday(&begin,NULL);
        int malloc_size = max_size * sizeof(struct flow);
        flow_head = flow_cur = (struct flow *)malloc(malloc_size);
        memset(flow_head, 0, malloc_size);
        //printf("sizeof flow:%d \n", sizeof(struct flow));
        //printf("malloc_size:%d M\n",malloc_size/1024/1024);

        pl = (struct port_list *)malloc(sizeof(struct port_list));
        pl->head = NULL;
        pl->size = 0;

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //可以使用ARP进行一下测试
    //fd = socket(PF_PACKET, SOCK_DGRAM, htons (ETH_P_ARP));
    if(fd<0)
    {
        perror("socket");
        goto failed_2;
    }

    //PACKET_VERSION和SO_BINDTODEVICE可以省略
#if 1
    const int tpacket_version = TPACKET_V1;
    /* set tpacket hdr version. */
    ret = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &tpacket_version, sizeof (int));
    if(ret<0)
    {
        perror("setsockopt");
        goto failed_2;
    }

    //#define NETDEV_NAME "wlan0"
#define NETDEV_NAME nic
    /* bind to device. */
    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NETDEV_NAME, sizeof (NETDEV_NAME));
    if(ret<0)
    {
        perror("setsockopt");
        goto failed_2;
    }
#endif

    struct tpacket_req req;
#define PER_PACKET_SIZE 2048
    const int BUFFER_SIZE = 1024*1024*16; //16MB的缓冲区
    req.tp_block_size = 4096;
    req.tp_block_nr = BUFFER_SIZE/req.tp_block_size;
    req.tp_frame_size = PER_PACKET_SIZE;
    req.tp_frame_nr = BUFFER_SIZE/req.tp_frame_size;

    ret = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req));
    if(ret<0)
    {
        perror("setsockopt");
        goto failed_2;
    }

    buff = (char *)mmap(0, BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(buff == MAP_FAILED)
    {
        perror("mmap");
        goto failed_2;
    }

    int nIndex=0, i=0;
    while(1)
    {
        //这里在poll前先检查是否已经有报文被捕获了
        struct tpacket_hdr* pHead = (struct tpacket_hdr*)(buff+ nIndex*PER_PACKET_SIZE);
        //如果frame的状态已经为TP_STATUS_USER了，说明已经在poll前已经有一个数据包被捕获了，如果poll后不再有数据包被捕获，那么这个报文不会被处理，这就是所谓的竞争情况。
        if(pHead->tp_status == TP_STATUS_USER)
            goto process_packet;

        //poll检测报文捕获
        struct pollfd pfd;
        pfd.fd = fd;
        //pfd.events = POLLIN|POLLRDNORM|POLLERR;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ret = poll(&pfd, 1, -1);
        if(ret<0)
        {
            perror("poll");
            goto failed_1;
        }

process_packet:
        //尽力的去处理环形缓冲区中的数据frame，直到没有数据frame了
        for(i=0; i < req.tp_frame_nr; i++)
        {
            struct tpacket_hdr* pHead = (struct tpacket_hdr*)(buff+ nIndex*PER_PACKET_SIZE);

            //XXX: 由于frame都在一个环形缓冲区中，因此如果下一个frame中没有数据了，后面的frame也就没有frame了
            if(pHead->tp_status == TP_STATUS_KERNEL)
                break;

            //处理数据frame
            CallBackPacket(pHead);

            //重新设置frame的状态为TP_STATUS_KERNEL
            pHead->tp_len = 0;
            pHead->tp_status = TP_STATUS_KERNEL;

            //更新环形缓冲区的索引，指向下一个frame
            nIndex++;
            nIndex %= req.tp_frame_nr;
        }

    }
success:
    close(fd);
    munmap(buff, BUFFER_SIZE);
    return 0;

failed_1:
    munmap(buff, BUFFER_SIZE);

failed_2:
    close(fd);
    return -1;
}
