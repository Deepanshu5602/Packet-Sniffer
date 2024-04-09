#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/ethernet.h> 
#include <string.h>
#include <sys/types.h>
#include <regex.h>
typedef unsigned char u_char;
typedef __u_short u_short;
typedef u_int32_t u_int;

/*MACRO to find Array size of any Array type*/
#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))

/*C struct data structure representing IP Header*/
struct ipheader{
    u_char ver_ihl;
    u_char tos;
    u_short len;
    u_short id;
    u_short flg_off;
/*MACRO for IP flag bits*/
#define DFRAG 0x4000
#define MFRAG 0x2000
/*MACRO defining IP Offset mask*/
#define IP_OFF_MASK 0x1fff
    u_char ttl;
    u_char prot;
    u_short chksum;
    struct in_addr src_addr, dst_addr; 
 };

//C struct data structure representing TCP Header
struct tcpheader{
    u_short src_port;
    u_short dst_port;
    u_int seq_num;
    u_int ack_num;
    u_char offsft;
//Macro to find data offset from a "struct tcpheader" pointer. 
#define OFFSET(th) ((th->offsft & 0xf0)>>4)
    u_char flags;
//MACRO defining flag bits
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short window;
    u_short chksum;
    u_short urp;
};

//Prints IP address into string representation from the "struct in_addr ip"
void printIP(struct in_addr ip){
    uint32_t x = ip.s_addr;
    for (int i = 0; i < 4; i++){
        printf("%d", x&255);
        x >>= 8;
        if (i!=3)printf(".");
    }
}

//Reverses byte order (not bits) of "u_short" data type. Used for converting Network Byte Order into Host Byte Order
u_short u_short_invert(u_short num){
    return (num>>8)|((num&255)<<8);
}
//Reverses byte order (not bits) of "u_int" data type. Used for converting Network Byte Order into Host Byte Order
u_int u_int_invert(u_int num){
    return (num>>24)|((num&255)<<24)|((num&16711680)>>8)|((num&65280)<<8);
}

//Prints TCP flags in their text form by taking the byte containing flags as argument.
void printFlags(u_char flag){
    if (flag&TH_FIN) printf("FIN ");
    if (flag&TH_SYN) printf("SYN ");
    if (flag&TH_RST) printf("RST ");
    if (flag&TH_PUSH) printf("PUSH ");
    if (flag&TH_ACK) printf("ACK ");
    if (flag&TH_URG) printf("URG ");
    if (flag&TH_ECE) printf("ECE ");
    if (flag&TH_CWR) printf("CWR ");
}

//Prints TCP header contents in a readable form. Takes the "struct tcpheader*" as an argument.
int printTCPHeader(struct tcpheader *tcph){
    printf("TCP Header:\n");
    printf("Source Port     : %hu\n", u_short_invert(tcph->src_port));
    printf("Destination Port: %hu\n", u_short_invert(tcph->dst_port));
    printf("Sequence Number : %u\n", u_int_invert(tcph->seq_num));
    printf("Ack. Number     : %u\n", u_int_invert(tcph->ack_num));
    printf("Data Offset     : %d bytes\n", OFFSET(tcph)*4);
    printf("Flags           : ");
    printFlags(tcph->flags);
    printf("\n");
    printf("Window Size     : %hu\n", u_short_invert(tcph->window));
    printf("Urgent pointer  : %hu\n", u_short_invert(tcph->urp));
}

//Prints IP header contents in a readable form. Takes the "struct ipheader*" as an argument.
int printIPHeader(struct ipheader *iphead){
    printf("IP Header:\n");
    printf("Header Length  : %d bytes\n", (int)(iphead->ver_ihl&(15))*4);
    printf("Total Length   : %hu bytes\n", u_short_invert(iphead->len));
    printf("Identification : %hu\n", u_short_invert(iphead->id));
    printf("Don\'t Fragment : %s\n", u_short_invert(iphead->flg_off)&DFRAG?"Set":"Not Set");
    printf("More Fragments : %s\n", u_short_invert(iphead->flg_off)&MFRAG?"Set":"Not Set");
    printf("Frag Offset    : %hu\n", u_short_invert(iphead->flg_off)&IP_OFF_MASK);
    printf("TTL            : %d\n", iphead->ttl);
    printf("Protocol Number: %d\n", iphead->prot);
    printf("Source IP Addr : ");
    printIP(iphead->src_addr);
    printf("\n");
    printf("Dest. IP Addr  : ");
    printIP(iphead->dst_addr);
    printf("\n");
    if (iphead->prot == 6) return 1;
    return 0;
}

//Prints Ethernet header contents in a readable form. Takes the "struct eth_header" as an argument.
int printEtherHeader(struct ether_header *ethframe){
    printf("Ethernet Header: \n");
    printf("Destination MAC Address: ");
    for (int i = 0; i < 6; i++) printf("%02X%s", ethframe->ether_dhost[i], i==5?"":":");
    printf("\n");
    printf("Source MAC Address:      ");
    for (int i = 0; i < 6; i++) printf("%02X%s", ethframe->ether_shost[i], i==5?"":":");
    printf("\n");
    //Prints ether type
    printf("Ether Type:              0x%04X\n", (ethframe->ether_type>>8)|((ethframe->ether_type&((1<<8) - 1))<<8));
    if (ethframe->ether_type != (u_int16_t)0x0008){
        return 0;
    }
    return 1;
}

//Check if given TCP packet is of type HTTP. This function uses POSIX Regular Expressions to find HTTP header.
int httpCheck(const u_char* packet, int size){
    regex_t reg; //Variable to hold compiled POSIX regex expression 
    regmatch_t pmatch[1]; //To hold REGEX matches
    regoff_t off, len; //Offset and length of matched string.
    const char* linere = "^.*$"; //Regex expression to find 1st line.
    //Compiling expression
    if (regcomp(&reg, linere, REG_NEWLINE|REG_EXTENDED)){
        printf("ERROR: Cannot determine if HTTP!\n");
        return 0;
    }    
    //Executing expression on packet
    if (regexec(&reg, packet, ARRAY_SIZE(pmatch), pmatch, 0) == REG_NOMATCH){
        printf("TCP payload not of type HTTP!\n");
        return 0;
    }
    len = pmatch[0].rm_eo - pmatch[0].rm_so;
    regfree(&reg); //Freeing the compiled regex
    //Temporary string to hold first line
    char* tpline = (char*)malloc(len + 1);
    strncpy(tpline, packet, len);
    tpline[len] = '\0';
    //Expression to find HTTP information in first line of HTTP Request
    const char* httpreqre = "^.*HTTP/[0-9]\\.[0-9]\\s$";
    if (regcomp(&reg, httpreqre, REG_NEWLINE|REG_EXTENDED)){
        printf("ERROR: Cannot determine if HTTP!\n");
        return 0;
    }
    int ifdn = 1;
    if (regexec(&reg, tpline, ARRAY_SIZE(pmatch), pmatch, 0) == REG_NOMATCH) ifdn = 0;
    regfree(&reg);
    //True if HTTP request.
    if (ifdn){
        printf("Type of Payload: HTTP Request; Top: %s\n", tpline);
        return 1;
    }
    //Expression to find HTTP information in first line of HTTP Response
    const char* httpresre = "^HTTP/[0-9]\\.[0-9] .*$";
    if (regcomp(&reg, httpresre, REG_NEWLINE|REG_EXTENDED)){
        printf("ERROR: Cannot determine if HTTP!\n");
        return 0;
    }
    ifdn = 1;
    if (regexec(&reg, tpline, ARRAY_SIZE(pmatch), pmatch, 0) == REG_NOMATCH) ifdn = 0;
    regfree(&reg);
    if (ifdn){        
        printf("Type of Payload: HTTP Response; Top: %s\n", tpline);
        return 2;
    }
    //Default fallthrough if not HTTP
    printf("TCP payload not of type HTTP!\n");
    return 0;
}

//Find the offset of HTTP header section's end
int findHeaderEnd(const u_char* packet, int size){
    regex_t reg; //Variable to hold compiled POSIX regex expression 
    regmatch_t pmatch[1]; //To hold REGEX matches
    regoff_t off, len; //Offset and length of matched string.
    const char* gapre = "^\r$"; //REGEX Expression to find empty line.
    //Compiling expression
    if (regcomp(&reg, gapre, REG_NEWLINE|REG_EXTENDED)){
        printf("ERROR: Cannot find empty line, falling back to full search!\n");
        return size;
    }
    //Executing expression
    if (regexec(&reg, packet, ARRAY_SIZE(pmatch), pmatch, 0) == REG_NOMATCH){
        printf("ERROR: Cannot find empty line, falling back to full search!\n");
        return size;
    }
    //Freeing the compiled expression
    regfree(&reg);
    printf("Header Section ends at: %d bytes\n", pmatch[0].rm_so);
    return pmatch[0].rm_so;
}

//string to hold regular expression to find the keyword provided by user. 
char keyword[1024];

//Function to print all the lines containing the keyword.
void printKeyword(const u_char* packet, int size){
    if (keyword[3] == '\n') return; //Checkk if keyword was left blank
    //Regex variables
    regex_t reg; 
    regmatch_t pmatch[1];
    regoff_t off, len;
    const u_char* s = packet;
    //Appending the expression with additional expression to find end of line
    strcpy(keyword + strlen(keyword) - 1, ".*$");
    //Compiling the expression
    if (regcomp(&reg, keyword, REG_NEWLINE|REG_EXTENDED)){
        printf("Cannot initialize Keyword Filter!\n");
        return;
    }
    //temporary string to store the line
    char tmp[4096];   
    //Loop to continously find the lines. 
    for (int i = 0;;i++){
        if (regexec(&reg, s, ARRAY_SIZE(pmatch), pmatch, 0)) {
            regfree(&reg);
            if (i == 0) printf("Keyword search returned no results!\n");
            else printf("\n");
            return;
        }
        if (i == 0) printf("Keyword Results:\n");
        off = pmatch[0].rm_so;
        len = pmatch[0].rm_eo - pmatch[0].rm_so;
        //Copy the matched line to tmp, check if length of matched line exceeds 4095.
        strncpy(tmp, s + off, len>4095?4095:(len));
        tmp[len>4095?4095:(len)] = '\0';
        printf("%s\n", tmp);
        s += pmatch[0].rm_eo + 1;
        if ((s - packet) >= size) break;
    }
}

//Function to print Authorization header
void printAuthorization(const u_char* headers){
    //Regex variables
    regex_t reg;
    regmatch_t pmatch[1];
    regoff_t off, len;
    char tmp[4096]; //Temporary string to hold the matched line
    //REGEX to find line containing Authorization Header
    char* re = "^Authorization:.*$";
    if (regcomp(&reg, re, REG_NEWLINE|REG_EXTENDED)){
        printf("Cannot initialize Authorization Filter!\n");
        return;
    }
    //Executing the regex on packet
    if (regexec(&reg, headers, ARRAY_SIZE(pmatch), pmatch, 0)) {
        regfree(&reg);
        return;
    }
    regfree(&reg);
    off = pmatch[0].rm_so;
    len = pmatch[0].rm_eo - pmatch[0].rm_so;
    strncpy(tmp, headers + off, len);
    tmp[len] = '\0';
    printf("%s\n", tmp);
}

//Function to print HTTP cookies
void printCookies(const u_char* headers, int resp){
    //REGEX variables
    regex_t reg;
    regmatch_t pmatch[1];
    regoff_t off, len;
    printf("\nCookies:\n");

    //If to check if the current HTTP payload is of request or response.
    //The need to check is if it is a response we will have cookies in multiple Set-Cookie Headers
    //Whereas in case of Request, the cookies will be in a single Cookie Header 
    if (resp){
        //Temporary string to hold the Cookie
        char tmp[4096];
        //REGEX to find Set-Cookie
        char* re = "^Set-Cookie:.*$";
        if (regcomp(&reg, re, REG_NEWLINE|REG_EXTENDED)){
            printf("Cannot initialize Cookie Filter!\n");
            return;
        }
        //Iterator on header section
        const char* s = headers; 
        //Loop to continously find HTTP Set-Cookie headers       
        while(1){
            if (regexec(&reg, s, ARRAY_SIZE(pmatch), pmatch, 0)) break;
            off = pmatch[0].rm_so;
            len = pmatch[0].rm_eo - pmatch[0].rm_so;
            //Removing the "Set-Cookie " part and only taking the actual cookie.
            strncpy(tmp, s + off + 12, len - 13);
            tmp[len - 13] = '\0';
            printf("%s\n", tmp);
            //Setting iterator after the end of previous match.
            s += pmatch[0].rm_eo + 1;
        }
    }
    else{
        //Temporary string to hold the Cookie
        char tmp[4096];
        //REGEX to find line containing Cookie header
        char* re = "^Cookie:.*$";
        if (regcomp(&reg, re, REG_NEWLINE|REG_EXTENDED)){
            printf("Cannot initialize Cookie Filter!\n");
            return;
        }
        const char* s = headers;
        //Continoulsy finding the lines with Cookie header        
        while(1){
            if (regexec(&reg, s, ARRAY_SIZE(pmatch), pmatch, 0)) break;
            off = pmatch[0].rm_so;
            len = pmatch[0].rm_eo - pmatch[0].rm_so;            
            int j = 0;
            //Looping through the line to extract all cookies separated by ";" and printing them
            for (int i = 8 + off; i < (off + len - 1); i++){
                if (s[i] == ';'){
                    tmp[j] = '\0';
                    printf("%s\n", tmp);
                    j = 0;
                }
                else if (j == 0 && s[i] == ' ') continue;
                else tmp[j++] = s[i]; 
            }
            if (j != 0) {
                tmp[j] = '\0';
                printf("%s\n", tmp);
            }
            s += pmatch[0].rm_eo + 1;
        }
    }
    printf("\n");
}

//Function to print details about the HTTP payload
void printHTTP(const u_char* packet, int size){
    printf("TCP Payload size: %d bytes, TCP Payload:\n\n", size);
    //Check if TCP payload is conforming to HTTP. ifHTTP will be 0 if not HTTP, 1 if Request and 2 if Response
    int ifHTTP = httpCheck(packet, size);
    if (!ifHTTP) return;
    //Find the end of header section so that we can perform headers search only on the section
    int headerEnd = findHeaderEnd(packet, size);
    //String to store HTTP header section
    char* headers = (char*)malloc(headerEnd + 1);
    strncpy(headers, packet, headerEnd);
    headers[headerEnd] = '\0';
    //String to store HTTP body
    char* body = (char*)malloc(size - headerEnd);
    strncpy(body, packet + headerEnd + 2, size - headerEnd - 2);
    body[size - headerEnd - 2] = '\0';
    //Print Cookies. ifHTTP - 1 will be 0 if request and 1 if Response
    printCookies(headers, ifHTTP - 1);
    //If HTTP request we can also print Authorization Header
    if(ifHTTP == 1) printAuthorization(headers);
    //Find and print the lines with user defined keyword
    printKeyword(packet, size);
    free(body);
    free(headers);
}

//Callback function called by the PCAP Loop for each packet captured. The 3rd argument is the actual packet captured.
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*packet)
{
    //Defining structs for storing Ethernet Frame, IP Header and TCP Header
    struct ether_header *ethframe;
    struct ipheader *iphead;
    struct tcpheader *tcph;
    printf("-------------------------------------------\n");
    //Storing Ethernet Frame Header.
    ethframe = (struct ether_header*)packet;
    //Printing the Etherenet details as provided by header.
    //Checking if packet has an IP payload
    int ifip = printEtherHeader(ethframe);
    if (!ifip){
        printf("Packet has Ether Type other than IP");
        printf("-------------------------------------------\n\n");
        return;
    }    
    //Extracting and storing IP header
    iphead = (struct ipheader*)(packet + ETH_HLEN);
    printf("-------------------------------------------\n");
    //Checking if packet has TCP payload.
    int iftcp = printIPHeader(iphead);
    if (iftcp == 1){
        printf("-------------------------------------------\n");
        //Extracting and storing TCP header
        tcph = (struct tcpheader*)(packet + ETH_HLEN + (int)(iphead->ver_ihl&(15))*4);
        printTCPHeader(tcph);
        //Size of TCP header
        int tcpdsz = u_short_invert(iphead->len) - (int)(iphead->ver_ihl&(15))*4 - OFFSET(tcph)*4;
        //If TCP header size > 0 then check for and print HTTP
        if (tcpdsz > 0){
            printf("-------------------------------------------\n");
            printHTTP(packet + ETH_HLEN + (int)(iphead->ver_ihl&(15))*4 + OFFSET(tcph)*4, tcpdsz);
        }
    }
    printf("-------------------------------------------\n\n");
}

int main(int argc,char **argv){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        
    bpf_u_int32 pMask;           
    bpf_u_int32 pNet;             
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;

    if(argc != 3) //2 Arguments required: 1st is BPF expression and 2nd is number of packets to filter before stopping.
    {
        printf("\nInsufficient Arguments \nUsage: %s [protocol/BPF-expression][number-of-packets]\n",argv[0]);
        return 0;
    }

    //Find all network interfaces present
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    //List all devices along with their description and their properties/flags
    printf("\nHere is a list of available devices on your system:\n\n");
    for(d=alldevs; d; d=d->next)
    {
        printf("%s:\n", d->name);
        printf("\t");
        if (d->description != NULL) {            
            printf("%s\n", d->description);
        }          
        else
        {
            printf(" (Sorry, No description available for this device)\n");            
        }
        printf("\tFlags:\n");
        int lpback = d->flags&PCAP_IF_LOOPBACK;
        int isup = d->flags&PCAP_IF_UP;
        int isrun = d->flags&PCAP_IF_RUNNING;
        int wrls = d->flags&PCAP_IF_WIRELESS;
        int constat = d->flags&PCAP_IF_CONNECTION_STATUS;
        printf("\t\tPCAP_IF_LOOPBACK: %s\n", lpback?"set":"not set");
        printf("\t\tPCAP_IF_UP: %s\n", isup?"set":"not set");
        printf("\t\tPCAP_IF_RUNNING: %s\n", isrun?"set":"not set");
        printf("\t\tPCAP_IF_WIRELESS: %s\n", wrls?"set":"not set");
        printf("\t\tPCAP_IF_CONNECTION_STATUS: ");
        switch(constat){
            case PCAP_IF_CONNECTION_STATUS_CONNECTED:
                printf("CONNECTED");
                break;
            case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
                printf("DISCONNECTED");
                break;
            case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
                printf("UNKNOWN");
                break;
            case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
                printf("NOT_APPLICABLE");
                break;
            default:
                printf("error");
                break;
        }
        printf("\n\n");        
    }

    printf("Enter the interface name on which you want to run the packet sniffer : ");
    fgets(dev_buff, sizeof(dev_buff)-1, stdin);
    dev_buff[strlen(dev_buff) - 1] = '\0';

    if(strlen(dev_buff))
    {
        dev = dev_buff;
        printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...\n",dev, (atoi)(argv[2]));
    }
    //Finding IP information related to the network interface/device selected.     
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);
    int ocmask = 1 << 8;
    ocmask--;
    int mask[4] = {(pMask)&ocmask, (pMask>>8)&ocmask, (pMask>>16)&ocmask, (pMask>>24)&ocmask};

    printf ("IP Address: %d.%d.%d.%d\n", (pNet)&ocmask, (pNet>>8)&ocmask, (pNet>>16)&ocmask, (pNet>>24)&ocmask);
    printf ("Network Mask: %d.%d.%d.%d\n\n", mask[0], mask[1], mask[2], mask[3]);
    //Open the selected device in PCAP to start filtering.
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }
    //Compiling the Berkeley Packet Filter(BPF) expression provided in argument into pseudo machine code
    if(pcap_compile(descr, &fp, argv[1], 0, pMask) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }
    //Setting the filter to FD of opened live device
    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    printf("Search Keyword (leave blank if none): "); 
    //First 3 characters of keyword are part of REGEX 
    strcpy(keyword, "^.*");  
    //User's keyword to be stored in "keyword" at position with offset of 3 
    fgets(keyword + 3, sizeof(keyword)-7, stdin);

    printf("\nCaptured Packets:\n");
    //Starting the capture loop to continously capture the packets
    pcap_loop(descr,atoi(argv[2]), callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}
