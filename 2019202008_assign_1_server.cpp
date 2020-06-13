#include <iostream>
#include <sstream>
#include<unistd.h>
#include<string>
#include<cstring>
#include<stdio.h>
#include<cstdlib>
#include<stdlib.h>
#include<string>
#include<sys/wait.h>
#include<pthread.h>
#include<vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <fstream> 
#include <algorithm>
#include <time.h>
#include <bits/stdc++.h>
#include <openssl/des.h>

using namespace std;
#define ll long long int
#define ul unsigned long int

int sportadd = 10016;

unordered_map<string, int> opcode({
	{"PUBKEY",10},
	{"REQSERV",20},
	{"ENCMSG",30},
	{"REQCOM",40},
	{"DISCONNET",50}
});

struct Header{
public:
	int code;
	int s_addr;
	int d_addr;
};

struct PubKey{
public:
	ll g;
	ll p;
	ll Y;
};

struct ReqServ{
public:
	char filename[50];
};

struct ReqCom{
public:
	bool iscomepleted;
	char message[50];
};

struct EncMsg{
public:
	ll file_size;
	ll buf_len;
	ll original_len;
	unsigned char encmessage[1025];
};

struct Disconnect{
public:
	bool isdisconnect;
	char message[50];
};

struct Message{
public:
	Header header;
	struct{
		PubKey pubkey;
		ReqServ reqserv;
		ReqCom reqcom;
		EncMsg encmsg;
		Disconnect disconnect;
	} allMsg;
};

struct deskey{
public:
	unsigned long int firstb;
	unsigned long int secondb;
	unsigned long int thirdb;
	unsigned long int fourthb;
	unsigned long int fifthb;
	unsigned long int sixthb;
	unsigned long int seventhb;
	unsigned long int eighthb;
};

ll DeffieHellman(ll g, ll p, ll y)
{
	return (ll)((ll)(pow(g,y))%p);
}

void createMap(unordered_map<string, char> *um) 
{ 
    (*um)["0000"] = '0'; 
    (*um)["0001"] = '1'; 
    (*um)["0010"] = '2'; 
    (*um)["0011"] = '3'; 
    (*um)["0100"] = '4'; 
    (*um)["0101"] = '5'; 
    (*um)["0110"] = '6'; 
    (*um)["0111"] = '7'; 
    (*um)["1000"] = '8'; 
    (*um)["1001"] = '9'; 
    (*um)["1010"] = 'A'; 
    (*um)["1011"] = 'B'; 
    (*um)["1100"] = 'C'; 
    (*um)["1101"] = 'D'; 
    (*um)["1110"] = 'E'; 
    (*um)["1111"] = 'F'; 
} 

deskey convertToHex(string num) 
{ 
	struct deskey hexkey;
    int size = num.size();  
    for (int i = 1; i <= (4 - size % 4) % 4; i++) 
        num = '0' + num; 
    unordered_map<string, char> num_map; 
    createMap(&num_map); 
      
    int i = 0; 
    string hex = ""; 
      
    while (1) 
    {  
        hex += num_map[num.substr(i, 4)]; 
        i += 4;
		if(i == 8)
		{
		//	cout<<"1 "<<hex<<endl;
			hexkey.firstb = stoul(hex);
			hex = "";
		}
		if(i == 16)
		{
		//	cout<<"2 "<<hex<<endl;
			hexkey.secondb = stoul(hex);
			hex = "";
		}
		if(i == 24)
		{
		//	cout<<"3 "<<hex<<endl;
			hexkey.thirdb = stoul(hex);
			hex = "";
		}
		if(i == 32)
		{
		//	cout<<"4 "<<hex<<endl;
			hexkey.fourthb = stoul(hex);
			hex = "";
		}
		if(i == 40)
		{
		//	cout<<"5 "<<hex<<endl;
			hexkey.fifthb = stoul(hex);
			hex = "";
		}
		if(i == 48)
		{
		//	cout<<"6 "<<hex<<endl;
			hexkey.sixthb = stoul(hex);
			hex = "";
		}
		if(i == 56)
		{
		//	cout<<"7 "<<hex<<endl;
			hexkey.seventhb = stoul(hex);
			hex = "";
		}
		if(i == 64)
		{
		//	cout<<"8 "<<hex<<endl;
			hexkey.eighthb = stoul(hex);
			hex = "";
		}
        if(i == num.size()) 
            break;
    }

    return hexkey;     
}

string decToStr(ll n) 
{ 
  	char result[65];
	char binaryNum[64];
  	for(int i =0; i< 64; i++)
      binaryNum[i] = '0';

	int i = 0; 
	while (n > 0) { 
		binaryNum[i] =(n % 2) +'0'; 
		n = n / 2; 
		i++; 
	} 
	for (int j = 63; j >= 0; j--) 
		result[63-j] = binaryNum[j]; 
  	result[64] = '\0';
  	string t(result);
  	return t;
}

void desencrypt(ll k1, ll k2, ll k3, char plaintext[], int n, int sockfd, Message msg)
{
	struct deskey key1, key2, key3;
	
	string K1 = decToStr(k1);
	string K2 = decToStr(k2);
	string K3 = decToStr(k3);

	// cout<<"k1 "<<K1.length()<<endl;
	// cout<<"k2 "<<K2<<endl;
	// cout<<"k3 "<<K3<<endl;

	key1 = convertToHex(K1);
	key2 = convertToHex(K2);
	key3 = convertToHex(K3);
	
    DES_cblock cb1 = {(unsigned char)key1.firstb,(unsigned char)key1.secondb,(unsigned char)key1.thirdb,(unsigned char)key1.fourthb,(unsigned char)key1.fifthb,(unsigned char)key1.sixthb,(unsigned char)key1.seventhb,(unsigned char)key1.eighthb};
   	DES_cblock cb2 = {(unsigned char)key2.firstb,(unsigned char)key2.secondb,(unsigned char)key2.thirdb,(unsigned char)key2.fourthb,(unsigned char)key2.fifthb,(unsigned char)key2.sixthb,(unsigned char)key2.seventhb,(unsigned char)key2.eighthb};
   	DES_cblock cb3 = {(unsigned char)key3.firstb,(unsigned char)key3.secondb,(unsigned char)key3.thirdb,(unsigned char)key3.fourthb,(unsigned char)key3.fifthb,(unsigned char)key3.sixthb,(unsigned char)key3.seventhb,(unsigned char)key3.eighthb};

	// DES_cblock cb1 = {0x00, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
   	// DES_cblock cb2 = {0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
   	// DES_cblock cb3 = {0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };

   	DES_key_schedule ks1,ks2,ks3;

   	DES_cblock cblock = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

   	char cipher[n];
   	for(int i=0; i<n; i++)
	{
		cipher[i] = '\0';
	}
//	memset(msg.allMsg.encmsg.encmessage,'\0',sizeof(msg.allMsg.encmsg.encmessage));
//	cout<<"before enc initialise"<<endl;
	for(int i=0; i<sizeof(msg.allMsg.encmsg.encmessage); i++)
	{
		msg.allMsg.encmsg.encmessage[i] = '\0';
	}
//	cout<<"before set key"<<endl;
	if (DES_set_key(&cb1, &ks1)<0 ||
        DES_set_key(&cb2, &ks2)<0 ||
         DES_set_key(&cb3, &ks3)<0 ) {
      printf("Key error, exiting ....\n");
      return;
   }
//	cout<<"before odd parity"<<endl;
   	DES_set_odd_parity(&cblock);
    DES_ede3_cbc_encrypt((const unsigned char*)plaintext, (unsigned char*)cipher, msg.allMsg.encmsg.original_len, &ks1, &ks2, &ks3, &cblock, DES_ENCRYPT);
//	cout<<"size of n "<<n<<endl;
//	cout<<"before copy cipher"<<endl;
	int i;
	for(i=0; i<n; i++)
	{
		msg.allMsg.encmsg.encmessage[i] = cipher[i];
	}
//	msg.allMsg.encmsg.encmessage[i] = '\0';
	msg.allMsg.encmsg.encmessage[n] = '\0';
//	cout<<"size of cipher "<<sizeof(msg.allMsg.encmsg.encmessage)<<endl;
//	cout<<"size of plaintext "<<msg.allMsg.encmsg.original_len<<endl;
	cout<<"cipher text"<<endl;
	cout<<msg.allMsg.encmsg.encmessage<<endl;
//	cout<<"size of message "<<sizeof(msg)<<endl;
	send(sockfd, (struct Message *)&msg, sizeof(struct Message), 0);

	// char text[msg.allMsg.encmsg.original_len];
	// memset(text,0,msg.allMsg.encmsg.original_len);
//	cout<<"before recve k"<<endl;
	// int k;
	// recv(sockfd,&k, sizeof(k),0);
	return;
}

bool is_file_exist(const char *fileName)
{
    std::ifstream infile(fileName);
    return infile.good();
}

void* processthread(void *sockdesc)
{
	int sockfd = *((int *)sockdesc);
	ll Y1, Y2, Y3, k1, k2, k3;
	struct Message msg;
	while(1)
	{
	//	cout<<"before command receive"<<endl;
		bzero(&msg,sizeof(msg));
		recv(sockfd, (struct Message *)&msg, sizeof(struct Message), 0);
	//	cout<<"msg header "<<msg.header.code<<endl;
	//	cout<<"size of msg "<<sizeof(msg)<<endl;
		if(msg.header.code == opcode["PUBKEY"])
		{
			recv(sockfd, (struct Message *)&msg, sizeof(struct Message), 0);
			Y1 = msg.allMsg.pubkey.Y;
			msg.allMsg.pubkey.Y = DeffieHellman(msg.allMsg.pubkey.g,msg.allMsg.pubkey.p,3);
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			k1 = DeffieHellman(Y1, msg.allMsg.pubkey.p, 3);
			cout<<"k1 "<<k1<<endl;

			recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			Y2 = msg.allMsg.pubkey.Y;
			msg.allMsg.pubkey.Y = DeffieHellman(msg.allMsg.pubkey.g,msg.allMsg.pubkey.p,3);
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			k2 = DeffieHellman(Y2, msg.allMsg.pubkey.p, 3);
			cout<<"k2 "<<k2<<endl;

			recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			Y3 = msg.allMsg.pubkey.Y;
			msg.allMsg.pubkey.Y = DeffieHellman(msg.allMsg.pubkey.g,msg.allMsg.pubkey.p,3);
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			k3 = DeffieHellman(Y3, msg.allMsg.pubkey.p, 3);
			cout<<"k3 "<<k3<<endl;

			// fflush(stdin);
			// fflush(stdout);
		}
		else if(msg.header.code == opcode["REQSERV"])
		{
			bzero(&msg,sizeof(msg));
		//	cout<<"in req serv"<<endl;
			recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
		//	cout<<"size of msg "<<sizeof(msg)<<endl;
			if(is_file_exist(msg.allMsg.reqserv.filename) == false)
			{
				msg.header.code = opcode["DISCONNECT"];
				strcpy(msg.allMsg.disconnect.message,"File not present");
				send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			}
			else
			{
			//	bzero(&msg,sizeof(msg));
			//	cout<<"opcode "<<opcode["ENCMSG"]<<endl;
				msg.header.code = opcode["ENCMSG"];
			//	cout<<"msg header sent "<<msg.header.code<<endl;
				send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);

				FILE *fp = fopen(msg.allMsg.reqserv.filename,"rb");
			//	cout<<"after file open"<<endl;
				fseek(fp , 0, SEEK_END);
				int size = ftell(fp);
				rewind(fp);
				msg.allMsg.encmsg.file_size = size;
				cout<<"size "<<size<<endl;
				send(sockfd,(struct Message *)&msg, sizeof(struct Message),0);

				char Buffer[1024];
				memset(Buffer,'\0', sizeof(Buffer));
				int n = 0;
			//	bzero(&msg,sizeof(msg));
				while((n = fread(Buffer, sizeof(char), sizeof(Buffer) , fp)) > 0  && size > 0 )
				{
				//	Buffer[n] = '\0';
					Message msg1;
					int m = n;
					if(n%8 != 0)
					{
						while(true)
						{
							if(n%8 == 0)
								break;
							n = n+1;
						}
					}
				//	n++;
					// for(int i=0; i<n; i++)
					// {
					// 	cout<<"i "<<i<<" "<<Buffer[i]<<endl;
					// }
					msg1.allMsg.encmsg.original_len = m;
					msg1.allMsg.encmsg.buf_len = n;
					desencrypt(k1,k2,k3,Buffer,n,sockfd,msg1);
   					memset(Buffer , '\0', sizeof(Buffer));
					size = size - m;
					// int t=0;
					// send(sockfd,&t,sizeof(t),0);
			//		cout<<"hi"<<endl;
				}
			//	cout<<"before sending m"<<endl;
				// int m=0;
				// send(sockfd,&m, sizeof(m),0);
				Message msg3;
				msg3.header.code = opcode["REQCOM"];
				string s ="Transfer completed";
				strcpy(msg3.allMsg.reqcom.message,s.c_str());
				send(sockfd,(struct Message *)&msg3, sizeof(struct Message),0);

			}

			// fflush(stdin);
			// fflush(stdout);
		}
		else if(msg.header.code == opcode["DISCONNECT"])
		{
			close(sockfd);
		}
		else
		{
			cout<<"Poor choice"<<endl;

			// fflush(stdin);
			// fflush(stdout);
		}
		
		fflush(stdin);
		fflush(stdout);	
	}
}

int main()
{
    int server_fd = socket (AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in   addr;
	struct sockaddr_in address;
	bzero(&addr, sizeof(addr));
	bzero(&address, sizeof(address));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sportadd);
	addr.sin_addr.s_addr=inet_addr("127.0.0.1");
	int addrlen = sizeof(sockaddr_in);
	if(bind (server_fd, (struct sockaddr *)&addr , sizeof(addr)) != 0)
    {
        cout<<"Unable to bind"<<endl;
        return 0;
    }
	int l=listen(server_fd, 3);
	int sockfd;
	pthread_t tid[1000];
	int i=0;
	while(1)
	{
		sockfd = accept(server_fd , (struct sockaddr *)&address , (socklen_t*)&addrlen);
		cout<<"Connected"<<endl;
		if( pthread_create(&tid[i], NULL, processthread, &sockfd) != 0 )
           printf("Failed to create thread\n");
      	int ret = pthread_detach(tid[i]);
      	i++;
	}
	close( server_fd);
	return 0;
}
