#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <string>
#include <string.h> 
#include <cstring>
#include <cstdlib>
#include <sys/wait.h>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <fstream> 
#include <algorithm>
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
			hexkey.firstb = stoul(hex);
			hex = "";
		}
		if(i == 16)
		{
			hexkey.secondb = stoul(hex);
			hex = "";
		}
		if(i == 24)
		{
			hexkey.thirdb = stoul(hex);
			hex = "";
		}
		if(i == 32)
		{
			hexkey.fourthb = stoul(hex);
			hex = "";
		}
		if(i == 40)
		{
			hexkey.fifthb = stoul(hex);
			hex = "";
		}
		if(i == 48)
		{
			hexkey.sixthb = stoul(hex);
			hex = "";
		}
		if(i == 56)
		{
			hexkey.seventhb = stoul(hex);
			hex = "";
		}
		if(i == 64)
		{
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

ll DeffieHellman(ll g, ll p, ll y)
{
	return (ll)((ll)(pow(g,y))%p);
}

void desdecrypt(ll k1, ll k2, ll k3, Message msg1, FILE* fp, int sockfd)
{
	struct deskey key1, key2, key3;
	string K1 = decToStr(k1);
	string K2 = decToStr(k2);
	string K3 = decToStr(k3);

	key1 = convertToHex(K1);
	key2 = convertToHex(K2);
	key3 = convertToHex(K3);

    DES_cblock cb1 = {(unsigned char)key1.firstb,(unsigned char)key1.secondb,(unsigned char)key1.thirdb,(unsigned char)key1.fourthb,(unsigned char)key1.fifthb,(unsigned char)key1.sixthb,(unsigned char)key1.seventhb,(unsigned char)key1.eighthb};
   	DES_cblock cb2 = {(unsigned char)key2.firstb,(unsigned char)key2.secondb,(unsigned char)key2.thirdb,(unsigned char)key2.fourthb,(unsigned char)key2.fifthb,(unsigned char)key2.sixthb,(unsigned char)key2.seventhb,(unsigned char)key2.eighthb};
   	DES_cblock cb3 = {(unsigned char)key3.firstb,(unsigned char)key3.secondb,(unsigned char)key3.thirdb,(unsigned char)key3.fourthb,(unsigned char)key3.fifthb,(unsigned char)key3.sixthb,(unsigned char)key3.seventhb,(unsigned char)key3.eighthb};

	// DES_cblock cb11 = {0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
   	// DES_cblock cb12 = {0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
   	// DES_cblock cb13 = {0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE, 0xAE };
   
   	DES_key_schedule ks1,ks2,ks3;
   	DES_cblock cblock1 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// Message msg1;
	// bzero(&msg1,sizeof(struct Message));
	// cout<<"before rcve "<<msg1.allMsg.encmsg.encmessage<<endl;
	//send(sockfd,&msg1,sizeof(struct Message),0);
	//cout<<"cipher text \n"<<msg1.allMsg.encmsg.encmessage<<endl;

	char text[msg1.allMsg.encmsg.original_len];
//	memset(text,'\0',msg1.allMsg.encmsg.original_len);
	for(int i =0; i<msg1.allMsg.encmsg.original_len; i++)
	{
		text[i] ='\0';
	}

	if (DES_set_key(&cb1, &ks1)<0 ||
        DES_set_key(&cb2, &ks2)<0 ||
         DES_set_key(&cb3, &ks3)<0 ) {
      printf("Key error, exiting ....\n");
      return;
   }

	memset(cblock1,0,sizeof(DES_cblock));
    DES_set_odd_parity(&cblock1);

    DES_ede3_cbc_encrypt((const unsigned char*)msg1.allMsg.encmsg.encmessage, (unsigned char*)text, msg1.allMsg.encmsg.buf_len, &ks1, &ks2, &ks3, &cblock1, DES_DECRYPT);
	
	//text[msg1.allMsg.encmsg.original_len-1] = '\0';
	// for(int i=0; i<msg1.allMsg.encmsg.original_len; i++)
	// {
	// 	cout<<"i "<<i<<" "<<text[i]<<endl;
	// }
    printf("Decrypted : %s\n",text);
	fwrite(text, sizeof(char), sizeof(text), fp);
	// int k=0;
	// send(sockfd,&k, sizeof(k),0);
	return;
}

int main()
{
    int sockfd = socket( AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in  serv_addr, client_addr;
	bzero(&serv_addr, sizeof(serv_addr));
	bzero(&client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(0);
	client_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
	if(bind(sockfd, (struct sockaddr*) &client_addr, sizeof(struct sockaddr_in)) != 0)
	{
    	cout<<"Unable to bind"<<endl; 
    	return 0;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(sportadd);
	serv_addr.sin_addr.s_addr = inet_addr("127.0.01");
	if(connect(sockfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0)
	{
		cout<<"unbale to connect"<<endl;
        return 0;
	}
    while(1)
    {
		ll k1, k2, k3;
		struct Message msg;
		int choice;
		cout<<"Enter choice\n 1. Session Key.\n 2. Request to server.\n 3. To Disconnect."<<endl;
		cin>>choice;

		if(choice == 1)
		{
			choice = 0;
			msg.header.code = opcode["PUBKEY"];
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);

			struct PubKey pk1;
			pk1.g = 9;
			pk1.p = 23;
			pk1.Y = DeffieHellman(9,23,4);
			msg.allMsg.pubkey = pk1;
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			recv(sockfd, (struct Message *)&msg, sizeof(struct Message), 0);
			k1 = DeffieHellman(msg.allMsg.pubkey.Y, msg.allMsg.pubkey.p, 4);
			cout<<"k1 "<<k1<<endl;

			struct PubKey pk2;
			pk2.g = 5;
			pk2.p = 23;
			pk2.Y = DeffieHellman(5,23,4);
			msg.allMsg.pubkey = pk2;
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			k2 = DeffieHellman(msg.allMsg.pubkey.Y, msg.allMsg.pubkey.p, 4);
			cout<<"k2 "<<k2<<endl;

			struct PubKey pk3;
			pk3.g = 7;
			pk3.p = 23;
			pk3.Y = DeffieHellman(7,23,4);
			msg.allMsg.pubkey = pk3;
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
			k3 = DeffieHellman(msg.allMsg.pubkey.Y, msg.allMsg.pubkey.p, 4);
			cout<<"k3 "<<k3<<endl;

			// fflush(stdin);
			// fflush(stdout);
		}
		else if(choice == 2)
		{
			choice = 0;
			bzero(&msg,sizeof(msg));
			msg.header.code = opcode["REQSERV"];
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);

			cout<<"Enter file name"<<endl;
			string filename;
			cin>>filename;
			struct ReqServ reqserv;
			strcpy(reqserv.filename, filename.c_str());

			msg.allMsg.reqserv = reqserv;
		//	cout<<"size of msg "<<sizeof(msg)<<endl;
			send(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);;
			bzero(&msg,sizeof(msg));
			recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
		//	cout<<"size of msg "<<sizeof(msg)<<endl;
			if(msg.header.code == opcode["DISCONNECT"])
			{
				cout<<msg.allMsg.disconnect.message<<endl;
				fflush(stdin);
			    fflush(stdout);
				continue;
			}
			else if(msg.header.code == opcode["ENCMSG"])
			{
				FILE *fp = fopen(reqserv.filename,"wb");

				bzero(&msg, sizeof(msg));
			//	memset(msg.allMsg.encmsg.encmessage,'\0',sizeof(msg.allMsg.encmsg.encmessage));
				for(int i=0; i<sizeof(msg.allMsg.encmsg.encmessage); i++)
				{
					msg.allMsg.encmsg.encmessage[i] = 0;
				}
				recv(sockfd,(struct Message *)&msg, sizeof(struct Message), 0);
				ll size = msg.allMsg.encmsg.file_size;
				cout<<"size "<<size<<endl;
				while(size > 0)
				{
					Message msg1;
					bzero(&msg1, sizeof(msg1));
					for(int i=0; i<sizeof(msg1.allMsg.encmsg.encmessage); i++)
					{
						msg1.allMsg.encmsg.encmessage[i] = 0;
					}
					recv(sockfd,&msg1, sizeof(struct Message), 0);
					cout<<"size of message "<<sizeof(msg1)<<endl;
					desdecrypt(k1,k2,k3,msg1,fp,sockfd);
					size = size-msg1.allMsg.encmsg.original_len;
					//cout<<"before false recve inner"<<endl;
					// int t;
					// recv(sockfd,&t,sizeof(t),0);
					cout<<"hello wihtin size "<<size<<endl;
				}
				fclose(fp);
			//	cout<<"before false recve"<<endl;
				// int m;
				Message msg3;
				recv(sockfd,(struct Message *)&msg3, sizeof(struct Message),0);
				cout<<msg3.allMsg.reqcom.message<<endl;
			}
			else
			{
				cout<<"bad"<<endl;
			}
			// fflush(stdin);
			// fflush(stdout);
		}
		else if(choice == 3)
		{
			Message msg2;
			msg2.header.code = opcode["DISCONNECT"];
			send(sockfd,&msg2, sizeof(struct Message), 0);
		//	recv(sockfd,&msg2, sizeof(struct Message), 0);
			cout<<"Disconnected"<<endl;
		//	close(sockfd);
			return 0;
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
    return 0;
}