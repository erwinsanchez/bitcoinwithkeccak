// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha256.h"

#include "crypto/common.h"

#include <string.h>
#include <string>
#include <vector>
using std::string;
using std::vector;
//#include <windows.h>
// Internal implementation code.
namespace
{
/// Internal SHA-256 implementation.
namespace sha256
{
uint64_t RC[] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
				 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
				 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
				 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
				 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
				 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

int r[5][5] = {{0, 36, 3, 41, 18},
				 {1, 44, 10, 45, 2},
				 {62, 6, 43, 15, 61},
				 {28, 55, 25, 21, 56},
				 {27, 20, 39, 8, 14}};
				 
string final;
				 
uint64_t Rot(uint64_t x, int n) 
{
	n = n%64;
	return ((x>>(64-n))|(x<<n));
}


uint64_t toHex(string data)
{
	uint64_t num = 0;
	uint64_t pow16 = 1;
	string alpha = "0123456789ABCDEF";
	for(int index = data.length() - 1; index >= 0; --index)
	{
		num += alpha.find(toupper(data[index])) * pow16;
		pow16 *= 16;
	}
	return num;
}

string toBinary(uint64_t num)
{
	int exponent = 0;
	double power = 1;
	while(power <= num)
	{
		power = power*2;
		exponent++;
	}		
	string binary = "";
	exponent--;
	power = power/2;
	while(exponent >= 0)
	{
		if(power <= num)
		{
			binary = binary + "1";
			num = num-power;
		}
		else
			binary = binary + "0";
		power = power/2;
		exponent--;
	}
	return binary;
}

void reverseArray(uint64_t byteArray[], int byteLength)
{
	uint64_t temp;
	int start = 0;
	int end = byteLength -1;
	while(end > start)
	{
		temp = byteArray[end];
		byteArray[end] = byteArray[start];
		byteArray[start] = temp;
		end--;
		start++;
	}
}

void toByteArray(uint64_t byteArray[], string binary, int byteLength)
{
	int index = 0;
	int position = 0;
	if(binary.length() % 8 == 0)
	{
		byteArray[index] = 0;
		index++;
	}
	else
	{
		string subString = binary.substr(0,binary.length()%8);
		byteArray[index] = strtoull(subString.c_str(), NULL, 2);
		position = position+binary.length()%8;
		index++;
	}
	while (index != byteLength)
	{
		string subString = binary.substr(position,8);
		byteArray[index] = strtoull(subString.c_str(), NULL, 2);
		position = position+8;
		index++;
	}
}

string reverseHex(uint64_t byteArray[], int byteLength)
{
	string revhex = "";
	for(uint64_t f=0;f<byteLength;f++)
	{
		char temp[10];
		itoa(byteArray[f],temp,16);
		if(temp[1] == '\0')
			revhex = revhex + "0";
		for(int j=0;temp[j]!='\0';j++)
			revhex = revhex + temp[j];
	}
	return revhex;
}


void Round(uint64_t S [5][5], uint64_t RC)
{
	uint64_t C[5];
	uint64_t D[5];
	uint64_t B[5][5];
	
	//theta step
	for (int i = 0; i < 5; i++)
		C[i] = (S[i][0])^(S[i][1])^(S[i][2])^(S[i][3])^(S[i][4]);
	for (int i = 0; i < 5; i++)
		D[i] = C[(i + 4) % 5]^(Rot(C[(i + 1) % 5], 1));
	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < 5; j++)
			S[i][j] = S[i][j]^(D[i]);
	}
	
	//rho and pi steps
	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < 5; j++)
			B[j][(2 * i + 3 * j) % 5] = Rot(S[i][j], r[i][j]);
	}
	
	//chi step
	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < 5; j++)
			S[i][j] = B[i][j]^(~(B[(i + 1) % 5][j])&(B[(i + 2) % 5][j]));
	}
	
	//iota step
	S[0][0] = S[0][0]^(RC);
}

void inline Initialize(uint64_t S[5][5])
{
	
	for(int i = 0; i < 5; i++)
	{
		for(int j = 0; j < 5; j++)
			S[i][j] = 0;
	}
	
	final = "";
	
}

void Keccak(string str)
{
   vector<char> bytes(str.begin(), str.end()); 
   uint64_t S[5][5] = {{0,0,0,0,0},{0,0,0,0,0},{0,0,0,0,0},{0,0,0,0,0},{0,0,0,0,0}};
   
   //padding
   string hex = "";
   for(uint64_t f=0;f<bytes.size();f++)
   {
		char temp[10];
		itoa((uint64_t) bytes.at(f),temp,16);
		for(int j=0;temp[j]!='\0';j++)
			hex = hex + temp[j];
   }
	hex = hex + "01";
	while (((hex.length() / 2) * 8 % 1088) != ((1088 - 8)))
		hex = hex + "00";
	hex = hex + "80";
	int size = (((hex.length() / 2) * 8) / 1088);
	uint64_t arrayM[size][25];
	for(int x = 0; x < 25; x++)
		arrayM[0][x] = 0x0000000000000000;
	int count = 0;
	int j = 0;
	int i = 0;
	for(uint64_t n = 0; n < hex.length(); n++)
	{
		if(j > ((1088)/(64-1)))
		{
			j = 0;
			i++;
		}
		count++;
		if ((count * 4 % 64) == 0) 
		{
			string subString = hex.substr((count - 64 / 4), 16);
			uint64_t num = toHex(subString);
			arrayM[i][j] = num;
			string binary = toBinary(num);
			int byteLength = binary.length()/8+1;
			uint64_t byteArray[byteLength];
			toByteArray(byteArray,binary,byteLength);
			reverseArray(byteArray,byteLength);
			string revhex = reverseHex(byteArray,byteLength);
			while(revhex.length() != 16)
				revhex = revhex + "0";
			num = toHex(revhex);
			arrayM[i][j] = num;
			j++;
		}
	}

	//absorbing phase
	for(int ix = 0; ix < size; ix++)
	{
		for (int i = 0; i < 5; i++)
		{
			for (int j = 0; j < 5; j++)
			{
				if((i + j * 5)<(1088/64))
					S[i][j] = (S[i][j]) | ((arrayM[ix][i + j*5]));
			}
		}
		
		for (int i = 0; i < 24; i++)
			Round(S, RC[i]);	
	}
	
	//squeezing phase
	string Z = "";
	do 
	{
		for (int i = 0; i < 5; i++)
		{
			for (int j = 0; j < 5; j++)
			{
				if ((5*i + j) < (1088 / 64))
				{
					uint64_t num = S[j][i];
					string binary = toBinary(num);
					int byteLength = binary.length()/8+1;
					uint64_t byteArray[byteLength];
					toByteArray(byteArray,binary,byteLength);
					reverseArray(byteArray,byteLength);
					string revhex = reverseHex(byteArray,byteLength);
					int lenn = revhex.length();
					for(int pp = 0; pp < 16-lenn; pp++)
					{
						revhex = revhex + "0";
					}
					Z = Z + revhex.substr(0,16);
				}
					
			}

		}		
		for (int i = 0; i < 24; i++)
			Round(S, RC[i]);
    } 
	while (Z.length() < 64); 
	final = final + Z;
}

string getFinal()
{
	return final;
}

} 
} 


CSHA256::CSHA256() 
{
	sha256::Initialize(S);
}

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
	string toHash ((const char *)data);
	sha256::Keccak(toHash);
    return *this;
	
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    if(sha256::getFinal().length() < OUTPUT_SIZE)
		sha256::Keccak("");
	string subString = sha256::getFinal().substr(0,OUTPUT_SIZE);
	for(int x = 0; x < OUTPUT_SIZE; x++)
		hash[x] = subString.at(x);
}


CSHA256& CSHA256::Reset()
{
	sha256::Initialize(S);
    return *this;
}

