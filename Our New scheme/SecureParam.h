#pragma once

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA256;

#include <iostream>
#include <Windows.h>
using namespace std;

// generate a random number
Integer randomGeneration(const int& secureParam);

// generate a random prime of secureParam bits
Integer primeGeneration(const int& secureParam);

// transform from Integer to string
string Integer_to_string(const Integer& integer);

// transform from sting to Integer
Integer string_to_Integer(const string& str);

// define the hash function
Integer hash256Function(const string& str);

// define the fastPower
Integer fastPower(const Integer& x, const Integer& y);

// signature verification function
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature);

void Integer_to_Bytes(Integer num, byte* bytes);

string time_to_string(time_t time);

void AES_CTR_Enc(const string& plain, byte* key, byte* iv, string& cipher);
void AES_CTR_Dec(const string& cipher, const byte* key, const byte* iv, string& recovered);

int hex_to_int(Integer hexNum);

Integer getInverse(Integer a, Integer mod);

Integer exgcd(Integer a, Integer b, Integer& x, Integer& y);

// define the secureParam
const int secureParam = 128;

// mersenne prime
const Integer prime = primeGeneration(secureParam);

// the minimum generator of mersenne prime is 2
const Integer generator = 2;

bool isInterprime(Integer a, Integer b);

Integer GCD(Integer a, Integer b);

void AES_CTR_EncFile(ifstream& plain, const byte* key, const byte* iv, ofstream& cipher);

string Byte_to_String(byte* bytes);

vector<byte> readFile(string filename);

Integer hashFile(string filename);

string byteToHexString(byte b);

struct Phi_u {
	string ctx_str;
	vector<byte> salt;
	string rho_u;
};