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
Integer fastPower(Integer base, Integer power);

// signature verification function
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature);

void Integer_to_Bytes(Integer num, byte* bytes);

string time_to_string(time_t time);

void AES_CTR_Enc(byte* key, string plain, string& cihper, byte* iv);
void AES_CTR_Dec(byte* key, byte* iv, string cipher, string& plain);

int hex_to_int(Integer hexNum);

// define the secureParam
const int secureParam = 128;

const Integer prime = primeGeneration(secureParam);

bool isInterprime(Integer a, Integer b);
