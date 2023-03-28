#pragma once

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "integer.h"
using CryptoPP::Integer;

#include "SecureParam.h"
extern struct Phi_u;

#include "sha.h"
using CryptoPP::SHA256;

#include <vector>
#include <Windows.h>
using namespace std;

class Client
{
private:

	Integer r;
	string psw_u;
	string ID_u;

public:

	Client ();
	Client (string psw_u, string ID_u);

	string getPassword();
	string getID();

	Integer rGeneration (Integer prime);

	Integer blindsPassword ();

	void credGen (const ECDSA<ECP, SHA256>::PublicKey& key,  string& message,  string& signature,  Integer& beta, vector<string> & cred);
	
	void tokenGenForKS(const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, string& token, byte* iv);

	void tokenGenForCS(Integer& beta, string& s_u, string& token, byte(&iv_dsk)[16], byte(&iv_sk)[16], byte(&iv_cs)[16], Phi_u* phi_u);

	void fetchFile(Integer beta, Phi_u* phi_u, byte(&iv_sk)[16], byte(&iv_dsk)[16]);
};