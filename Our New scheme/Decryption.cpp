#include "Decryption.h"

#include "Client.h"

#include "hex.h"
using CryptoPP::HexEncoder;

#include "KeyServer.h"

#include "CloudServer.h"

#include "SecureParam.h"

#include <iostream>
#include <vector>
using namespace std;

void Decryption(const string& psw_u, const string& ID_u) {
	cout << endl;
	cout << endl;
	cout << "***************************Decryption Mode***************************" << endl;

	// User input the password & ID
	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;
	CloudServer cloudserver;

	// Password blindness
	Integer alpha;
	alpha = client.blindsPassword();

	// Password hardening
	Integer beta;
	beta = keyserver.hardenPassword(client.getID(), alpha);

	// Digital signature (NIZK)
	string msg_beta = Integer_to_string(beta);
	string signature;
	bool result = false;
	result = keyserver.SignMessage(msg_beta, signature);
	assert(true == result);

	// KeyServer Authentication
	string token_ks;
	byte* IV_ks = new byte[AES::BLOCKSIZE];
	client.tokenGenForKS(keyserver.mpk, msg_beta, signature, beta, token_ks, IV_ks);
	vector<string> response;
	string s_u = keyserver.tokenVerify(token_ks, IV_ks, response);

	// CloudServer Authentication
	string token_cs;
	byte* IV_cs = new byte[AES::BLOCKSIZE];
	byte* IV_dsk = new byte[AES::BLOCKSIZE];
	byte* IV_sk = new byte[AES::BLOCKSIZE];
	vector<string> Phi_u;
	client.tokenGenForCS(beta, s_u, token_cs, IV_dsk, IV_sk, IV_cs, Phi_u);
	cloudserver.tokenVerifyC(token_cs, IV_cs, Phi_u);

	// Client Decryption
	Phi_u = cloudserver.Send(); 
	client.fetchFile(beta, Phi_u, IV_sk, IV_dsk);
}