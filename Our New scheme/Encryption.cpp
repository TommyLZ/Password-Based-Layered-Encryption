#include "Encryption.h"

#include "Client.h"

#include "hex.h"
using CryptoPP::HexEncoder;

#include "KeyServer.h"

#include "CloudServer.h"

#include "SecureParam.h"

#include <iostream>
#include <vector>
using namespace std;

void Encryption(const string& psw_u, const string& ID_u) {
	cout << "***************************Encryption Mode***************************" << endl;

	// User input the password & ID
	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;
	CloudServer cloudserver;

	// Password blindness
	Integer alpha;
	alpha = client.blindsPassword();
	cout << "alpha: " << alpha << endl;

	// Password hardening
	Integer beta;
	beta = keyserver.hardenPassword(client.getID(), alpha);
	cout << "beta: " << beta << endl;

	// Digital signature (NIZK)
	string msg_beta = Integer_to_string(beta);
	string signature;
	bool result = false;
	result = keyserver.SignMessage(msg_beta, signature);
	assert(true == result);

	// Authentication
	string token;
	byte* IV = new byte[AES::BLOCKSIZE];
	client.tokenGenForKS(keyserver.mpk, msg_beta, signature, beta, token, IV);
	cout << "the client pass the token: " << token << endl;
	vector<string> response;
	keyserver.tokenVerify(token, IV, response);
}