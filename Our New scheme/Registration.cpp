#include "Registration.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::HashFilter;

#include "hex.h"
using CryptoPP::HexEncoder;

#include "integer.h"
using CryptoPP::Integer;

#include "SecureParam.h"
extern const int secureParam;
extern const Integer prime;

#include "sha.h"
using CryptoPP::SHA256;

#include <cryptlib.h>
#include <iostream>
#include <Windows.h>
#include <vector>
#include <sstream>
#include <string>

using namespace std;

void Registration (const string& psw_u, const string& ID_u) {
	cout << "***************************Registration Mode***************************" << endl;
	
	// User input the password & ID
	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;
	CloudServer cloudserver;

	// Password blindness
	Integer alpha = client.blindsPassword();

	// Password hardening
	Integer beta = keyserver.hardenPassword(client.getID(), alpha);
	
	// Digital signature (NIZK)
	string msg_beta = Integer_to_string(beta);
	string signature;
	bool result = false;
	result = keyserver.SignMessage(msg_beta, signature);
	assert(true == result);

	// Credential Generation
	vector<string> cred;
	client.credGen(keyserver.mpk, msg_beta, signature, beta, cred);
	keyserver.store(cred[0], cred[1], cred[2]);
	cloudserver.store(cred[0], cred[3]);
}