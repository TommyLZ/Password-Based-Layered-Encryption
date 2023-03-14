#include "Client.h"

#include "KeyServer.h"

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

#include <iostream>
#include <Windows.h>
#include <vector>
#include <sstream>
#include <string>

using namespace std;

int main() {
	cout << "************************Encryption Mode************************" << endl;

	// User input the password & ID
	string psw_u = "f4520tommy";
	string ID_u = "Wolverine";

	// Object instantiation
	Client client(psw_u, ID_u);
	KeyServer keyserver;

	// Password blindness
	Integer alpha;
	alpha = client.blindsPassword();
	cout << "alpha: " << alpha << endl;

	// 
	Integer beta;
	beta = keyserver.hardenPassword(client.getID(), alpha, prime);
	cout << "beta: " << beta << endl;
	
	string msg_beta;
	std::stringstream ss;
	ss << std::hex << beta;
	ss >> msg_beta;
	transform(msg_beta.begin(), msg_beta.end(), msg_beta.begin(), ::toupper);
	cout << msg_beta << endl;
	msg_beta = msg_beta.substr(0, msg_beta.size() - 1);
	cout << "msg_beta: " << msg_beta << endl;

	bool result = false;
	string signature;
	result = keyserver.SignMessage(msg_beta, signature);
	assert(true == result);

	result = keyserver.VerifyMessage(keyserver.mpk, msg_beta, signature);
	assert(true == result);



	return 0;
}