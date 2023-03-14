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

	result = VerifyMessage(keyserver.mpk, msg_beta, signature);
	cout << "verification result: " << result << endl;
	assert(true == result);

	// credential generation
	

	return 0;
}