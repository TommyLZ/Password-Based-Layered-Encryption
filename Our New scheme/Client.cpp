#include "Client.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::StreamTransformationFilter;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecureParam.h"
extern const int secureParam;
extern const Integer prime;

#include "sha.h"
using CryptoPP::SHA256;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

#include "assert.h"

#include <cstdlib>
#include <cmath>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <Windows.h>
#include <sys/timeb.h>

using namespace std;

Client::Client() {}

Client::Client(string psw_u, string ID_u): psw_u(psw_u), ID_u(ID_u){
    std::cout << "prime: " << hex << prime << endl;
    this -> r = rGeneration(prime);
    std::cout << "r: " << hex << r << endl;
}

string Client::getPassword () {
    return psw_u;
}

string Client::getID() {
    return ID_u;
}

Integer Client::rGeneration (Integer prime) {
    AutoSeededRandomPool prng;
    Integer r;

    const Integer mini = 1;
    const Integer maxi = prime;
    r.Randomize(prng, mini, maxi);

    return r;
}

Integer Client::blindsPassword() {
    Integer H(hash256Function(this->psw_u));
    cout << "hash value of client: " << H << endl;
    
    Integer alpha = fastPower(H, this->r);

    return alpha;
}

void Client::credGen (const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature, const Integer& beta, vector<string>& cred) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    string s_u = Integer_to_string(randomGeneration(secureParam));
    // beta^(1/r) = (beta^r)^(-1)
    // using Fermat's little theorem, it is (beta)^(p + r -1)
    string beta_inverse = Integer_to_string(fastPower(beta, prime + this->r - 1));
    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));

    string cred_ks = Integer_to_string(hash256Function(pwd_u_hat + this -> ID_u));
    string cred_cs = Integer_to_string(hash256Function(this->ID_u + pwd_u_hat + s_u));

    cred.push_back(this->ID_u);
    cred.push_back(cred_ks);
    cred.push_back(s_u);
    cred.push_back(cred_cs);
}

void Client::tokenGenForKS(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature, const Integer& beta, string& token) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    // beta^(1/r) = (beta^r)^(-1)
    // using Fermat's little theorem, it is (beta)^(p + r -1)
    string beta_inverse = Integer_to_string(fastPower(beta, prime + this->r - 1));
    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));

    // To use AES, the length needs to be 128 bits.
    Integer omega_ks = hash256Function(pwd_u_hat + this->ID_u);

    byte* ase_key = new byte [16];

    cout << "omega_ks: " << omega_ks << endl;

    Integer_to_Bytes(omega_ks, ase_key);

    cout << endl;

	timeb t;
	ftime(&t);
	string str_time = time_to_string(t.time);

    cout << "t.time: " << t.time << endl;
    cout << "str_time" << str_time << endl;

	token = AES_CTR_Enc(ase_key, this->ID_u + str_time);
}

