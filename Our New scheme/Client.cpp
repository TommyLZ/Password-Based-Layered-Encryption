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
#include <math.h>
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

    const Integer mini = 0;
    const Integer maxi = prime - 1;
    r.Randomize(prng, mini, maxi);

    return r;
}

Integer Client::blindsPassword() {

    Integer H(hash256Function(this->psw_u));
    cout << "hash value of client: " << H << endl;

    H = fastPower(generator, H);

    return fastPower(H, this->r);
}

void Client::credGen (const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, vector<string>& cred) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    string s_u = Integer_to_string(randomGeneration(secureParam));

    Integer r_inverse = this->r.InverseMod(prime);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    string cred_ks = Integer_to_string(hash256Function(pwd_u_hat + this -> ID_u));
    string cred_cs = Integer_to_string(hash256Function(this->ID_u + pwd_u_hat + s_u));

    cred.push_back(this->ID_u);
    cred.push_back(s_u);
    cred.push_back(cred_ks);
    cred.push_back(cred_cs);
}

void Client::tokenGenForKS(const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, string& token, byte* iv) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    Integer r_inverse = this->r.InverseMod(prime);
    cout << r_inverse * this->r % prime << endl;
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    Integer omega_ks = hash256Function(pwd_u_hat + this->ID_u);
    byte* ase_key = new byte [16];

    cout << "omega_ks: " << omega_ks << endl;

    Integer_to_Bytes(omega_ks, ase_key);

	timeb t;
	ftime(&t);
	string str_time = time_to_string(t.time);

    cout << "t.time: " << t.time << endl;
    cout << "str_time" << str_time << endl;
    
	AES_CTR_Enc(ase_key, this->ID_u + str_time, token, iv);
}