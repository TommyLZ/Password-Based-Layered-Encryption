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
#include <integer.h>
#include <math.h>
#include <string>
#include <sstream>
#include <vector>
#include <Windows.h>
#include <sys/timeb.h>

using namespace std;
using namespace CryptoPP;

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

// r is randomly generated for secure protection
Integer Client::rGeneration (Integer prime) {
    AutoSeededRandomPool prng;
    Integer r;

    const Integer mini = 0;
    const Integer maxi = prime - 1;
    r.Randomize(prng, mini, maxi);
    
    bool flag = true;
    while (GCD(r, prime) != 1) {
        r.Randomize(prng, mini, maxi);
    }

    return r;
}

Integer Client::blindsPassword() {

    Integer H(hash256Function(this->psw_u));

    // blind the value to against dictionary guessing attack
    Integer blind_value = fastPower(H, this -> r);

    Integer a1 = fastPower(H, this->r);
    Integer a2 = fastPower(a1, this->r.InverseMod(prime));

    cout << "this->r" << this->r << endl;
    cout << "the value of H: " << hex << H << endl;
    cout << "blind_value" << blind_value << endl;
    cout << "Integer a2: " << hex << a1 << endl;
    cout << "Integer a2: " << hex << a2  << endl;

    return blind_value;
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

    cout << "credential for key server: " << cred_ks << endl;
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

    // Pretty print key
    string encoded;
    encoded.clear();
    StringSource(ase_key, 16, true, new HexEncoder(new StringSink(encoded)));
    cout << "key: " << encoded << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, 16, true, new HexEncoder(new StringSink(encoded)));
    cout << "iv: " << encoded << endl;
    
    cout << "plain text: " << this->ID_u + str_time << endl;

	AES_CTR_Enc(this->ID_u + str_time, ase_key, iv, token);
}