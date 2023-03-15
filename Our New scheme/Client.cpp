#include "Client.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::HashFilter;

#include "hex.h"
using CryptoPP::HexEncoder;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecureParam.h"
extern const int secureParam;
extern const Integer prime;

#include "sha.h"
using CryptoPP::SHA256;

#include <cstdlib>
#include <cmath>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

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