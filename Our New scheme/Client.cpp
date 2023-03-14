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

#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cmath>

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