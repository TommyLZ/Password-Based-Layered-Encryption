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
    string h1;
    SHA256 sha256;

    StringSource ss(
        this -> psw_u,
        true,
        new HashFilter(sha256,
            new HexEncoder(new CryptoPP::StringSink(h1)),
            false,
            secureParam / 8) // cut the formoal secureParam / 8 bytes
    );
    cout << endl;
    cout << "h1: " << h1 << endl;

    // convert str to char*, further convert to integer.
    char* a = new char[100];
    int i = 0;

    for (; i < h1.size(); ++i) {
        a[i] = h1[i];
    }

    a[i++] = 'h';
    a[i] = '\0';
    cout << "a: " << a << endl;

    Integer H1(a);
    cout << "H1: " << H1 << endl;
    
    Integer alpha = 1;
    for (int i = 0; i < this->r; ++i) {
        alpha = alpha * H1 % prime;
    }

    return alpha;
}