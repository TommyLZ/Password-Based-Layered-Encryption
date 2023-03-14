#include "SecureParam.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "sha.h"
using CryptoPP::SHA256;

#include "hex.h"
using CryptoPP::HexEncoder;

#include <numeric>
#include <sstream>
#include <Windows.h>
using namespace std;

// Realize the primeGeneration function
Integer primeGeneration (const int& secureParam) {
	AutoSeededRandomPool prng;
	Integer p;

	AlgorithmParameters params = MakeParameters("BitLength", secureParam)("RandomNumberType", Integer::PRIME);
	p.GenerateRandom(prng, params);

	return p;
}

string Integer_to_string (const Integer& integer) {
    string str;
    stringstream ss;

    ss << hex << integer;
    ss >> str;
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    cout << str << endl;
    str = str.substr(0, str.size() - 1);
    cout << "str: " << str << endl;

    return str;
}

Integer string_to_Integer (const string& str) {
    // Fisrt convert string to char*
    char* a = new char[100];
    int i = 0;

    for (; i < str.size(); ++i) {
        a[i] = str[i];
    }

    a[i++] = 'h';
    a[i] = '\0';
    cout << "a: " << a << endl;
    
    Integer H(a);

    return H;
}

Integer hash256Function (const string& str) {
	string value;
    SHA256 sha256;

    StringSource ss(
        str,
        true,
        new HashFilter(sha256,
            new HexEncoder(new CryptoPP::StringSink(value)),
            false,
            secureParam / 8) // cut the formoal secureParam / 8 bytes
    );

    return string_to_Integer(value);
}

Integer fastPower (Integer base, Integer power) {
    Integer result = 1;

    while (power > 0) {
        if (power % 2 == 1) {
            result = (result * base) % prime;
        }
        power >>= 1;
        base = (base * base) % prime;
    }

    return result;
}

bool isInterprime(Integer a, Integer b) {
    if (a == 1 || b == 1)
        return true;

    Integer t;
    while (true) {
        t = a % b;
        if (t == 0) {
            break;
        }
        else {
            a = b;
            b = t;
        }
    }

    if (b > 1) {
        return false;
    }
    else {
        return true;
    }

    return false;
}

bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature)
{
    bool result = false;

    StringSource(signature + message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP, SHA256>::Verifier(key),
            new ArraySink((byte*)&result, sizeof(result))
        ) // SignatureVerificationFilter
    );

    return result;
}