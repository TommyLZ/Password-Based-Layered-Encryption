#include "SecureParam.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::SignatureVerificationFilter;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "sha.h"
using CryptoPP::SHA256;

#include "hex.h"
using CryptoPP::HexEncoder;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

#include <fstream>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <sys/timeb.h>
#include <Windows.h>
using namespace std;

Integer fastPower(const Integer& x, const Integer& y)
{
    Integer res = 1;
    Integer x_mod_p = x % prime;
    Integer y_copy = y;

    while (y_copy > 0) {
        if (y_copy.IsOdd()) {
            res = (res * x_mod_p) % prime;
        }
        y_copy >>= 1;
        x_mod_p = (x_mod_p * x_mod_p) % prime;
    }

    return res;
}

Integer randomGeneration(const int& secureParam) {
    AutoSeededRandomPool prng;
    Integer p;

    AlgorithmParameters params = MakeParameters("BitLength", secureParam);
    p.GenerateRandom(prng, params);

    return p;
}

Integer primeGeneration (const int& secureParam) {

    char a[100] = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFh";
    Integer p(a);

	return p;
}

string Integer_to_string (const Integer& integer) {
    string str;
    stringstream ss;

    ss << hex << integer;
    ss >> str;
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    str = str.substr(0, str.size() - 1);

    return str;
}

Integer string_to_Integer (const string& str) {
    // Firstly, convert string to char*
    char* a = new char[200];
    int i = 0;

    for (; i < str.size(); ++i) {
        a[i] = str[i];
    }

    a[i++] = 'h';
    a[i] = '\0';
    
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
            new HexEncoder(new CryptoPP::StringSink(value))
        )
    );
    
    // reducing the value into the cyclic group
    return fastPower(generator, string_to_Integer(value));
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

void Integer_to_Bytes(Integer num, byte* bytes)
{
    for (int i = 0, j= num.ByteCount()-1, k=0; i < num.ByteCount(); ++i, --j, ++k) {
        bytes[k] = num.GetByte(j);
    }
}

string time_to_string (time_t time) {
    tm curr_tm{};
	char time_string[100];

	localtime_s(&curr_tm ,&time);
	
	strftime(time_string, 50, "%X", &curr_tm);

    return time_string;
}

int hex_to_int(Integer hexNum) {
    stringstream ss;

    int decNum;
    ss << std::hex << hexNum;
    ss >> decNum;

    return decNum;
}

void AES_CTR_Enc(const string& plain, const byte* key, const byte* iv, string& cipher) {
    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
}

void AES_CTR_Dec(const string& cipher, const byte* key, const byte* iv, string& recovered) {
    CTR_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    // Pretty print key
    string encoded;
    encoded.clear();
    StringSource(key, 16, true, new HexEncoder(new StringSink(encoded)));
    cout << "key in decryption: " << encoded << endl;

    StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
}

Integer GCD(Integer a, Integer b)
{
    if (b == Integer::Zero())
        return a;
    else
        return GCD(b, a % b);
}