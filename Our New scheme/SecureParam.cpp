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

//Integer fastPower(Integer base, Integer power) {
//    Integer result = 1;
//
//    while (power > 0) {
//        if (power % 2 == 1) {
//            result = (result * base) % prime;
//        }
//        power >>= 1;
//        base = (base * base) % prime;
//    }
//
//    return result;
//}

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

    //Integer p;
    //ifstream in("Prime_store.txt");

    //if (!in) {   // If the file doesn't exit
    //    AutoSeededRandomPool prng;

    //    AlgorithmParameters params = MakeParameters("BitLength", secureParam)("RandomNumberType", Integer::PRIME);
    //    p.GenerateRandom(prng, params);

    //    ofstream out("Prime_store.txt");

    //    if (out.is_open()) {
    //        out << hex << p;
    //    }

    //    out.close();
    //}
    //else {
    //    in >> hex >>  p;
    //    in.close();
    //}

	return p;
}

string Integer_to_string (const Integer& integer) {
    string str;
    stringstream ss;

    ss << hex << integer;
    ss >> str;
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    //cout << str << endl;
    str = str.substr(0, str.size() - 1);
    //cout << "str: " << str << endl;

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
    //cout << "a: " << a << endl;
    
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

// AES: key length 128, 192, 256
void AES_CTR_Enc (byte* key, string plain, string& cipher, byte* iv) {
    AutoSeededRandomPool prng;

    prng.GenerateBlock(iv, sizeof(iv));

    string encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, 16, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "key: " << encoded << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, 16, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "iv: " << encoded << endl;

    // Encryption
    try
    {
        cout << "plain text: " << plain << endl;

        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, 16, iv);

        StringSource(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter      
        ); // StringSource
    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "cipher text: " << encoded << endl;
    cipher = encoded;
}

void AES_CTR_Dec(byte* key, byte* iv, string cipher, string& plain) {
    string recovered;

    // Pretty print iv
    cout << "iv in the decryption function: ";
    string encoded;
    encoded.clear();
    StringSource(iv, 16, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << "iv: " << encoded << endl;

    cout << "key in the decryption function: ";
    encoded.clear();
    StringSource(key, 16, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    cout << encoded << endl;

    cout << "cipher to be decrypted: " << cipher << endl;
    // decryption
    try
    {
        CTR_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, 16, iv);

        // the streamtransformationfilter removes
        //  padding as required.
        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // streamtransformationfilter
        ); // stringsource

        cout << "recovered text: " << recovered << endl;

        plain = recovered;
    }
    catch (const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

int hex_to_int(Integer hexNum) {
    stringstream ss;

    int decNum;
    ss << std::hex << hexNum;
    ss >> decNum;

    return decNum;
}

// 找到阶为n的最小原根
Integer findPrimitiveRoot(const Integer& n)
{
    if (n <= 2) {
        return -1;
    }
    if (n == 4) {
        return 3;
    }
    Integer phi = n - 1;
    Integer factors[100];
    Integer tmp = phi;
    int count = 0;

    for (Integer i = 2; i * i <= tmp; i++) {
        if (tmp % i == 0) {
            factors[count++] = i;
            while (tmp % i == 0) {
                tmp /= i;
            }
        }
    }

    if (tmp > 1) {
        factors[count++] = tmp;
    }

    for (Integer res = 2; res <= n; res++) {
        bool ok = true;
        for (int i = 0; i < count && ok; i++) {
            ok = (fastPower(res, phi / factors[i]) != 1);
        }
        if (ok) {
            cout << "原根为: " << res << endl;
            return res;
        }
    }

    return -1;
}