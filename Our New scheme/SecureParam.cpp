#include "SecureParam.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

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

/************************************Format transformation Begin****************************/
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

string time_to_string(time_t time) {
    tm curr_tm{};
    char time_string[100];

    localtime_s(&curr_tm, &time);

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

void Integer_to_Bytes (Integer num, byte* bytes)
{
    int k = 0;
    for (int i = 0, j = num.ByteCount() - 1; i < num.ByteCount(); ++i, --j, ++k) {
        bytes[k] = num.GetByte(j);
    }

    // Padding
    while (k < secureParam / 8) {
        bytes[k] = 0;
        k++;
    }
}

string Byte_to_String(byte* bytes) {
    //string str = "";
    //for (int i = 0; i < sizeof(bytes); ++i) {
    //    str += (int)bytes[i];
    //}
    //return str;

    //stringstream ss;
    //for (int i = 0; i < sizeof(bytes) / sizeof(byte); ++i) {
    //    ss << hex << (int)bytes[i];
    //}
    //
    //return ss.str();

    return std::string(reinterpret_cast<const char*>(bytes), sizeof(bytes));
}

string byteToHexString(byte b) {
    stringstream ss;
    ss << setfill('0') << setw(2) << hex << (int)b;
    return ss.str();
}

/********************************Format transformation End*******************************/


/***************************Hash the data & file (using SHA256)**************************/
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

vector<byte> readFile (string filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<byte> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    else {
        return std::vector<byte>();
    }
}

Integer hashFile (string filename) {
    vector<byte> data = readFile(filename);
    SHA256 hash;
    vector<byte> digest(hash.DigestSize());
    hash.Update(data.data(), data.size());
    hash.Final(digest.data());

    string str = "";
    for (const byte& b : digest) {
        str += byteToHexString(b);
    }

    cout << "the hash value of the file: " << str << endl;

    return fastPower(generator, string_to_Integer(str));
}



/***************************Hash the data & file (using SHA256)**************************/

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


void AES_CTR_Enc(const string& plain, const byte* key, const byte* iv, string& cipher) {
    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
}

void AES_CTR_Dec(const string& cipher, const byte* key, const byte* iv, string& recovered) {
    cout << "iv used in decryption: ";
    for (int i = 0; i < 16; ++i) {
        cout << (int)iv[i];
    }
    cout << endl;


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