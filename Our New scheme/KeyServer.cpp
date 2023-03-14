#include "KeyServer.h"

#include <Windows.h>

#include <assert.h>
#include <sstream>
#include <string>

#include <iostream>
using std::cout;
using std::endl;

using std::string;

#include "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "aes.h"
using CryptoPP::AES;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA256;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::HashFilter;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "oids.h"
using CryptoPP::OID;

#include "SecureParam.h"
extern const int secreParam;

#include "hex.h"
using CryptoPP::HexEncoder;

#if _MSC_VER <= 1200 // VS 6.0
using CryptoPP::ECDSA<ECP, SHA256>;
using CryptoPP::DL_GroupParameters_EC<ECP>;
#endif

KeyServer::KeyServer() {
    //// Scratch result
    //bool result = false;

    //// Generate Keys
    //result = GeneratePrivateKey(CryptoPP::ASN1::secp256r1(), this -> msk);
    //assert(true == result);

    //result = GeneratePublicKey(this -> msk, this -> mpk);
    //assert(true == result);
    //
    //PrintDomainParameters(this -> mpk);


    //// Save key in PKCS#9 and X.509 format    
    //SavePrivateKey( "ec.private.key", this->msk);
    //SavePublicKey( "ec.public.key", this->mpk);

    // Load key in PKCS#9 and X.509 format     
    LoadPrivateKey( "ec.private.key", this->msk);
    LoadPublicKey( "ec.public.key", this->mpk);

    PrintPrivateKey(this -> msk);
    PrintPublicKey(this -> mpk);
}

bool KeyServer::GeneratePrivateKey(const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key)
{
    AutoSeededRandomPool prng;

    key.Initialize(prng, oid);
    assert(key.Validate(prng, 3));

    return key.Validate(prng, 3);
}

bool KeyServer::GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey)
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert(privateKey.Validate(prng, 3));

    privateKey.MakePublicKey(publicKey);
    assert(publicKey.Validate(prng, 3));

    return publicKey.Validate(prng, 3);
}

void KeyServer::PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void KeyServer::PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey& key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void KeyServer::PrintDomainParameters(const DL_GroupParameters_EC<ECP>& params)
{
    cout << endl;

    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;

    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;

    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;

    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl;
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;

    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;

    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;
}

void KeyServer::PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl;
}

void KeyServer::PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey& key)
{
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl;
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void KeyServer::SavePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void KeyServer::SavePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void KeyServer::LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void KeyServer::LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

bool KeyServer::SignMessage(const string& message, string& signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
        new SignerFilter(prng,
            ECDSA<ECP, SHA256>::Signer(this -> msk),
            new StringSink(signature)
        ) // SignerFilter
    ); // StringSource

    return !signature.empty();
}

bool KeyServer::VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature)
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

Integer KeyServer::hardenPassword(string ID_u, Integer alpha, Integer p) {
    string h2;
    SHA256 sha256;

    const Integer m = (this->msk).GetPrivateExponent();
    cout << "m  :" << m << endl;
    string msk;
    std::stringstream ss;
    ss << std::hex << m;
    ss >> msk;
    transform(msk.begin(), msk.end(), msk.begin(), ::toupper);
    cout << msk << endl;
    msk = msk.substr(0, msk.size() - 1);
    cout << "msk: " << msk << endl;

    // Generate Hash Function and its output is in Zp*
    Integer nu;
    bool flag = false;
    while (!flag) {
        StringSource ssa(
            msk + ID_u,
            true,
            new HashFilter(sha256,
                new HexEncoder(new CryptoPP::StringSink(h2)),
                false,
                secureParam / 8) // cut the formoal secureParam / 8 bytes
        );
        cout << endl;
        cout << "h2: " << h2 << endl;

        // convert str to char*, further convert to integer.
        char* a = new char[100];
        int i = 0;

        for (; i < h2.size(); ++i) {
            a[i] = h2[i];
        }

        a[i++] = 'h';
        a[i] = '\0';
        cout << "a: " << a << endl;

        Integer nu_a(a);
        nu += nu_a;
        cout << "nu: " << nu << endl;

        Integer aa = nu;
        Integer bb = p;
        Integer tmp(aa);

        // Ensure gcd(nu, p) = 1
        while (1) {
            tmp = aa % bb;
            if (tmp == 0) {
                break;
            }
            else {
                aa = bb;
                bb = tmp;
            }
        }

        if (bb > 1) {
            flag = false;
            nu += 1;
        }
        else {
            flag = true;
            cout << "gcd == 1" << endl;
        }
    }
    
    //Fast power: alpha^nu
    Integer beta = 1;
    cout << "nu before power: " << nu << endl;
    cout << "alpha before power: " << alpha << endl;

    while (nu > 0) {
        if (nu % 2 == 1) {
            beta = (beta * alpha) % p;
        }
        nu >>= 1;
        alpha = (alpha * alpha) % p;
    }
    cout << "beta before return: " << beta << endl;

    return beta;
}