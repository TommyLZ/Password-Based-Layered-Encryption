#include "KeyServer.h"

#include "aes.h"
using CryptoPP::AES;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::HashFilter;

#include "hex.h"
using CryptoPP::HexEncoder;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "oids.h"
using CryptoPP::OID;

#include "sha.h"
using CryptoPP::SHA256;

#include "SecureParam.h"
extern const int secreParam;
extern const Integer prime;

#include <assert.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <Windows.h>

using std::cout;
using std::endl;
using std::string;

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

    //// Save key in PKCS#9 and X.509 format    
    //SavePrivateKey( "ec.private.key", this->msk);
    //SavePublicKey( "ec.public.key", this->mpk);

    //Load key in PKCS#9 and X.509 format     
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

// Generate Hash Function and its output is in Zp*
Integer KeyServer::hardenPassword(string ID_u, Integer alpha) {
    string msk = Integer_to_string((this->msk).GetPrivateExponent());

    Integer nu = hash256Function(msk + ID_u);
    cout << "Hash of key server: " << nu << endl;
    
    // Determine the interprime
    while (!isInterprime(nu, prime)) {
        nu += 11;
    }

    Integer beta = fastPower(alpha, nu);

    return beta;
}

bool KeyServer::SignMessage(const string& message, string& signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
        new SignerFilter(prng,
            ECDSA<ECP, SHA256>::Signer(this->msk),
            new StringSink(signature)
        ) // SignerFilter
    ); // StringSource

    return !signature.empty();
}

void KeyServer::store (string& ID_u, string& s_u, string& cred_ks) {
    ofstream out("KS_store.txt");

    if (out.is_open()) {
        out << "user_identity: " << ID_u 
            << "    s_u:" << s_u
            << "    credential: " << cred_ks;
    }

    out.close();
}

void KeyServer::tokenVerify(string& token, vector<string> & KSresponse) {
    ifstream in("KS_store.txt");
    string s;

    in >> s;
    
    cout << "read the file: " << s << endl;
}