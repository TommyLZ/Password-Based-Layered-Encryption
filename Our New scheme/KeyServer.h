#pragma once

#include <Windows.h>

#include <assert.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "osrng.h"
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

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "oids.h"
using CryptoPP::OID;

#if _MSC_VER <= 1200 // VS 6.0
using CryptoPP::ECDSA<ECP, SHA256>;
using CryptoPP::DL_GroupParameters_EC<ECP>;
#endif

class KeyServer
{
private:
	ECDSA<ECP, SHA256>::PrivateKey msk;

public:
	ECDSA<ECP, SHA256>::PublicKey mpk;

	KeyServer();

	bool GeneratePrivateKey(const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key);
	bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey);

	void SavePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key);
	void SavePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key);
	void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key);
	void LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key);

	void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey& key);
	void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey& key);
	void PrintDomainParameters(const DL_GroupParameters_EC<ECP>& params);
	void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey& key);
	void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey& key);

	bool SignMessage(const string& message, string& signature);
	bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature);

	Integer hardenPassword(string ID_u, Integer alpha, Integer p);
};

