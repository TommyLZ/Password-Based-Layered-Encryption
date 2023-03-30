#include "Client.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "files.h"

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::StreamTransformationFilter;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "pwdbased.h"

#include "SecureParam.h"
extern const int secureParam;
extern const Integer modulo;
extern const Integer generator;
extern const Integer order;

#include "sha.h"
using CryptoPP::SHA256;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

#include "assert.h"

#include <cstdlib>
#include <cmath>
#include <fstream>
#include <iostream>
#include <integer.h>
#include <math.h>
#include <cstring>
#include <sstream>
#include <vector>
#include <sys/timeb.h>

using namespace std;
using namespace CryptoPP;

Client::Client() {}

Client::Client(string psw_u, string ID_u): psw_u(psw_u), ID_u(ID_u){
    this -> r = rGeneration(order);
}

string Client::getPassword () {
    return psw_u;
}

string Client::getID() {
    return ID_u;
}

// r is randomly select from [1, order-1]
Integer Client::rGeneration (Integer order) {
    AutoSeededRandomPool prng;
    Integer r;

    const Integer mini = 0;
    const Integer maxi = order - 1;
    r.Randomize(prng, mini, maxi);

    return r;
}

Integer Client::blindsPassword() {
    Integer H(hash256Function(this->psw_u));

    // blind the value
    Integer blind_value = fastPower(H, this -> r);

    return blind_value;
}

void Client::credGen (const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, vector<string>& cred) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    string s_u = Integer_to_string(randomGeneration(secureParam));

    Integer r_inverse = this->r.InverseMod(order);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    string cred_ks = Integer_to_string(hash256Function(pwd_u_hat + this -> ID_u));

    string cred_cs = Integer_to_string(hash256Function(this->ID_u + pwd_u_hat + s_u));

    cred.push_back(this->ID_u);
    cred.push_back(s_u);
    cred.push_back(cred_ks);
    cred.push_back(cred_cs);
}

void Client::tokenGenForKS(const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, string& token, byte (&iv)[16]) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    Integer r_inverse = this->r.InverseMod(order);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    Integer omega_ks = hash256Function(pwd_u_hat + this->ID_u);
    byte* ase_key = new byte [16];

    Integer_to_Bytes(omega_ks, ase_key);

	timeb t;
	ftime(&t);
	string str_time = time_to_string(t.time);

    // Pretty print key
    string encoded;
    encoded.clear();
    StringSource(ase_key, 16, true, new HexEncoder(new StringSink(encoded)));
    cout << "key: " << encoded << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, 16, true, new HexEncoder(new StringSink(encoded)));
    cout << "iv: " << encoded << endl;
    
    cout << "plain text: " << this->ID_u + str_time << endl;

    // Encryption
	AES_CTR_Enc(this->ID_u + str_time, ase_key, iv, token);
} 


void Client::tokenGenForCS(Integer& beta, string& s_u, string& token, byte(&iv_dsk)[16], byte(&iv_sk)[16], byte(&iv_cs)[16], Phi_u* phi_u) {
    Integer r_inverse = this->r.InverseMod(order);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    Integer omega_cs = hash256Function(this->ID_u + pwd_u_hat + s_u);

/***************************************File Encryption***************************************/
    // encrypt key & iv for encrytion
    byte sk[CryptoPP::AES::DEFAULT_KEYLENGTH];
    // iv set with sk
    AutoSeededRandomPool prng;
    prng.GenerateBlock(sk, sizeof(sk));
    prng.GenerateBlock(iv_sk, 16);

    string print;
    print.clear();
    StringSource(iv_sk, 16, true, new HexEncoder(new StringSink(print)));

    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(sk, AES::DEFAULT_KEYLENGTH, iv_sk);

    // read and write the file
    ifstream ifs("bigdata.txt", std::ios::binary);
    ofstream ofs("bigdata_encrypted.txt", std::ios::binary);

    // encrypt the file
    FileSource(ifs, true, new StreamTransformationFilter(e, new FileSink(ofs)));
    cout << "File Encryption Finished!" << endl;

    ifs.close();
    ofs.close();

/********************************************Key Derivation********************************************/
    string password = pwd_u_hat;
    cout << "pwd_u_hat in encryption phase: " << pwd_u_hat << endl;

    // generate the salt
    AutoSeededRandomPool rng;
    vector<byte> salt(16);
    rng.GenerateBlock(&salt[0], salt.size());
    
    int iterationCount = 10000;
    int keySize = 16; // byte

    // generate the derived key dsk
    SecByteBlock dsk(keySize); // variant to store the key
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
    pbkdf2.DeriveKey(dsk, dsk.size(), 0x00, (byte*)password.data(), password.size(), &salt[0], salt.size(), iterationCount);
    // store the derived secret key
    string dsk_str;
    StringSource(dsk, dsk.size(), true, new HexEncoder(new StringSink(dsk_str)));
/**************************************Encrypt the Symmetric Key**************************************/
    // iv set with dsk
    AutoSeededRandomPool srng;
    srng.GenerateBlock(iv_dsk, 16);

    CTR_Mode<AES>::Encryption ee;
    ee.SetKeyWithIV(sk, AES::DEFAULT_KEYLENGTH, iv_dsk);

    // encrypt the symmetric key
    //string str_sk = Byte_to_String(sk);
    string str_sk;
    //print.clear();
    StringSource(sk, sizeof(sk), true, new HexEncoder(new StringSink(str_sk)));
    cout << "加密阶段: 需要加密的明文sk: " << str_sk << endl;
    string ctx_sk;
    AES_CTR_Enc(str_sk, dsk, iv_dsk, ctx_sk);

    string ctx_sk_encoded;
    StringSource(ctx_sk, true, new HexEncoder(new StringSink(ctx_sk_encoded)));
    cout << "加密阶段：加密sk得到的密文: " << ctx_sk_encoded << endl;
    cout << "加密阶段：加密sk使用的向量iv_dsk: ";
    for (int i = 0; i < sizeof(iv_dsk) / sizeof(iv_dsk[0]); ++i) {
        cout << hex << (int)iv_dsk[i];
    }
    cout << endl;
    cout << "加密阶段：加密sk使用的密钥dsk: ";
    for (int i = 0; i < dsk.size(); ++i) {
        cout << hex << (int)dsk[i];
    }
    cout << endl;
/**********************************Authenticaiton Token Generation**********************************/
    // setting the IV
    AutoSeededRandomPool ssrng;
    ssrng.GenerateBlock(iv_cs, sizeof(iv_cs));
    // key format transformation
    byte* ase_key = new byte[16];
    Integer_to_Bytes(omega_cs, ase_key);

    // generate the token
    timeb t;
    ftime(&t);
    string str_time = time_to_string(t.time);
    //cout << "t.time: " << t.time << endl;
    //cout << "str_time" << str_time << endl;

    // Pretty print key
    string encoded;
    encoded.clear();
    StringSource(ase_key, 16, true, new HexEncoder(new StringSink(encoded)));
    //cout << "key: " << encoded << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv_cs, 16, true, new HexEncoder(new StringSink(encoded)));

    // Encryption
    AES_CTR_Enc(this->ID_u + str_time, ase_key, iv_cs, token);

/**************************************Integrity Tag Generation**************************************/
    // hash the file
    Integer file_hash = hashFile("bigdata_encrypted.txt");
    string file_hash_str = Integer_to_string(file_hash);
    string rho_u = Integer_to_string(hash256Function(file_hash_str + ctx_sk + dsk_str));

/***********************************************Outsourcing***********************************************/
    //outsoucing the relative params
    phi_u->ctx_str = ctx_sk;
    phi_u->salt = salt;
    phi_u->rho_u = rho_u;
}


void Client::fetchFile (Integer beta,Phi_u * phi_u, byte(&iv_sk)[16], byte (&iv_dsk)[16]) {

/***************************************Parse the Phi_u***************************************/
    string ctx_sk = phi_u->ctx_str;
    vector<byte> salt = phi_u->salt;
    string rho_u = phi_u->rho_u;

/**************************************Calculate the Param***********************************/
    Integer r_inverse = this->r.InverseMod(order);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));

/***************************************Key Derivation***************************************/
    string password = pwd_u_hat;
    cout << "pwd_h_hat in decryption phase: " << pwd_u_hat << endl;

    SecByteBlock dsk(16); // variant to store the key
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
    int iterationCount = 10000;
    pbkdf2.DeriveKey(dsk, dsk.size(), 0x00, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterationCount);
    string dsk_str;
    StringSource(dsk, dsk.size(), true, new HexEncoder(new StringSink(dsk_str)));

/**************************************Integrity Tag Generation**************************************/
    Integer file_hash = hashFile("bigdata_encrypted.txt");
    string file_hash_str = Integer_to_string(file_hash);
    string rho_new = Integer_to_string(hash256Function(file_hash_str + ctx_sk + dsk_str));

    if (rho_new != rho_u) {
        cout << "The Integrity Verification Fails! " << endl;
    }
    else { 
        cout << "The Integrity Verification success! " << endl;
    }
/**************************************Symmetric Key Decyrption**************************************/
    string sk;
    string print;
    cout << "用来解密sk的密文：" << ctx_sk << endl;
    cout << "用来解密sk的iv_dsk: ";
    for (int i = 0; i < sizeof(iv_dsk) / sizeof(iv_dsk[0]); ++i) {
        cout << hex << (int)iv_dsk[i];
    }
    cout << endl;
    cout << "用来解密sk的dsk: ";
    for (int i = 0; i < dsk.size(); ++i) {
        cout << hex << (int)dsk[i];
    }
    cout << endl;

    AES_CTR_Dec(ctx_sk, dsk, iv_dsk, sk);
    cout << "用来解密的密钥sk: " << sk << endl;

/*******************************************File Decyrption******************************************/
    ifstream inputFile("bigdata_encrypted.txt", std::ios::binary);
    if (!inputFile)
    {
        std::cerr << "Failed to open input file: " << "bigdata_encrypted.txt" << std::endl;
        return;
    }

    // Open output file
    std::ofstream outputFile("recover.txt", std::ios::binary);
    if (!outputFile)
    {
        std::cerr << "Failed to open output file: " << "recover.txt" << std::endl;
        return;
    }

    // Set up decryption
    byte* sk_byte = new byte [16];
    Integer sk_int = string_to_Integer(sk);

    Integer_to_Bytes(sk_int, sk_byte);

    CTR_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(sk_byte, AES::DEFAULT_KEYLENGTH, iv_sk);

    // Decrypt input file and write to output file
    FileSource(inputFile, true,
        new StreamTransformationFilter(decryption,
            new FileSink(outputFile)
        )
    );
}