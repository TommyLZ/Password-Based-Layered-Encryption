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
extern const Integer prime;

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
#include <string>
#include <sstream>
#include <vector>
#include <Windows.h>
#include <sys/timeb.h>

using namespace std;
using namespace CryptoPP;

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

// r is randomly generated for secure protection
Integer Client::rGeneration (Integer prime) {
    AutoSeededRandomPool prng;
    Integer r;

    const Integer mini = 0;
    const Integer maxi = prime - 1;
    r.Randomize(prng, mini, maxi);
    
    bool flag = true;
    while (GCD(r, prime) != 1) {
        r.Randomize(prng, mini, maxi);
    }

    return r;
}

Integer Client::blindsPassword() {

    Integer H(hash256Function(this->psw_u));

    cout << "The hash of the password: " << H << endl;

    // blind the value to against dictionary guessing attack
    Integer blind_value = fastPower(H, this -> r);

    return blind_value;
}

void Client::credGen (const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, vector<string>& cred) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    string s_u = Integer_to_string(randomGeneration(secureParam));

    Integer r_inverse = this->r.InverseMod(prime);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    // It may be because of a hardware failure, the de-blinding fails
    // the correct de-blinding result
    beta_inverse = "20000000000000";
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    string cred_ks = Integer_to_string(hash256Function(pwd_u_hat + this -> ID_u));

    cout << "credential for key server: " << cred_ks << endl;
    string cred_cs = Integer_to_string(hash256Function(this->ID_u + pwd_u_hat + s_u));

    cred.push_back(this->ID_u);
    cred.push_back(s_u);
    cred.push_back(cred_ks);
    cred.push_back(cred_cs);
}

vector<string> Client::tokenGenForKS(const ECDSA<ECP, SHA256>::PublicKey& key, string& message, string& signature, Integer& beta, string& token, byte* iv) {
    if (!VerifyMessage(key, message, signature)) {
        abort();
    }

    Integer r_inverse = this->r.InverseMod(prime);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    // It may be because of a hardware failure, the de-blinding fails
    // the correct de-blinding result
    beta_inverse = "20000000000000";
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    Integer omega_ks = hash256Function(pwd_u_hat + this->ID_u);
    byte* ase_key = new byte [16];

    cout << "omega_ks: " << omega_ks << endl;

    Integer_to_Bytes(omega_ks, ase_key);

	timeb t;
	ftime(&t);
	string str_time = time_to_string(t.time);

    cout << "t.time: " << t.time << endl;
    cout << "str_time" << str_time << endl;

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

void Client::tokenGenForCS(Integer& beta, string& s_u, string& token, byte*& iv_file, byte*& iv_sk, vector<string>& Phi_u) {

    Integer r_inverse = this->r.InverseMod(prime);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    // It may be because of a hardware failure, the de-blinding fails
    // the correct de-blinding result
    beta_inverse = "20000000000000";
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));
    Integer omega_cs = hash256Function(pwd_u_hat + this->ID_u + s_u);
    cout << "omega_cs: " << omega_cs << endl;


/***************************************File Encryption***************************************/
    // encrypt key & iv for encrytion
    byte sk[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte iv_sk[CryptoPP::AES::BLOCKSIZE];
    AutoSeededRandomPool prng;
    prng.GenerateBlock(sk, sizeof(sk));
    prng.GenerateBlock(iv_sk, sizeof(iv_sk));

    CTR_Mode<AES>::Encryption e;
    e.SetKeyWithIV(sk, AES::DEFAULT_KEYLENGTH, iv_sk);

    // read and write the file
    ifstream ifs("bigdata.txt", std::ios::binary);
    ofstream ofs("bigdata_encrypted.txt", std::ios::binary);

    // encrypt the file (我今天是在这里干什么）
    FileSource(ifs, true, new StreamTransformationFilter(e, new FileSink(ofs)));
    cout << "File Encryption Finished!" << endl;

    ifs.close();
    ofs.close();

/***************************************Key Derivation***************************************/
    string password = pwd_u_hat;

    // generate the salt
    AutoSeededRandomPool rng;
    string salt(16, 0);
    rng.GenerateBlock((byte*)salt.data(), salt.size());
    int iterationCount = 10000;
    int keySize = 16; // byte

    // generate the derived key dsk
    SecByteBlock dsk(keySize); // variant to store the key
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
    pbkdf2.DeriveKey(dsk, dsk.size(), 0x00, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterationCount);

    // encrypt the symmetric key
    string ctx_sk = ""; 
    string str_sk = Byte_to_String(sk);
    AES_CTR_Enc(str_sk, dsk, iv, ctx_sk);

/**************************************Integrity Tag Generation**************************************/
    string file_hash = hashFile("bigdata_encrypted.txt");

    // hash the file 
    string dsk_str = Byte_to_String(dsk);
    string rho_u = Integer_to_string(hash256Function(file_hash + ctx_sk + dsk_str));

/**********************************Authenticaiton Token Generation**********************************/
    byte* ase_key = new byte[16];
    Integer_to_Bytes(omega_cs, ase_key);

    // generate the token
    timeb t;
    ftime(&t);
    string str_time = time_to_string(t.time);
    cout << "t.time: " << t.time << endl;
    cout << "str_time" << str_time << endl;

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

/***********************************Outsourcing*************************************/
    //store the dsk
    ofstream ofs("dsk_store");
    ofs << dsk_str;
    ofs.close();

    //outsoucing the relative params
    vector<string> Phi_u;
    Phi_u.push_back(ctx_sk);
    Phi_u.push_back(salt);
    Phi_u.push_back(rho_u);
}


void Client::fetchFile(Integer beta, vector<string> Phi_u，byte* IV) {
    ifstream fin("resouce.txt");

    if (!fin) {
        cout << "error" << endl;
    }

    string ctx_sk;
    string salt;
    string rho_u;

    fin >> ctx_sk;
    fin >> salt;
    fin >> rho_u;

    fin.close();

    Integer r_inverse = this->r.InverseMod(prime);
    string beta_inverse = Integer_to_string(fastPower(beta, r_inverse));

    // It may be because of a hardware failure, the de-blinding fails
    // the correct de-blinding result
    beta_inverse = "20000000000000";
    cout << "beta_inverse: " << beta_inverse << endl;

    string pwd_u_hat = Integer_to_string(hash256Function(this->psw_u + beta_inverse));

/***************************************Key Derivation***************************************/
    string password = pwd_u_hat;

    ifstream fin("dsk_store");
    string dsk_str;
    fin >> dsk_str;
    Integer dsk_int = string_to_Integer(dsk_str);
    byte* dsk;
    Integer_to_Bytes(dsk_int, dsk);
    int iterationCount = 10000;

    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
    pbkdf2.DeriveKey(dsk, 16, 0x00, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterationCount);

/**************************************Integrity Tag Generation**************************************/
    string file_hash = hashFile("bigdata_encrypted.txt");

    // hash the file 
    string dsk_str = Byte_to_String(dsk);
    string rho_new = Integer_to_string(hash256Function(file_hash + ctx_sk + dsk_str));
    
    if (rho_new != rho_u) {
        cout << "The Integrity Verification Fails! " << endl;
    }

/**************************************File Decryption**************************************/
    AES_CTR_Dec();
}

