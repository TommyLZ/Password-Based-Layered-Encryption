#include "CloudServer.h"

#include "SecureParam.h"

#include "integer.h"
using CryptoPP::Integer;

#include <fstream>
#include <iostream>
#include <vector>
#include <Windows.h>

CloudServer::CloudServer () {}

void CloudServer::store(string& ID_u, string& cred_cs) {
    ofstream out("CS_store.txt");

    if (out.is_open()) {
        out << "user_identity: " << ID_u
            << "    credential: " << cred_cs;
    }

    out.close();
}

void resource_store(vector<string> Phi_u) {
    ofstream fout("resource.txt");

    if (!fout) {
        cout << "error!" << endl;
    }

    fout << Phi_u[0] << "    ";
    fout << Phi_u[1] << "    ";
    fout << Phi_u[2] ;

    fout.close();

    cout << "Outsourcing Successfully!" << endl;
}

void tokenVerify(string& token, byte* IV, vector<string>& Phi_u) {
    ifstream in("CS_store.txt");
    string user_identity;
    string cred_ks;

    in >> user_identity;
    in >> cred_ks;

    user_identity = user_identity.substr(user_identity.find(':') + 1, user_identity.size());
    cred_ks = cred_ks.substr(cred_ks.find(':') + 1, cred_ks.size());
    cout << "cred_ks: " << cred_ks << endl;

    // type conversion
    Integer key_int;
    key_int = string_to_Integer(cred_ks);
    byte* key_byte = new byte[16];
    Integer_to_Bytes(key_int, key_byte);
    cout << key_byte << endl;
    string plain;
    AES_CTR_Dec(token, key_byte, IV, plain);

    cout << "recovered text: " << plain << endl;

    resource_store(Phi_u);
}

vector<string> Send() {
    ifstream fin("resource.txt");

    vector<string> Phi_u;
    string ctx_sk = "";
    string salt = "";
    string rho_u = "";

    Phi_u.push_back(ctx_sk);
    Phi_u.push_back(salt);
    Phi_u.push_back(rho_u);

    return Phi_u;
}

