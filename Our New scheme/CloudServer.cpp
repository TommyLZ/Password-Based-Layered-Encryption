#include "CloudServer.h"

#include <fstream>
#include <iostream>

CloudServer::CloudServer () {}

void CloudServer::store(string& ID_u, string& cred_cs) {
    ofstream out("CS_store.txt");

    if (out.is_open()) {
        out << "user_identity: " << ID_u
            << "    credential: " << cred_cs;
    }

    out.close();
}

