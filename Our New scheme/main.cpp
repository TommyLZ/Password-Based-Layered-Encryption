#include "registration.h"
#include "encryption.h"
#include "decryption.h"

#include <iostream>
using namespace std;

int main() {
	string psw_u = "f4520tommy";
	string id_u = "wolverine";

	//Registration(psw_u, id_u);

	//Encryption(psw_u, id_u);

	Decryption(psw_u, id_u);

	return 0;
}