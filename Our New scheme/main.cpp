#include "Registration.h"
#include "Encryption.h"

#include <iostream>
using namespace std;

int main() {
	string psw_u = "f4520tommy";
	string ID_u = "Wolverine";

	Registration(psw_u, ID_u);

	Encryption(psw_u, ID_u);

	return 0;
}