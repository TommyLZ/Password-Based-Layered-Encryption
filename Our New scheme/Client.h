#pragma once

#include "integer.h"
using CryptoPP::Integer;

using namespace std;

class Client
{
private:

	Integer r;
	string psw_u;
	string ID_u;

public:

	Client ();
	Client (string psw_u, string ID_u);

	string getPassword();
	string getID();

	Integer rGeneration (Integer prime);

	Integer blindsPassword();
};