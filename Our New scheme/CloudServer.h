#pragma once
#include "SecureParam.h"

#include <iostream>
#include <cstring>
#include <vector>
#include <Windows.h>
using namespace std;

class CloudServer
{
public:
	CloudServer();
	void store (string& ID_u, string& cred_cs);
	vector<string> Send ();
	void resource_store (vector<string> Phi_u);
	void tokenVerifyC (string& token, byte* IV, Phi_u* phi_u);
};