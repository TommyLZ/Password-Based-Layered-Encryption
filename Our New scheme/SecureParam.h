#pragma once

#include "integer.h"
using CryptoPP::Integer;

#include <iostream>
using namespace std;

// generate a random prime of secureParam bits
Integer primeGeneration(const int& secureParam);

// define the hash function

// define the secureParam
const int secureParam = 80;

const Integer prime = primeGeneration(secureParam);






