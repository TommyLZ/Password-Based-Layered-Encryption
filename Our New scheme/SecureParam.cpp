#include "SecureParam.h"

#include "algparam.h"
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

// Realize the primeGeneration function
Integer primeGeneration(const int& secureParam) {
	AutoSeededRandomPool prng;
	Integer p;

	AlgorithmParameters params = MakeParameters("BitLength", secureParam)("RandomNumberType", Integer::PRIME);
	p.GenerateRandom(prng, params);

	return p;
}

