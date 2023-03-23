//#include <iostream>
//#include <string>
//#include <cryptlib.h>
//#include <integer.h>
//#include <secblock.h>
//
//using namespace CryptoPP;
//using namespace std;
//
//Integer fastPower(const Integer& x, const Integer& y, const Integer& prime)
//{
//    Integer res = 1;
//    Integer x_mod_p = x % prime;
//    Integer y_copy = y;
//
//    while (y_copy > 0) {
//        if (y_copy.IsOdd()) {
//            res = (res * x_mod_p) % prime;
//
//        }
//        y_copy >>= 1;
//        x_mod_p = x_mod_p * x_mod_p % prime;
//    }
//
//    return res;
//}
//
//int main()
//{
//    char a[100] = "4000000000000000000000h";
//    char b[100] = "1000000000000000000000000000h";
//    char c[100] = "7fffffffffffffffffffffffffffffffh";
//
//    Integer H(a);
//    Integer r(b);
//    Integer prime(c);
//
//    Integer rInv = r.InverseMod(prime);
//
//    Integer a1 = fastPower(H, r, prime);
//    Integer a2 = fastPower(a1, rInv, prime);
//
//    std::cout << "a1 = " << std::hex << a1 << std::endl;
//    //std::cout << "a2 = " << std::hex << a2 << std::endl;
//    //std::cout << "H = " << std::hex << H << std::endl;
//
//    return 0;
//}


//#include <iostream>
//#include <iomanip>
//#include <cryptopp/osrng.h>
//#include <cryptopp/pwdbased.h>
//#include <cryptopp/hex.h>
//
//int main() {
//    using namespace CryptoPP;
//
//    // 输入参数
//    std::string password = "myPassword";
//    std::string salt = "mySalt";
//    int iterationCount = 10000;
//    int keySize = 32; // 输出的密钥长度（以字节为单位）
//
//    // 生成密钥
//    SecByteBlock key(keySize);
//    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
//    pbkdf2.DeriveKey(key, key.size(), 0x00, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), iterationCount);
//
//    // 输出密钥的十六进制表示
//    std::string encoded;
//    HexEncoder encoder(new StringSink(encoded));
//    encoder.Put(key.data(), key.size());
//    encoder.MessageEnd();
//    std::cout << "Derived Key: " << encoded << std::endl;
//
//    return 0;
//}


//#include <cryptopp/sha.h>
//#include <cryptopp/filters.h>
//#include <cryptopp/files.h>
//#include <fstream>
//#include <iostream>
//#include <iomanip>
//#include <vector>


