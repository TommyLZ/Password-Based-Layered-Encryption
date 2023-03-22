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
//    char b[100] = "51389b3163ea893b7cc20f9d6c4da3e8h";
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
//    std::cout << "a2 = " << std::hex << a2 << std::endl;
//    std::cout << "H = " << std::hex << H << std::endl;
//
//    return 0;
//}
