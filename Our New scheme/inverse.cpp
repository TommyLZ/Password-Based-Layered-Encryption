//#include <iostream>
//#include <string>
//#include <cryptlib.h>
//#include <integer.h>
//
//using namespace CryptoPP;
//using namespace std;
//
//Integer fastPower(const Integer& x, const Integer& y, const Integer& prime)
//{
//    Integer res = 1;
//    Integer x_mod_p = x;
//    Integer y_copy = y;
//
//    while (y_copy > 0) {
//        if (y_copy.IsOdd()) {
//            res = (res * x_mod_p) % prime;
//        }
//
//        x_mod_p = (x_mod_p * x_mod_p) % prime;
//        y_copy >>= 1;
//
//    }
//
//    return res;
//}
//
//int main()
//{
//    char a[100] = "21c9acf5b05becc16e99c75fe236fb09h";
//    char b[100] = "10001h";
//    char c[100] = "439359eb60b7d982dd338ebfc46df613h";
//    char d[100] = "5a5e76149590cebf9eaae0ce2f2fdd1h";
//
//    Integer H(a);
//    Integer r(b);
//    Integer order(d);
//    Integer prime(c);
//
//    Integer rInv = r.InverseMod(order);
//
//    Integer a1 = fastPower(H, r, prime);
//    Integer a2 = fastPower(a1, rInv, prime);
//
//    cout << "a1 = " << a1 << std::endl;
//    cout << "a2 = " << std::hex << a2 << std::endl;
//    cout << "H = " << std::hex << H << std::endl;
//
//    return 0;
//}
//
//
//
////Modulo: p = 439359eb60b7d982dd338ebfc46df613h
////Generator : q = 5a5e76149590cebf9eaae0ce2f2fdd1h
////Group order : g = 21c9acf5b05becc16e99c75fe236fb09h