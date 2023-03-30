//#include <iostream>
//#include <vector>
//#include <cryptlib.h>
//#include <integer.h>
//#include <nbtheory.h>
//#include <osrng.h>
//using namespace CryptoPP;
//
//bool MillerRabinTest(const Integer& n, unsigned int rounds) {
//    // Check for small values of n
//    if (n <= 3) {
//        return n == 2 || n == 3;
//    }
//
//    // Find k and m such that n-1 = 2^k * m, where m is odd
//    Integer m = n - 1;
//    unsigned int k = 0;
//    while (m.IsEven()) {
//        m >>= 1;
//        k++;
//    }
//
//    // Run the Miller-Rabin primality test for 'rounds' rounds
//    AutoSeededRandomPool rng;
//    for (unsigned int i = 0; i < rounds; i++) {
//        // Generate a random base a such that 1 < a < n-1
//        Integer a = Integer(rng, 2, n - 2);
//
//        // Compute b = a^m (mod n)
//        Integer b = ModularExponentiation(a, m, n);
//
//        // If b == 1 or b == n-1, then n passes this round of the test
//        if (b == 1 || b == n - 1) {
//            continue;
//        }
//
//        // Run the test for k-1 additional times
//        bool isPrime = false;
//        for (unsigned int j = 0; j < k - 1; j++) {
//            // Compute b = b^2 (mod n)
//            b = ModularExponentiation(b, 2, n);
//
//            // If b == n-1, then n passes this round of the test
//            if (b == n - 1) {
//                isPrime = true;
//                break;
//            }
//        }
//
//        if (!isPrime) {
//            return false;
//        }
//    }
//
//    // If n has passed all rounds of the test, then it is probably prime
//    return true;
//}
//
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
//class CyclicGroup {
//private:
//    static const int EQUAL = 0;
//    Integer TWO = Integer(2);
//
//    Integer p, g, q;
//
//public:
//    // 构造函数，传入 bitLength 表示生成的素数 p 的位数
//    CyclicGroup(int bitLength) {
//        init(bitLength);
//    }
//
//    void init(int bitLength) {
//        //Integer q = Integer::Zero();
//
//        // 循环直到找到一个符合条件的素数 p 和生成元 g
//        while (true) {
//            // 生成一个 bitLength 位的大素数 q
//            AutoSeededRandomPool prng;
//            //q = Integer(prng, bitLength, 40);
//            AlgorithmParameters params = MakeParameters("BitLength", 128)
//                ("RandomNumberType", Integer::PRIME);
//
//            q.GenerateRandom(prng, params);
//
//
//            // 计算模数 p = 2q+1
//            p = (q * TWO) + Integer::One();
//
//            // 如果 p 不是素数，则继续生成下一个 q
//            if (!MillerRabinTest(p, 40)) {
//                continue;
//            }
//
//            while (true) {
//                // 生成一个随机的生成元 g
//                g = Integer(prng, TWO, p - Integer::One());
//
//                // 计算 (p-1)/q
//                Integer exp = (p - Integer::One()) / q;
//
//                // 如果 g^(p-1)/q ≠ 1 (mod p)，则停止循环
//                if (ModularExponentiation(g, exp, p) != Integer::One()) {
//                    break;
//                }
//            }
//
//            break;
//        }
//    }
//
//    // 获取一个随机的群元素
//    Integer getRandomElement() {
//        AutoSeededRandomPool prng;
//        return ModularExponentiation(g, Integer(prng, p.ByteCount()), p);
//    }
//
//    // 获取循环群中的所有元素
//    std::vector<Integer> getElements() {
//        std::vector<Integer> elements;
//
//        Integer index = Integer::One();
//        Integer element = Integer::Zero();
//
//        // 循环直到找到群的单位元 1
//        while (element != Integer::One()) {
//            // 计算 g 的幂次
//            element = ModularExponentiation(g, index, p);
//            elements.push_back(element);
//
//            index++; // index++
//        }
//
//        return elements;
//    }
//
//    // 获取模数 p
//    Integer getModulus() {
//        return p;
//    }
//
//    // 获取生成元 g
//    Integer getGenerator() {
//        return g;
//    }
//
//    // 获取循环群的阶
//    Integer getOrder() {
//        return q;
//    }
//};
//
//int main() {
//    // 生成一个 128 位的循环群
//    CyclicGroup group(128);
//
//    Integer p = group.getModulus();
//    Integer g = group.getGenerator();
//    Integer q = group.getOrder();
//
//    std::cout << "Modulo: p=" << std::hex << group.getModulus() << std::endl;
//    std::cout << "Generator: g=" << std::hex << group.getGenerator() << std::endl; 
//    std::cout << "Group order: q=" << std::hex << group.getOrder() << std::endl;
//
//    Integer H = g * g % p;
//    Integer r = 1000;
//    Integer rInv = r.InverseMod(q);
//
//    Integer a1 = fastPower(H, r, p);
//    Integer a2 = fastPower(a1, rInv, p);
//
//    std::cout << H << std::endl;
//    std::cout << a2 << std::endl;
//}