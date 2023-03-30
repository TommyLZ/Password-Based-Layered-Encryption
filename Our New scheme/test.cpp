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
//    // ���캯�������� bitLength ��ʾ���ɵ����� p ��λ��
//    CyclicGroup(int bitLength) {
//        init(bitLength);
//    }
//
//    void init(int bitLength) {
//        //Integer q = Integer::Zero();
//
//        // ѭ��ֱ���ҵ�һ���������������� p ������Ԫ g
//        while (true) {
//            // ����һ�� bitLength λ�Ĵ����� q
//            AutoSeededRandomPool prng;
//            //q = Integer(prng, bitLength, 40);
//            AlgorithmParameters params = MakeParameters("BitLength", 128)
//                ("RandomNumberType", Integer::PRIME);
//
//            q.GenerateRandom(prng, params);
//
//
//            // ����ģ�� p = 2q+1
//            p = (q * TWO) + Integer::One();
//
//            // ��� p ���������������������һ�� q
//            if (!MillerRabinTest(p, 40)) {
//                continue;
//            }
//
//            while (true) {
//                // ����һ�����������Ԫ g
//                g = Integer(prng, TWO, p - Integer::One());
//
//                // ���� (p-1)/q
//                Integer exp = (p - Integer::One()) / q;
//
//                // ��� g^(p-1)/q �� 1 (mod p)����ֹͣѭ��
//                if (ModularExponentiation(g, exp, p) != Integer::One()) {
//                    break;
//                }
//            }
//
//            break;
//        }
//    }
//
//    // ��ȡһ�������ȺԪ��
//    Integer getRandomElement() {
//        AutoSeededRandomPool prng;
//        return ModularExponentiation(g, Integer(prng, p.ByteCount()), p);
//    }
//
//    // ��ȡѭ��Ⱥ�е�����Ԫ��
//    std::vector<Integer> getElements() {
//        std::vector<Integer> elements;
//
//        Integer index = Integer::One();
//        Integer element = Integer::Zero();
//
//        // ѭ��ֱ���ҵ�Ⱥ�ĵ�λԪ 1
//        while (element != Integer::One()) {
//            // ���� g ���ݴ�
//            element = ModularExponentiation(g, index, p);
//            elements.push_back(element);
//
//            index++; // index++
//        }
//
//        return elements;
//    }
//
//    // ��ȡģ�� p
//    Integer getModulus() {
//        return p;
//    }
//
//    // ��ȡ����Ԫ g
//    Integer getGenerator() {
//        return g;
//    }
//
//    // ��ȡѭ��Ⱥ�Ľ�
//    Integer getOrder() {
//        return q;
//    }
//};
//
//int main() {
//    // ����һ�� 128 λ��ѭ��Ⱥ
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