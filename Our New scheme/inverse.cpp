//#include "secureparam.h"
//#include <iostream>
//using namespace std;
//
//int main() {
//	char pswd_hash[500] = "3551e136e4f167d1804b8ef94566b4f3h";
//	char this_r1[500] = "35ddbc561c71454da543a8078f6cc891h";
//	char this_r2[500] = "329275b52c370edcd3f297f37597a22fh";
//	char nu[500] = "8979d90066816152e7f69af9df501862h";
//
//	Integer int_pswd_hash(pswd_hash); // 口令哈希值
//
//	Integer int_this_r1(this_r1);	//
//	Integer int_this_r2(this_r2);
//
//	Integer int_nu(nu); // 密钥服务器
//
//	Integer a = int_this_r1.InverseMod(prime);
//	Integer b = int_this_r2.InverseMod(prime);
//
//	cout << "alpha1 = pswd_hash^r1: " << fastPower(int_pswd_hash, int_this_r1) << endl;
//	cout << "alpha2 = pswd_hash^r2: " << fastPower(int_pswd_hash, int_this_r2) << endl;
//
//	cout << a * int_this_r1 % prime << endl;
//	cout << b * int_this_r2 % prime << endl;
//
//	cout << "adapt1: " << hex << fastPower(fastPower(int_pswd_hash, int_this_r1), a) % prime << endl;
//	cout << "adapt2: " << hex << fastPower(fastPower(int_pswd_hash, int_this_r2), b) % prime << endl;
//
//	//cout << "beta1 = alpha2^nu: " << fastPower(fastPower(int_pswd_hash, int_this_r1), int_nu) << endl;
//	//cout << "beta2 = alpha2^nu: " << fastPower(fastPower(int_pswd_hash, int_this_r2), int_nu) << endl;
//
//	//cout << "beta_inverse = beta1^(inverse_r1): " << fastPower(fastPower(fastPower(int_pswd_hash, int_this_r1), int_nu), r1_inverse) << endl;
//	//cout << "answer: " << fastPower(int_pswd_hash, int_nu) << endl;
//	//cout << "beta_inverse = beta2^(inverse_r2): " << fastPower(fastPower(fastPower(int_pswd_hash, int_this_r2), int_nu), r2_inverse) << endl;
//
//
//}