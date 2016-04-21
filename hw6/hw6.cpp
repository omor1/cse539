#include <array>
#include <iostream>
#include <random>

#include "RSA.h"

using namespace RSAUtil;

BigInt blind_sig(BigInt *m, BigInt *rand, RSA *rsa)
{
	auto sig = rsa->encrypt(*rand);
	sig *= *m;
	sig = sig % rsa->getModulus();
	return sig;
}

BigInt sign(BigInt m, RSA rsa)
{
	return rsa.decrypt(m);
}

BigInt unblind_sig(BigInt sig, BigInt rand, RSA rsa)
{
	sig *= modInverse(rand, rsa.getModulus());
	return sig % rsa.getModulus();
}

int main(int argc, char *argv[])
{
	std::cout << "1: Encryption and Decryption" << std::endl;

	std::cout << "a: 2 random primes" << std::endl;
	std::array<RSA, 10> a;
	for (auto rsa: a) {
		unsigned long tmp;
		auto e = rsa.encrypt(42);
		auto d = rsa.decrypt(e);
		d.toULong(&tmp, 1);
		std::cout << "Plaintext: 42\tCiphertext: " << e.toHexString() << "\tDecrypted: " << tmp << std::endl;
	}

	std::cout << "b: 1 chosen prime, 1 random prime" << std::endl;
	std::array<RSA, 5> b = { RSA(36131), RSA(30677), RSA(34511), RSA(36007), RSA(35729) };
	for (auto rsa: b) {
		unsigned long tmp;
		auto e = rsa.encrypt(42);
		auto d = rsa.decrypt(e);
		d.toULong(&tmp, 1);
		std::cout << "Plaintext: 42\tCiphertext: " << e.toHexString() << "\tDecrypted: " << tmp << std::endl;
	}

	std::cout << "c: 2 chosen primes" << std::endl;
	std::array<RSA, 5> c = { RSA(33923, 31771), RSA(35419, 39293), RSA(59539, 51907), RSA(45841, 59743), RSA(36709, 50069) };
	for (auto rsa: c) {
		unsigned long tmp;
		auto e = rsa.encrypt(42);
		auto d = rsa.decrypt(e);
		d.toULong(&tmp, 1);
		std::cout << "Plaintext: 42\tCiphertext: " << e.toHexString() << "\tDecrypted: " << tmp << std::endl;
	}

	std::cout << "d: 2 chosen non-primes" << std::endl;
	// the first few of these are Carmichael numbers, so there's a greater chance that they will work "right"
	std::array<RSA, 10> d = { RSA(41041, 46657), RSA(52633, 62745), RSA(63973, 75361), RSA(30001, 30003), RSA(65432, 45612),
				  RSA(32324, 43434), RSA(36912, 48120), RSA(67824, 32378), RSA(56782, 33332), RSA(33334, 55556) };
	for (auto rsa: d) {
		unsigned long tmp;
		auto e = rsa.encrypt(42);
		auto d1 = rsa.decrypt(e);
		d1.toULong(&tmp, 1);
		std::cout << "Plaintext: 42\tCiphertext: " << e.toHexString() << "\tDecrypted: " << tmp << std::endl;
	}

	std::cout << std::endl << "2: Challenge-Response Scheme" << std::endl;
	RSA rsa1, rsa2;
	rsa2.setN(rsa1.getModulus());
	rsa1.getPublicKey();
	rsa1.getPrivateKey();
	rsa2.setPublicKey(rsa1.getPublicKey());
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<int> dist;
	BigInt i = dist(mt);
	std::cout << "Random BigInt: " << i.toHexString() << std::endl;
	auto i_encrypt = rsa2.encrypt(i);
	auto i_decrypt = rsa1.decrypt(i_encrypt);
	std::cout << "Encrypted: " << i_encrypt.toHexString() << "\tDecrypted: " << i_decrypt.toHexString() << std::endl;
	if (i == i_decrypt)
		std::cout << "Challenge-Response succeeded" << std::endl;
	else
		std::cout << "Challenge-Response failed" << std::endl;

	std::cout << std::endl << "3: Blind Signature" << std::endl;
	RSA bob;
	BigInt m = 42;
	std::cout << "Message: " << m.toHexString() << std::endl;
	BigInt rand = dist(mt);
	auto sig = blind_sig(&m, &rand, &bob);
	std::cout << "Blinded: " << sig.toHexString() << std::endl;
	sig = sign(sig, bob);
	std::cout << "Blinded signature: " << sig.toHexString() << std::endl;
	sig = unblind_sig(sig, rand, bob);
	std::cout << "Signature: " << sig.toHexString() << std::endl;
	std::cout << "Verify: " << bob.encrypt(sig).toHexString() << std::endl;

	return 0;
}
