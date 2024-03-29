#pragma once
#include <osrng.h>
#include <rsa.h>
#include <string>
class RSAKeysWraper
{
public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;

	RSAKeysWraper(const RSAKeysWraper& rsaprivate);
	RSAKeysWraper& operator=(const RSAKeysWraper& rsaprivate);
public:
	RSAKeysWraper();
	RSAKeysWraper(const char* key, unsigned int length);
	RSAKeysWraper(const std::string& key);
	~RSAKeysWraper();

	std::string getPrivateKey() const;
	char* getPrivateKey(char* keyout, unsigned int length) const;

	std::string getPublicKey() const;
	char* getPublicKey(char* keyout, unsigned int length) const;

	std::string decrypt(const std::string& cipher);
	std::string decrypt(const char* cipher, unsigned int length);
};


