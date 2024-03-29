#pragma once
#include <iostream>
#include <base64.h>
#include <rsa.h>
#include <osrng.h>

using namespace std;

class Utils
{
public:
	static string findIp(const string& serverAddress);
	static string findPort(const string& serverAddress);
	static string hexi(const uint8_t* buffer, const size_t size);
	static string reverse_hexi(const string& hexString);
	static string encode(const string& str);
	static string decode(const std::string& str);


};
