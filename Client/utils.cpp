#pragma once
#include <iostream>
#include "utils.h"
#include "constants.h"
#include <boost/algorithm/hex.hpp>



string Utils::findIp(const string& serverAddress)
{
	string ip = "";

	/*Find the IP from the serverAddress, serverAddress is storing the first line's transfer.info file*/
	for (int i = 0; i < serverAddress.size(); i++)
	{
		if (serverAddress[i] == ':')
		{
			break;
		}
		ip += serverAddress[i];
	}
	return ip;
	
};

string Utils::findPort(const string& serverAddress)
{
	int startPort  = serverAddress.size();
	string port = "";

	/*Find the Port from the serverAddress, serverAddress is storing the first line's transfer.info file*/
	for (int i = 0; i < serverAddress.size(); i++)
	{
		if (serverAddress[i] == ':')
		{
			startPort = i;
			continue;
		}
		if (i > startPort)
		{
			port += serverAddress[i];
		}
		
	}
	return port;

};

/*  convert to hexedecimal representation */
string Utils::hexi(const uint8_t* buffer, const size_t size)
{
	if (size == 0 || buffer == nullptr)
		return "";
	const std::string byteString(buffer, buffer + size);
	if (byteString.empty())
		return "";
	try
	{
		return boost::algorithm::hex(byteString);
	}
	catch (...)
	{
		return "";
	}
}
string Utils::reverse_hexi(const string& hexString)
{
	try
	{
		std::string byteString;
		boost::algorithm::unhex(hexString, std::back_inserter(byteString));
		return byteString;
	}
	catch (...)
	{
		return "";
	}
}
std::string Utils::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

/* base64 decoder */
std::string Utils::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}