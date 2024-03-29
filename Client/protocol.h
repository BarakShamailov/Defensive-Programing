#pragma once
#include <cstdint>
#include <iostream>

constexpr auto VERSION  = 3;
constexpr auto PACKET_SIZE = 2048;
constexpr auto UID_SIZE = 16;
constexpr auto VERSION_SIZE = 1;
constexpr auto CODE_SIZE = 2;
constexpr auto PAYLOAD_SIZE = 4;
constexpr auto REQUEST_HEADER_SIZE = 23;
constexpr auto HEADER_SIZE = 7;
constexpr auto NAME_SIZE = 255;
constexpr auto PUBLIC_KEY_SIZE = 160;
constexpr auto CLIENT_HEADER_SIZE = 23;
constexpr auto CONTENT_SIZE = 4;
constexpr auto ORIGIN_FILE_SIZE = 4;
constexpr auto PACKET_NUM = 2;
constexpr auto TOTAL_PACKETS = 2;
constexpr auto CRC_SIZE = 4;
constexpr auto FILE_NAME_SIZE = 255;
constexpr auto MAX_CRC_SEND = 4;
constexpr auto MAX_NAME_SIZE = 255;
constexpr auto MAX_SENDS = 4;
constexpr auto DEF_VAL = 0;
constexpr auto CHUNK_SIZE_CONTENT = 1024; // The size that remain for chunk file data to send

typedef uint16_t code_t;
typedef uint32_t payload_t;


enum CodeRequests : uint16_t {
	REGISTER_REQUEST = 1025,
	PUBLIC_KEY_REQUEST = 1026,
	RECONNECTION_REQUEST = 1027,
	SEND_FILE_REQUEST = 1028,
	VALID_CRC_REQUEST = 1029,
	INVALID_CRC_REQUEST = 1030,
	FOURTH_INVALID_CRC_REQUEST = 1031
};

enum CodeResponses : uint16_t {
	SUCCESSFUL_REGISTRATION = 1600,
	FAILED_REGISTRATION = 1601,
	PUBLIC_KEY_RESPONSE = 1602,
	GOT_VALID_FILE = 1603,
	ACCEPT_MESSAGE = 1604,
	ACCEPT_RECONNECTION_REQUEST = 1605,
	REJECT_RECONNECTION_REQUEST = 1606,
	GENERAL_ERROR = 1607
};

#pragma pack(push, 1) // with this we can pack all the struct in once
struct ClientRequestHeader
{
	uint8_t uid[16]; //16 bytes
	uint8_t  version; //one byte
	uint16_t  code;   // the request code to execute  , 2 byets
	uint32_t payloadSize; //4 byets  payload size
	ClientRequestHeader(code_t requestCode, payload_t payloadSize) : uid{ '\0' }, version(VERSION), code(requestCode), payloadSize(payloadSize) {}
};
#pragma pack(pop)


struct SymmetryKeyRequest
{
	ClientRequestHeader header;
	SymmetryKeyRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}

};

struct RegisterationRequest
{
	ClientRequestHeader header;
	RegisterationRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct ReconnectionRequest
{
	ClientRequestHeader header;
	ReconnectionRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};
struct FileSendRequest
{
	ClientRequestHeader header;
	FileSendRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};
struct CRCRequest
{
	ClientRequestHeader header;
	CRCRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};
struct ServerResponse
{

	struct SResponseHeader
	{
		uint8_t  version; //one byte
		uint16_t  code;   // the request code to execute  , 2 byets
		uint32_t payloadSize; //4 byets  payload size
		SResponseHeader() : version(VERSION), code(DEF_VAL), payloadSize(DEF_VAL) {}

	};
	struct Payload
	{
		uint8_t* payload;
		Payload() : payload(nullptr) {}
	};

	SResponseHeader header;  // request header
	Payload payload;
};

