#include <iostream>
#include <algorithm>
#include <cstring>
#include <boost/crc.hpp>
#include "client.h"
#include "constants.h"
#include "file_handler.h"
#include "aes_wraper.h"
#include "utils.h"
#include "protocol.h"
#include "rsa_wraper.h"
#include "cksum.h"

Client::Client()
{
	
	_name = "";
	_uid = "";
	_filePath = "";
	_base64privateKey = "";
	_AESKey = "";
	_publicKey = "";
	_privateKey = "";
	_fileContent = "";

};

/*Creating and packing the Symmetry Key Request */
void Client::createRegisterationRequest(vector<uint8_t>& requestData) {
	FileHandler* file = new FileHandler();
	if (!_uid.empty())
		throw std::runtime_error("[ERROR] User already registered!");
	/*Cheking wether the client name is not more than 255*/
	if (_name.length() > MAX_NAME_SIZE - 1)
		throw std::invalid_argument("[ERROR] Specified user name cannot be longer than " + std::to_string(MAX_NAME_SIZE - 1) + " chars!");
	RegisterationRequest request(REGISTER_REQUEST, NAME_SIZE);
	
	/* pack the header */
	memcpy(requestData.data(), &request, REQUEST_HEADER_SIZE);
	/* pack the payload */
	memcpy(requestData.data() + REQUEST_HEADER_SIZE,_name.c_str(), _name.length());//23 is where payload starts
	memcpy(requestData.data() + REQUEST_HEADER_SIZE + _name.length(), "\0", 1);//add null ptr for name
	delete file;

}
/*Creating and packing the Symmetry Key Request */
void Client::createSymmetryKeyRequest(vector<uint8_t>& requestData) {

	requestData.clear();
	requestData.resize(PACKET_SIZE);
	SymmetryKeyRequest request(PUBLIC_KEY_REQUEST, NAME_SIZE + PUBLIC_KEY_SIZE);
	/* pack the header */
	std::string unhexUID = Utils::reverse_hexi(_uid);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestData.data(), &request, REQUEST_HEADER_SIZE);

	/* pack the payload */
	memcpy(requestData.data() + CLIENT_HEADER_SIZE, _name.c_str(), _name.length());
	std::fill(requestData.begin() + CLIENT_HEADER_SIZE + _name.length(),
		requestData.begin() + CLIENT_HEADER_SIZE + NAME_SIZE, '\0');
	memcpy(requestData.data() + CLIENT_HEADER_SIZE + NAME_SIZE, _publicKey.c_str(), PUBLIC_KEY_SIZE);
}
/*Creating and packing the Reconnection Request */
void Client::createReconnectionRequest(vector<uint8_t>& requestData) {
	requestData.clear();
	requestData.resize(PACKET_SIZE);
	FileHandler* file = new FileHandler();
	/*Check weather the client name is more than 255*/
	if (_name.length() > MAX_NAME_SIZE - 1)
		throw std::invalid_argument("[ERROR] Specified user name cannot be longer than " + std::to_string(MAX_NAME_SIZE - 1) + " chars!");

	RegisterationRequest request(RECONNECTION_REQUEST, NAME_SIZE);
	std::string unhexUID = Utils::reverse_hexi(_uid);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestData.data(), &request, REQUEST_HEADER_SIZE);
	/* pack the payload */
	memcpy(requestData.data() + CLIENT_HEADER_SIZE, _name.c_str(), _name.length());
	std::fill(requestData.begin() + CLIENT_HEADER_SIZE + _name.length(),
		requestData.begin() + CLIENT_HEADER_SIZE + NAME_SIZE, '\0');
	delete file;

}
/*Creating and packing the Send File Request */
bool Client::createSendFileRequest(vector<std::uint8_t>& requestData)
{
	/* check if the payload size is smaller then the max excpected payload size  */
	if (CONTENT_SIZE + FILE_NAME_SIZE + _encryptedContent.size() > std::numeric_limits<unsigned int>::max())
	{
		return false;
	}
	int payload_size = ORIGIN_FILE_SIZE + PACKET_NUM + TOTAL_PACKETS + CONTENT_SIZE + FILE_NAME_SIZE + _chunkData.size();
	FileSendRequest request(SEND_FILE_REQUEST, payload_size);
	requestData.clear();
	requestData.resize(request.header.payloadSize);

	/* pack the header */
	std::string unhexUID = Utils::reverse_hexi(_uid);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestData.data(), &request, REQUEST_HEADER_SIZE);

	/* extract file name for the client file path */
	string fileName1 = _filePath.substr(_filePath.find_last_of("/\\") + 1);
	if (fileName1.length() > FILE_NAME_SIZE)
	{
		cout << "[ERROR] The file name is too long, please try again." << endl;
		return false;
	}
	uint32_t ContentSize = _fileContent.size();
	uint32_t encrtpytedContentSize = _encryptedContent.size();
	/* pack the payload */
	memcpy(requestData.data() + REQUEST_HEADER_SIZE, &encrtpytedContentSize, CONTENT_SIZE);
	memcpy(requestData.data() + REQUEST_HEADER_SIZE + CONTENT_SIZE, &ContentSize, ORIGIN_FILE_SIZE);
	memcpy(requestData.data() + REQUEST_HEADER_SIZE + CONTENT_SIZE + ORIGIN_FILE_SIZE, &_packetNum, PACKET_NUM);
	memcpy(requestData.data() + REQUEST_HEADER_SIZE + CONTENT_SIZE + ORIGIN_FILE_SIZE + PACKET_NUM,&_totalPackets, TOTAL_PACKETS);
	int new_size = REQUEST_HEADER_SIZE + CONTENT_SIZE + ORIGIN_FILE_SIZE + PACKET_NUM + TOTAL_PACKETS;
	memcpy(requestData.data() + new_size, fileName1.c_str(), FILE_NAME_SIZE);
	memset(requestData.data() + new_size + fileName1.length(), '\0', FILE_NAME_SIZE - fileName1.length());
	memcpy(requestData.data() + new_size + FILE_NAME_SIZE, _chunkData.c_str(), _chunkData.size());
	return true;
}

/*This function manage the send file request, determine how many packet will be in total and sending*/
void Client::manageSendFileRequest(vector<std::uint8_t>& requestBuffer, uint16_t packetNum,size_t start, size_t end)
{
	_packetNum = packetNum;	
	/*Calculate the total packets*/
	_encryptedContent = encryptFileUsingAESKey(_fileContent);
	_totalPackets = static_cast<uint16_t>(_encryptedContent.size() / CHUNK_SIZE_CONTENT);
	if ((_encryptedContent.size() % CHUNK_SIZE_CONTENT) != 0)
	{
		_totalPackets += 1;
	}	
	_chunkData = encryptFileUsingAESKey(_fileContent.substr(start, end));
	//First we senf the file details
	if (start == 0 && end == 0)
	{
		_chunkData = "";
	}	
	createSendFileRequest(requestBuffer);
}


/*Creating and packing CRC file Request */
bool Client::createCrcRequest(vector<std::uint8_t>& requestData,size_t codeRequest)
{
	requestData.clear();
	requestData.resize(PACKET_SIZE);

	CRCRequest request(static_cast<uint16_t>(codeRequest), FILE_NAME_SIZE);
	std::string unhexUID = Utils::reverse_hexi(_uid);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestData.data(), &request, REQUEST_HEADER_SIZE);

	string fileName = _filePath.substr(_filePath.find_last_of("/\\") + 1);

	if (fileName.length() > FILE_NAME_SIZE)
	{
		cout << "[ERROR] The file name is too long, please try again." << endl;
		return false;
	}

	memcpy(requestData.data() + REQUEST_HEADER_SIZE, fileName.c_str(), FILE_NAME_SIZE);
	memset(requestData.data() + REQUEST_HEADER_SIZE + fileName.length(), '\0', FILE_NAME_SIZE - fileName.length());
	return true;
}

/*Unpacking the Server's responses*/
ServerResponse* Client::unpackResponse(vector<uint8_t> responseBuffer, const uint32_t size)
{
	ServerResponse* res = new ServerResponse;
	/* unpack and copy the server response header */
	res->header.version = responseBuffer[0];
	res->header.code = *reinterpret_cast<uint16_t*>(&responseBuffer[VERSION_SIZE]);
	res->header.payloadSize = *reinterpret_cast<uint32_t*>(&responseBuffer[VERSION_SIZE + CODE_SIZE]);
	
	/* unpack and copy the server response payload */
	uint32_t leftOver = size - HEADER_SIZE;
	if (res->header.payloadSize < leftOver)
		leftOver = res->header.payloadSize;
	res->payload.payload = new uint8_t[leftOver];
	memcpy(res->payload.payload, responseBuffer.data() + HEADER_SIZE, leftOver);
	return res;
}
/*Checking the server's response content to Registeration Request */
string Client::handleRegisterationRequest(vector<uint8_t>& responseBuffer, uint16_t code)
{
	if (code == CodeResponses::FAILED_REGISTRATION)
	{
		cout << "[ERROR] You are already registered." << endl;
		return "";
	}
	ServerResponse* res = unpackResponse(responseBuffer,PACKET_SIZE);
	if (!checkResponse(*res, UID_SIZE))
	{
		delete res;
		return "";
	}
	_uid = Utils::hexi(res->payload.payload, UID_SIZE);
	delete res;
	return _uid;
}
/*Checking the server's response content to Send File Request */
int Client::handleSendFileRequest(vector<uint8_t>& responseBuffer)
{
	ServerResponse* res = unpackResponse(responseBuffer, PACKET_SIZE);
	size_t payloadSize = UID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE + CRC_SIZE;
	if (!checkResponse(*res, payloadSize))
	{
		delete res;
		return -1; // -1 to mark this error.
	}
	unsigned int clientCrc = CheckSum::readfile(_filePath);
	int crcPosition = (payloadSize - CRC_SIZE) + HEADER_SIZE;
	uint32_t serverCrc = *reinterpret_cast<uint32_t*>(&responseBuffer[crcPosition]);
	if (serverCrc == clientCrc)
	{
		delete res;
		return true;
	}
	else
	{
		delete res;
		return false;
	}
}
/*Checking the server's response content to Symmetry Key Request */
string Client::handleSymmetryKeyRequest(vector<uint8_t>& responseBuffer, uint16_t code)
{
	ServerResponse* res = unpackResponse(responseBuffer, PACKET_SIZE);
	if (!checkResponse(*res, PUBLIC_KEY_SIZE+UID_SIZE))
	{
		delete res;
		return "";
	}
	_AESKey = extractAESKey(res->payload.payload, res->header.payloadSize);
	delete res;
	return _AESKey;
}
/*Checking the server's response content to Valid CRC or Fourth invalid crc requests. */
void Client::handleAcceptMessageResponse(vector<uint8_t>& responseBuffer)
{
	ServerResponse* res = unpackResponse(responseBuffer, PACKET_SIZE);
	if (!checkResponse(*res, UID_SIZE))
	{
		delete res;
	}
	string uid = Utils::hexi(&responseBuffer[HEADER_SIZE], UID_SIZE);

	if (uid != _uid)
	{
		cout << "[ERROR] There is no match between the client ID to the ID in the server response." << endl;
		delete res;
	}
	delete res;
};
/*Reading the contect from transfer.info file and me.info file*/
void Client::readFiles(string& ip, string& port, bool& registered) {
	FileHandler* file_handler = new FileHandler();
	/*checking firstly if me.info file exists*/
	if (!file_handler->checkExsistanceFile(ME_FILE))
	{
		cout << "[INFO] me.info file not exists, reading transfer.info file." << endl;
		readTransferFile(ip, port);
	}
	else
	{
		/* if me.info file is exists it is sign that the client resigtered.*/
		registered = true;
		cout << "[INFO] me.info file is exists, reading transfer.info file." << endl;
		readTransferFile(ip, port);
		cout << "[INFO] Reading me.info file." << endl;
		/*Reading the content from me.info*/
		if (file_handler->openFile(ME_FILE, true)) {

			std::string* resultData = file_handler->readFileData(ME_FILE, MAX_ME_LINES);
			_name = resultData[FIRST_LINE];
			_uid = resultData[SECOND_LINE];
			_base64privateKey = resultData[THIRD_LINE];
			delete[] resultData;
		}
	}
	delete file_handler;
};
/*Reading the contect from transfer.info file*/
void Client::readTransferFile(string& ip, string& port)
{
	FileHandler* file_handler = new FileHandler();
	bool is_exists = file_handler->checkExsistanceFile(TRANSFER_FILE);
	/*Reading the content from transfer.info*/
	if(is_exists)
	{
		if (file_handler->openFile(TRANSFER_FILE, is_exists)) {
			Utils* handleAddress = new Utils();
			std::string* resultData = file_handler->readFileData(TRANSFER_FILE, MAX_LINES);
			ip = handleAddress->findIp(resultData[FIRST_LINE]);
			port = handleAddress->findPort(resultData[FIRST_LINE]);
			_name = resultData[SECOND_LINE];
			_filePath = resultData[THIRD_LINE];
			if (!file_handler->checkExsistanceFile(_filePath))
			{
				cout << "[ERROR] The file path in the transfer.info is not exists." << endl;
				delete file_handler;
				delete[] resultData;
				delete handleAddress;
				system("pause");
				exit(1);
			}
			_fileContent = file_handler->extractFileContent(_filePath);
			delete[] resultData;
			delete handleAddress;
			delete file_handler;
		}
	}
	else
	{
		cout << "[ERROR] transfer.info file is not exists." << endl;
		delete file_handler;
		system("pause");
		exit(1);
	}
}

/*creating me.info file*/
bool Client::creatingMeInfo(bool& registered)
{
	registered = true;
	FileHandler* file_handler = new FileHandler();
	RSAKeysWraper* rsa = new RSAKeysWraper();
	/* get the RSA public key */
	_publicKey = rsa->getPublicKey();

	/* get the RSA private key decoded as base64 using Base64Wrapper */
	_base64privateKey = Utils::encode(rsa->getPrivateKey());

	if (!file_handler->openFile(ME_FILE, false))
	{
		delete file_handler;
		delete rsa;
		return false;
	}

	/* write the client info into me.info file */
	file_handler->writeLine(_name);
	file_handler->writeLine(_uid);
	file_handler->writeAtOnce(_base64privateKey);
	delete file_handler;
	delete rsa;
	return true;
}
/*creating priv.key file*/
bool Client::creatingPrivKey()
{
	FileHandler* file_handler = new FileHandler();
	if (!file_handler->openFile(KEY_FILE, false))
	{
		delete file_handler;
		return false;
	}
	/* write the client info into me.info file */
	file_handler->writeAtOnce(_base64privateKey);
	delete file_handler;
	return true;
}

/*This function decrypt aes key*/
string Client::extractAESKey(uint8_t* payload, uint32_t len)
{
	FileHandler* file_handler = new FileHandler();
	/* get the client private key from me.info */
	string base64key = file_handler->extractBase64privateKey(KEY_FILE);
	RSAKeysWraper rsapriv_other(Utils::decode(base64key));

	/* get the AES key using client private key */
	_AESKey = rsapriv_other.decrypt(reinterpret_cast<const char*>(&payload[UID_SIZE]), len - UID_SIZE);
	delete file_handler;

	return _AESKey;
}
/*This function encrypt the file content*/
string Client::encryptFileUsingAESKey(string fileContent)
{
	AESWrapper aes((unsigned char*)_AESKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);
	string ciphertext = aes.encrypt(fileContent.c_str(), fileContent.size());
	
	return ciphertext;

}
/*This function checking weather the version and the payload in server's response are valid.*/
bool Client::checkResponse(ServerResponse& res, size_t payloadSize)
{
	if (int(res.header.version) != VERSION)
	{
		cout << "[ERROR] There is no match between client's version to the server's version." << endl;
		return false;
	}
	if (res.header.payloadSize > payloadSize)
	{
		cout << "[ERROR] The payload size is invalid" << endl;
		return false;
	}
	return true;
}

