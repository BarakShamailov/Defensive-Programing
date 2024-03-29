#pragma once
#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "protocol.h" // Assuming RegisterationRequest is defined here


using namespace std;

class Client
{
private:
    string _name;
    string _filePath;
    string _base64privateKey;
    string _AESKey;
    string _uid;
    string _publicKey;
    string _privateKey;
    string _encryptedContent;
    string _fileContent;
    string _chunkData;
    uint16_t _packetNum;
    uint16_t _totalPackets;
    uint32_t _clientCRC;
   
    

public:
    Client();
    string handleRegisterationRequest(vector<uint8_t>& responseBuffer, uint16_t code);
    string handleSymmetryKeyRequest(vector<uint8_t>& responseBuffer, uint16_t code);
    int handleSendFileRequest(vector<uint8_t>& responseBuffer);
    void handleAcceptMessageResponse(vector<uint8_t>& responseBuffer);
    ServerResponse* unpackResponse(vector<uint8_t> responseBuffer, const uint32_t size);
    void createRegisterationRequest(vector<uint8_t>& requestData);
    void createSymmetryKeyRequest(vector<uint8_t>& requestData);
    void createReconnectionRequest(vector<uint8_t>& requestData);
    bool createSendFileRequest(vector<std::uint8_t>& requestBuffer);
    bool createCrcRequest(vector<std::uint8_t>& requestData, size_t codeRequest);
    bool creatingMeInfo(bool& registered);
    bool creatingPrivKey();
    void manageSendFileRequest(vector<std::uint8_t>& requestBuffer, uint16_t packetNum, size_t start, size_t end);
    void readFiles(string& ip, string& port, bool& registered);
    void readTransferFile(string& ip, string& port);
    string extractAESKey(uint8_t* payload, uint32_t len);
    string encryptFileUsingAESKey(string fileContent);
    bool checkResponse(ServerResponse& res, size_t payloadSize);

   



};
