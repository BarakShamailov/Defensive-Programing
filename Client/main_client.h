#pragma once
#include <functional>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "client.h"
#include "constants.h"
#include "file_handler.h"
#include "utils.h"
#include "protocol.h"

using boost::asio::io_context;
using boost::asio::ip::tcp;
using namespace boost::asio;
using namespace std;

class ClientSession {
private:
    boost::asio::io_context* _io_context;
    tcp::resolver* _resolver;
    tcp::socket* _socket;
    string _ip;
    string _port;
    bool _registered;
    bool _validFile;
    bool _generalError;
    string _fileName;



public:
    ClientSession();
    ~ClientSession();
    bool write(vector<uint8_t>& requestBuffer);
    void read(vector<uint8_t>& responseBuffer);
    bool connectToServer();
    void handler_session();
    void printingFatalError();
    void handler_responses(vector<uint8_t>& responseBuffer, Client& client);
    void closingConnection();
    void handleRequestFile(vector<uint8_t>& requestBuffer, Client& client);
};

