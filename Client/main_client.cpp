#include "main_client.h"
#include "utils.h"
#include "aes_wraper.h"
#include "rsa_wraper.h"
#include "protocol.h"
#include "cksum.h"
#include <iostream>
#include <algorithm>



using namespace boost::asio;

ClientSession::ClientSession()
{
	_io_context = new io_context();
	_socket = new tcp::socket(*_io_context);
	_resolver = new tcp::resolver(*_io_context);
	_registered = false;
	_validFile = false;
	_generalError = false;
	_fileName = "";
};
ClientSession::~ClientSession()
{
	delete _io_context;
	delete _socket;
	delete _resolver;
};

/*This Function closing the connection and program*/
bool ClientSession::connectToServer()
{
	try
	{
		auto endpoint = _resolver->resolve(_ip, _port);
		boost::asio::connect(*_socket, endpoint);
		_socket->non_blocking(false);
	}
	catch (...)
	{
		cout << "[ERROR] There is problem to setup the server.\nPlease check the IP and the Port that you entered and try again" << endl;
		return false;
	}
	return true;
};

/*This Function closing the connection and program*/
void ClientSession::closingConnection()
{
	cout <<  "\n[INFO] Closing connection." << std::endl;
	delete this;
	system("pause");
	exit(1);
};
void ClientSession::printingFatalError()
{
	cout << "\n[Fatal Error]: The request has been rejected by the server." << endl;
	cout << "This could stem from technical problems on the server, invalid parameters in the header request, or if there is no match between your data and the data in the server's database." << endl;

};

/*This Function write and sending the client's data to the server*/
bool ClientSession::write(vector<uint8_t>& requestBuffer)
{
	boost::system::error_code error;
	const size_t len = boost::asio::write(*_socket, boost::asio::buffer(requestBuffer.data(), PACKET_SIZE), error);
	if (len == 0)
	{
		/* error. Failed sending and shouldn't use buffer.*/
		return false;
	}

	if (error)
	{

		return false;
	}
	return true;
};
/*This Function Read the server response data*/
void ClientSession::read(vector<uint8_t>& responseBuffer)
{
	boost::system::error_code error;
	

	// Set up a deadline timer to cancel the blocking read operation if it takes too long
	boost::asio::deadline_timer timer(*_io_context);
	timer.expires_from_now(boost::posix_time::seconds(1));

	// Start asynchronous read operation
	_socket->async_read_some(boost::asio::buffer(responseBuffer),
		[&](const boost::system::error_code& ec, std::size_t bytes_transferred)
		{
			if (!ec)
			{
				// Read operation completed successfully
				std::cout << "[INFO] The server response message was successfully read." << std::endl;
			}
			else if (ec == boost::asio::error::operation_aborted)
			{
				// Read operation was cancelled due to timeout
				std::cout << "[ERROR] read operation timed out." << std::endl;
			}
			else
			{
				// Error occurred during read operation
				std::cout << "[ERROR] read failed: " << ec.message() << std::endl;
			}
		});

	// Wait for the deadline timer to expire
	timer.async_wait([&](const boost::system::error_code& ec)
		{
			if (ec != boost::asio::error::operation_aborted)
			{
				// Cancel the read operation if it's still in progress
				_socket->cancel();
			}
		});
	// Run the IO context to perform asynchronous operations
	_io_context->run();
	_io_context->restart();


}


/*Determines which function to execute by the request code.*/
void ClientSession::handler_responses(vector<uint8_t>& responseBuffer, Client& client)
{
	/*Poping the code request from server's response*/
	uint16_t code_response = *reinterpret_cast<uint16_t*>(&responseBuffer[VERSION_SIZE]);	
	if (code_response == SUCCESSFUL_REGISTRATION || code_response == FAILED_REGISTRATION)
	{
		string uid = client.handleRegisterationRequest(responseBuffer, code_response);
		if (uid == "")
		{
			closingConnection();
		}
		else if (!client.creatingMeInfo(_registered))
		{
			cout << "[ERROR] Can't create me.info file." << endl;
			closingConnection();
		}
		else if (!client.creatingPrivKey())
		{

			cout << "[ERROR] Can't create priv.key file." << endl;
			closingConnection();
		}
		else
		{
			cout << "[INFO] Registration request performed successfully." << endl;
		}
	}
	else if (code_response == PUBLIC_KEY_RESPONSE || code_response == ACCEPT_RECONNECTION_REQUEST)
	{
		cout << "[INFO] Got aes key from server." << endl;
		string AESKey = client.handleSymmetryKeyRequest(responseBuffer, code_response);
		if (AESKey == "")
		{
			closingConnection();
		}
		
	}
	else if (code_response == REJECT_RECONNECTION_REQUEST)
	{
		cout << "[INFO] The server rejected your reconnection request, please restart and try again." << endl;
		_registered = false;

	}
	else if (code_response == GOT_VALID_FILE)
	{
		int result = client.handleSendFileRequest(responseBuffer);
		if (result == -1) // Error
		{
			closingConnection();
		}
		_validFile = result;
	}
	else if (code_response == ACCEPT_MESSAGE)
	{
		client.handleAcceptMessageResponse(responseBuffer);
	}
	else if (code_response == GENERAL_ERROR)
	{
		std::cout << "[INFO]: Server responded with an error." << endl;
		_generalError = true;
	}
	responseBuffer.clear();
	responseBuffer.resize(PACKET_SIZE);

};

/*Manage the send file request */
void ClientSession::handleRequestFile(vector<uint8_t>& requestBuffer, Client& client)
{
	requestBuffer.clear();
	requestBuffer.resize(PACKET_SIZE);
	size_t sentBytes = 0;
	//Firstly we create a send file request to know how many packes will we need.
	client.manageSendFileRequest(requestBuffer,1, sentBytes, sentBytes);
	uint32_t contentSize = *reinterpret_cast<uint32_t*>(&requestBuffer[REQUEST_HEADER_SIZE]);
	int totalPacketsPosition = REQUEST_HEADER_SIZE + ORIGIN_FILE_SIZE + CONTENT_SIZE + PACKET_NUM;
	uint16_t totalPackets = *reinterpret_cast<uint16_t*>(&requestBuffer[totalPacketsPosition]);	
	//sending the file data in chunks after we know the total packet that needed.
	for (uint16_t i = 0; i < totalPackets;)
	{
		size_t remainingBytes = contentSize - sentBytes;
		size_t currentChunkSize = std::min((size_t)CHUNK_SIZE_CONTENT, remainingBytes);
		i += 1;
		client.manageSendFileRequest(requestBuffer, i, sentBytes, currentChunkSize);
		write(requestBuffer);
		sentBytes += currentChunkSize;
	}
}
/*Run the client by the protocol*/
void ClientSession::handler_session() {
	
	Client* c = new Client();
	c->readFiles(_ip, _port, _registered);
	connectToServer();
	cout << "[INFO] The client connected to the server, The client's version is "<< VERSION <<"." << endl;
	vector<uint8_t> requestData(PACKET_SIZE);
	vector<uint8_t> responseData(PACKET_SIZE);
	while (1)
	{
		if (!_registered)
		{
			for (int i = 0; i < MAX_SENDS; i++)
			{
				//////////////// Registration request///////////////
				_generalError = false;
				cout << "\n[INFO] Sending Registration request." << endl;
				c->createRegisterationRequest(requestData);
				write(requestData);
				cout << "[INFO] Server responded to Registration request." << endl;
				read(responseData);
				handler_responses(responseData, *c);
				if (_generalError)
				{
					if (i == MAX_SENDS - 1)
					{
						printingFatalError();
						closingConnection();
					}
					continue;
					
				}
				break;
			}
			for (int i = 0; i < MAX_SENDS; i++)
			{
				_generalError = false;
				////////////////Symmetry Key request///////////////
				cout << "\n[INFO] Sending Symmetry Key Request." << endl;
				c->createSymmetryKeyRequest(requestData);
				write(requestData);
				cout << "[INFO] Server responded to Symmetry Key Request." << endl;
				read(responseData);
				handler_responses(responseData, *c);
				if (_generalError)
				{
					if (i == MAX_SENDS - 1)
					{
						printingFatalError();
						closingConnection();
					}
					continue;

				}
				break;
			}
		}
		else
		{		
			////////////////Reconnection request///////////////
			for (int i = 0; i < MAX_SENDS; i++)
			{
				_generalError = false;
				cout << "\n[INFO] Sending Reconnection request." << endl;
				c->createReconnectionRequest(requestData);
				write(requestData);
				cout << "[INFO] Server responded to Reconnection request." << endl;
				read(responseData);
				handler_responses(responseData, *c);
				if (!_registered)
				{
					closingConnection();
				}
				if (_generalError)
				{
					if (i == MAX_SENDS - 1)
					{
						printingFatalError();
						closingConnection();
					}
					continue;

				}
				break;
			}
		}
		for (int i = 0; i < MAX_SENDS; i++)
		{
			_generalError = false;

			//Sending Send File Request
			cout << "\nThe number attempet: " << i + 1 << ".\n[INFO] Sending Send File Request, it can take a while." << endl;
			handleRequestFile(requestData, *c);
			cout << "[INFO] Server responded to Send File Request." << endl;
			read(responseData);
			handler_responses(responseData, *c);
			if (_generalError)
			{
				if (i == MAX_SENDS - 1)
				{
					printingFatalError();
					closingConnection();
				}
				continue;

			}
			if (_validFile)
			{
				cout << "\n[INFO] Sending Valid CRC Request." << endl;
				c->createCrcRequest(requestData,VALID_CRC_REQUEST);
				write(requestData);
				cout << "[INFO] Server responded to Valid CRC Request." << endl;
				read(responseData);
				handler_responses(responseData, *c);
				cout << "[INFO] The file was successfully received by the server and the file is valid." << endl;
				break;
			}
			else
			{
				//Sending Fourth Invalid CRC Request	
				if (i == MAX_SENDS - 1) {
					cout << "\n[INFO] The file was not received properly on the fourth attempt." << endl;
					cout << "[INFO] Sending Fourth Invalid CRC Request." << endl;
					c->createCrcRequest(requestData, FOURTH_INVALID_CRC_REQUEST);
					write(requestData);
					cout << "[INFO] Server responded to Fourth Invalid CRC Request." << endl;
					read(responseData);
					handler_responses(responseData, *c);
				}
				else {
					//Sending Invalid CRC Request
					cout << "\n[INFO] Sending Invalid CRC Request." << endl;
					c->createCrcRequest(requestData, INVALID_CRC_REQUEST);
					cout << "[INFO] The file was not received properly, trying an new attempet." << endl;
					write(requestData);
				}
			}			
		}
		break;
	}
	delete c;
	cout << "\n[INFO] Process has been finished." << endl;
	closingConnection();
};

int main()
{
	ClientSession* c_s = new ClientSession();
	c_s->handler_session();
	
	delete c_s;
	return 0;
};