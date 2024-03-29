import os
import struct
import protocol
import socket
import cksum
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import uuid
import threading
import datetime
import db
import utils


FILES_FOLDER = "files" # The folder that will store the client's files.
PORT_FILE = "port.info.txt"
DEFAULT_PORT = 1256
DEFAULT_IP = "127.0.0.1"
VERSION = 3
PACKET_SIZE = 2048
START_POS_CODE = 17 # The index that Code Request end
END_POS_CODE = 19 # The index that Code Request end
START_POS_CODE_RES = 1 # The index that Code response start
END_POS_CODE_RES = 3 # The index that Code response end

class Server:

    def __init__(self):
        self.port = self.reading_port_server()
        self.clients = dict()
        self.files = dict()
        self.database = db.DataBase()
        self.loading_database()
        self.lock = threading.Lock()
        # A data structure that determines which function to execute by the request code.
        self.request_handle = {
            protocol.ClientRequestsCode.REGISTRATION_CLIENT_REQUEST.value: self.handle_client_register_request,
            protocol.ClientRequestsCode.SYMMETRY_KEY_REQUEST.value: self.handle_symmetry_key_request,
            protocol.ClientRequestsCode.RECONNECTION_REQUEST.value : self.handle_reconnection_request,
            protocol.ClientRequestsCode.SEND_FILE_REQUEST.value: self.handle_send_file_request,
            protocol.ClientRequestsCode.VALID_CRC.value: self.handle_crc_request,
            protocol.ClientRequestsCode.INVALID_CRC.value: self.handle_crc_request,
            protocol.ClientRequestsCode.FOURTH_INVALID_CRC.value: self.handle_crc_request,
        }

    def reading_port_server(self) -> int:
        if os.path.exists(PORT_FILE):
            with open(PORT_FILE,"r") as file:
                file_content = file.read()
            return int(file_content)
        else:
            print(f"[ERROR] - the file {PORT_FILE} is not found, the port will be the default port {DEFAULT_PORT}.")
            return DEFAULT_PORT
    def start_server(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((DEFAULT_IP,self.port))
            server.listen()
            print(f"\nServer start listening on {DEFAULT_IP}:{self.port}, Version:{VERSION}.")
            while True:
                connection, client_address = server.accept()
                print("Accepting connection ",client_address)
                # Using threads to support multiple clients.
                self.client = threading.Thread(target=self.client_handler, daemon=True,args=(connection,))
                self.client.start()

        except Exception as e:
            print(f"There is problem to setup the server.\nPlease check the IP and the Port that you entered and try again.\n{e}")
            exit(1)

    def client_handler(self,client_connection):
        while True:
            try:
                client_data = client_connection.recv(PACKET_SIZE)
            except ConnectionResetError:
                print("[ERROR] Client closed the connection unexpectedly.")
                client_connection.close()
                break
            # If got Empty data from the user we close the connection.
            if not client_data:
                break
            code_request = struct.unpack(f"<H", client_data[START_POS_CODE:END_POS_CODE])[0]  # Unpack the code request
            if code_request:
                # Check whether the code request is valid; if so, call the appropriate function.
                if code_request in self.request_handle.keys():
                    response = self.request_handle[code_request](client_data)
                    if not response:
                        print("[ERROR] Can't send response.")
                        break
                    else:
                        if response == bytes(protocol.ClientRequestsCode.SEND_FILE_REQUEST.value):
                            # continue to get file data in chunks
                            continue
                        client_connection.send(response)
                        code_response = struct.unpack(f"<H", response[START_POS_CODE_RES:END_POS_CODE_RES])[0]  # Unpack the code response
                        # If the response code is 1604 closing the connection.
                        if code_response == protocol.ServerResponseCode.ACCEPT_MESSAGE.value:
                            break
                else:
                    print("[ERROR] Invalid code request, please try again.")
            else:
                client_connection.close()
                print("[INFO] Connection has been closed!")
                break
        print("[INFO] Process has been finished, closing the connection.")
        client_connection.close()

    def handle_client_register_request(self,client_data: bytes) -> bytes:
        print("\n[INFO] Registration request has been received.")
        client_request = protocol.ClientRegistrationRequest()
        if not client_request.unpack(client_data):
            print("[ERROR] Can't unpack client's data")
            return self.creating_general_error_response()
        if client_request.version != VERSION:
            print("[ERROR] There is no match between client's version to server's version")
            return self.creating_general_error_response()
        server_response = protocol.ClientRegistrationResponse()
        print("[INFO] Check if the client exists in database.")
        if self.database.is_client_exists(client_request.name):
            data_response = server_response.pack(protocol.ServerResponseCode.RESPONSE_REGISTRATION_FAILED.value,len(protocol.ERROR_MESSAGE))
            print("[ERROR] The user has already registered.")
            return data_response
        client_id = uuid.uuid4().bytes
        data_response = server_response.pack(protocol.ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value,protocol.ID_SIZE,client_id)
        self.clients[client_id] = [client_request.name]
        currentTime = datetime.datetime.now().strftime('%d-%m-%y %H:%M')
        self.database.add_client(client_id, client_request.name, b"", str(currentTime),b"")
        return data_response

    def handle_symmetry_key_request(self, client_data : bytes) -> bytes:
        print("\n[INFO] Symmetry Key request has been received.")
        client_request = protocol.SymmetryKeyRequest()
        if not client_request.unpack(client_data):
            print("[ERROR] Can't unpack client's data")
            return self.creating_general_error_response()
        if client_request.version != VERSION:
            print("[ERROR] There is no match between client's version to server's version")
            return self.creating_general_error_response()
        # Checking weather the user is already in database
        print("[INFO] Checking if client exists database.")
        if not self.database.is_client_exists(client_request.name):
            print("[ERROR] The user has not been registered.")
            return self.creating_general_error_response()
        aes_key = get_random_bytes(protocol.AES_KEY_SIZE)# generating AES 256bit key
        # Updating AES key and public key to the client
        print("[INFO] Updating AES key and public key client in database.")
        self.database.update_public_key(client_request.id, client_request.public_key, aes_key)
        # Updating in the RAM's program
        print("[INFO] Updating client to RAM's program:")
        if not self.updating_clients(client_request.public_key,client_request.id,aes_key):
            return self.creating_general_error_response()
        # Encrypt the AES key with the client's public key
        public_key = RSA.import_key(client_request.public_key)
        cipher = PKCS1_OAEP.new(public_key)
        cipher_text = cipher.encrypt(aes_key)
        server_response = protocol.SymmetryKeyResponse(client_request.id,cipher_text)
        print("[INFO] Sending server response for Symmetry Key request.")
        return server_response.pack()

    def handle_reconnection_request(self, client_data: bytes) -> bytes:
        print("\n[INFO] Reconnection request has been received.")
        client_request = protocol.ReconnectionRequest()
        if not client_request.unpack(client_data):
            print("[ERROR] Can't unpack client's data")
            return self.creating_general_error_response()
        if client_request.version != VERSION:
            print("[ERROR] There is no match between client's version to server's version")
            return self.creating_general_error_response()
        print("[INFO] Checking if client exists database.")
        if not self.database.find_client_by_id(client_request.id):
            server_response = protocol.ReconnectionResponse(protocol.ServerResponseCode.REJECTED_RECONNECTION.value,
                                                            client_request.id)
            if self.database.find_client_name(client_request.id) != client_request.name:
                print("[ERROR] The user has not been registered.")
                return server_response.pack()
            print("[ERROR] The user has not been registered.")
            return server_response.pack()
        print("[INFO] The user has been registered.")
        # Encrypt AES ley with client's public key
        aes_key = self.database.get_aes_key_by_client_id(client_request.id)
        public_key = RSA.import_key(self.database.get_public_key_by_client_id(client_request.id))
        cipher = PKCS1_OAEP.new(public_key)
        cipher_text = cipher.encrypt(aes_key)
        server_response = protocol.ReconnectionResponse(protocol.ServerResponseCode.ACCEPT_RECONNECTION.value,
                                                        client_request.id,cipher_text)
        print("[INFO] Sending server response for Reconnection request.")
        return server_response.pack()

    def handle_send_file_request(self,client_data : bytes) -> bytes:
        client_request = protocol.SendFileRequest()
        if not client_request.unpack(client_data):
            print("[ERROR] Can't unpack client's data.")
            return self.creating_general_error_response()
        if client_request.version != VERSION:
            print("[ERROR] There is no match between client's version to server's version.")
            return self.creating_general_error_response()
        if not self.database.find_client_by_id(client_request.id):
            print("[ERROR] The user has not been registered.")
            return self.creating_general_error_response()
        # We are decrypt the file data
        aes_key = self.database.get_aes_key_by_client_id(client_request.id)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv=(b'\0' * protocol.IV_SIZE))
        decrypted_data = unpad(cipher.decrypt(client_request.encrypted_content),AES.block_size)
        # Writing the data file
        if not self.write_file(decrypted_data,client_request.id,client_request.file_name,client_request.packet_num, client_request.content_size):
            return self.creating_general_error_response()
        # When it is not finish to send file we continue to get Send File request without to response
        if client_request.packet_num == client_request.total_packets:
            file_path = os.path.join(FILES_FOLDER,client_request.id.hex(), client_request.file_name)
            code = protocol.ServerResponseCode.VALID_FILE.value
            server_response = protocol.SendFileResponse(code, client_request.id, client_request.content_size,
                                                        client_request.file_name.encode("utf-8"), cksum.readfile(file_path))
            # Inserting the file data in the ram and in the database
            print("[INFO] Updating the files details in RAM's program and database.")
            self.files[client_request.id,client_request.file_name] = [file_path, False]
            self.database.add_file(client_request.id, client_request.file_name, file_path, False)
            print("[INFO] Finished to write file data in server.")
            print("[INFO] Sending server response for Send File request.")
            return server_response.pack()
        # When the whole packet has not been received yet, we wait for more file data to write.
        if client_request.packet_num <= client_request.total_packets:
            if client_request.packet_num == 1:
                print("\n[INFO] Send file request has been received.")
            return bytes(client_request.code)

    def handle_crc_request(self, client_data : bytes) -> bytes:
        client_request = protocol.ValidCRCRequest()
        if not client_request.unpack(client_data):
            print("[ERROR] Can't unpack client's data.")
            return self.creating_general_error_response()
        if client_request.version != VERSION:
            print("[ERROR] There is no match between client's version to server's version.")
            return self.creating_general_error_response()
        if not self.database.find_client_by_id(client_request.id):
            print("[ERROR] The user has not been registered.")
            return self.creating_general_error_response()
        server_response = protocol.AcceptMessageResponse(protocol.ServerResponseCode.ACCEPT_MESSAGE.value,
                                                         client_request.id)
        # If got Invalid CRC request, prepare to ger send file request
        if client_request.code == protocol.ClientRequestsCode.INVALID_CRC.value:
            print("\n[INFO] Invalid CRC request has been received.")
            if not self.delete_file_in_server(client_request.id,client_request.file_name):
                return self.creating_general_error_response()
            print("[INFO] Sending server response for Invalid CRC request.")
            return bytes(protocol.ClientRequestsCode.VALID_CRC.value)
        # If got fourth invalid CRC request, closing the connection with the client.
        elif client_request.code == protocol.ClientRequestsCode.FOURTH_INVALID_CRC.value:
            print("\n[INFO] Fourth Invalid CRC request has been received.")
            if not self.delete_file_in_server(client_request.id,client_request.file_name):
                return self.creating_general_error_response()
            print("[INFO] Sending server response for Fourth Invalid CRC request.")
            return server_response.pack()
        else:
            print("\n[INFO] Valid CRC request has been received.")
        # If got Valid CRC Request
            print("[INFO] Updating the file verified value")
            if not self.update_files(client_request.id,client_request.file_name,True):
                print("[ERROR] The file has not in database or in RAM.")
                return self.creating_general_error_response()
        print("\n[INFO] Sending server response for Valid CRC Request.")
        return server_response.pack()

    """This function's goal is the create the client's file in the server"""
    def write_file(self,file_data: bytes, uid: bytes, file_name: str, packet: int, file_size: int) -> bool:
        try:
            client_folder = os.path.join(FILES_FOLDER,uid.hex())
            if not os.path.exists(client_folder):
                os.makedirs(client_folder)
        except:
            print(f"[ERROR] Error occurred when trying create folder.")
            return False
        try:
            file_path = os.path.join(FILES_FOLDER,uid.hex(), file_name)
            # First we are checking if we have enough space
            if not utils.check_disk_space(FILES_FOLDER,file_size):
                return False
            if packet == 1: # If it is the first packet we are creating the file
                with open(file_path,"wb") as file:
                    file.write(file_data)
                    return True
            else: # If it is not the first packet we are updating the file
                with open(file_path, "ab") as file:
                    file.write(file_data)
                    return True
        except:
            print(f"[ERROR] Error occurred when trying to create the file {file_name}.")
            return False

    """This function update the file details in RAM and in the database."""
    def update_files(self,uid: bytes,file_name: str, verified: bool = False) -> bool:
        with self.lock:
            if (uid,file_name) in self.files.keys():
                if not self.database.update_verified_file(uid, file_name, verified):
                    return False
                self.files[uid,file_name][-1] = verified
                return True
            else:
                return False

    """This function deleting the file that stored in the server."""
    def delete_file_in_server(self,uid: bytes, file_name: str) -> bool:
        with self.lock:
            try:
                file_path = os.path.join(FILES_FOLDER,uid.hex(), file_name)
                os.remove(file_path)
                return True
            except:
                print(f"Error occurred when trying to delete the file {file_name} in server.")
                return False

    """This function create general error response"""
    def creating_general_error_response(self) -> bytes:
        print("[INFO] Server response with an error (general error).")
        error_response = protocol.GeneralErrorResponse(protocol.ServerResponseCode.GENERAL_ERROR.value)
        return error_response.pack()

    """This function goal is to load the database data into the RAM's program"""
    def loading_database(self):
        print("[INFO] Loading clients and files data into the RAM's program.")
        for row in self.database.get_clients():
            self.clients[row[0]] = list(row[1:])
        for row in self.database.get_files():
            self.files[row[:2]] = list(row[2:])

    """This function goal is update clients data in the RAM's program"""
    def updating_clients(self, public_key: bytes, uid: str, aes: bytes) -> bool:
        with self.lock:
            if uid in self.clients.keys():
                self.clients[uid].append(public_key)
                self.clients[uid].append(aes)
                return True
            else:
                return False


if __name__ == '__main__':
    Server().start_server()

