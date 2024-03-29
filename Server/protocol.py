from enum import Enum
import struct

# sizes
ERROR_MESSAGE = "Server responded with an error"
PACKET_SIZE = 2048
SERVER_VERSION = 3
DEFAULT_VAL = 0
RESPONSE_HEADER_SIZE = 7
REQUEST_HEADER_SIZE = 23
ID_SIZE = 16
CLIENT_NAME_SIZE = 255
FILE_NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 32
IV_SIZE = 16
CONTENT_SIZE = 4
ORIGINAL_FILE_SIZE = 4
PACKET_NUMBER = 2
TOTAL_PACKETS = 2
FILE_NAME = 255

# Requests code
class ClientRequestsCode(Enum):
    REGISTRATION_CLIENT_REQUEST = 1025
    SYMMETRY_KEY_REQUEST = 1026
    RECONNECTION_REQUEST = 1027
    SEND_FILE_REQUEST = 1028
    VALID_CRC = 1029
    INVALID_CRC = 1030
    FOURTH_INVALID_CRC = 1031

# Responses code
class ServerResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESSFUL = 1600
    RESPONSE_REGISTRATION_FAILED = 1601
    RESPONSE_SYMMETRY_KEY = 1602
    VALID_FILE = 1603
    ACCEPT_MESSAGE = 1604
    ACCEPT_RECONNECTION = 1605
    REJECTED_RECONNECTION = 1606
    GENERAL_ERROR = 1607

# classes to handle with client request
class RequestHeader:

    def __init__(self):
        self.id = b""
        self.version = DEFAULT_VAL      # 1 byte
        self.code = DEFAULT_VAL         # 2 bytes
        self.payload_size = DEFAULT_VAL  # 4 bytes

# Handle Registration Request
class ClientRegistrationRequest(RequestHeader):

    def __init__(self):
        super().__init__()
        self.name = b""
    # Unpacking the client data request
    def unpack(self, data: bytes) -> bool:
        try:
            self.id, self.version, self.code, self.payload_size, self.name = struct.unpack(f"<{ID_SIZE}s BHL {CLIENT_NAME_SIZE}s", data[:REQUEST_HEADER_SIZE+CLIENT_NAME_SIZE])
            self.id = self.id.decode().rstrip("\x00")
            self.name = self.name.decode().rstrip("\x00")
            return True
        except:
            return False
# Handle Symmetry Key Request
class SymmetryKeyRequest(RequestHeader):

    def __init__(self):
        super().__init__()
        self.name = b""
        self.public_key = b""

    # Unpacking the client data request
    def unpack(self, data: bytes) -> bool:
        try:
            end_data = REQUEST_HEADER_SIZE + CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE

            self.id, self.version, self.code, self.payload_size, self.name, self.public_key = struct.unpack(
                f"<{ID_SIZE}s BHL {CLIENT_NAME_SIZE}s {PUBLIC_KEY_SIZE}s", data[:end_data])
            self.name = self.name.decode().rstrip("\x00")
            return True
        except:
            return False

# Handle Reconnection Request
class ReconnectionRequest(RequestHeader):

    def __init__(self):
        super().__init__()
        self.name = b""
    # Unpacking the client data request
    def unpack(self, data: bytes) -> bool:
        try:
            end_data = REQUEST_HEADER_SIZE + CLIENT_NAME_SIZE
            self.id, self.version, self.code, self.payload_size, self.name = struct.unpack(
                f"<{ID_SIZE}s BHL {CLIENT_NAME_SIZE}s", data[:end_data])
            self.name = self.name.decode().rstrip("\x00")
            return True
        except:
            return False
# Handle Send File Request
class SendFileRequest(RequestHeader):

    def __init__(self):
        super().__init__()
        self.content_size = DEFAULT_VAL
        self.original_file_size = DEFAULT_VAL
        self.packet_num = DEFAULT_VAL
        self.total_packets = DEFAULT_VAL
        self.file_name = b""
        self.encrypted_content = b""

    # Unpacking the client data request
    def unpack(self, data: bytes) -> bool:
        try:
            self.id, self.version, self.code, self.payload_size = struct.unpack(f"<{ID_SIZE}s BHL",
                                                                                    data[:REQUEST_HEADER_SIZE])
            end_data = self.payload_size + REQUEST_HEADER_SIZE
            encrypted_content_size = self.payload_size - (
                    FILE_NAME + TOTAL_PACKETS + CONTENT_SIZE + PACKET_NUMBER + ORIGINAL_FILE_SIZE)
            self.content_size, self.original_file_size, self.packet_num, self.total_packets, self.file_name, self.encrypted_content = struct.unpack(
                f"<L L H H {FILE_NAME}s {encrypted_content_size}s", data[REQUEST_HEADER_SIZE:end_data])
            self.file_name = self.file_name.decode("utf-8").rstrip("\x00")
            return True
        except:
            return False
# Handle Valid CRC Request
class ValidCRCRequest(RequestHeader):
    def __init__(self):
        super().__init__()
        self.file_name = b""

    # Unpacking the client data request
    def unpack(self, data: bytes) -> bool:
        try:
            self.id, self.version, self.code, self.payload_size,self.file_name = struct.unpack(f"<{ID_SIZE}s BHL {FILE_NAME_SIZE}s", data[:REQUEST_HEADER_SIZE + FILE_NAME_SIZE])
            self.file_name = self.file_name.decode("utf-8").rstrip("\x00")
            return True
        except:
            return False



# Classes to create server response
class ResponseHeader:
    def __init__(self):
        self.version = SERVER_VERSION
        self.code = DEFAULT_VAL
        self.payload = DEFAULT_VAL

# Handle Registration Response
class ClientRegistrationResponse(ResponseHeader):
    def __init__(self,id=b""):
        super().__init__()
        self.id = id

    # Packing the server data response
    def pack(self,code: int,payload: int,id: bytes = b"") -> bytes:
        self.code, self.payload, self.id = code, payload, id
        try:
            if self.code == ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value:

                    data = struct.pack(f"<BHL {ID_SIZE}s", self.version, self.code, self.payload, self.id)
                    return data
            else:
                data = struct.pack(f"<BHL {len(ERROR_MESSAGE)}s", self.version, self.code, self.payload,ERROR_MESSAGE.encode("utf-8"))
                return data

        except:
            print(f"[ERROR] Error occurred when trying to pack the server's response data.")
            return b""

# Handle Symmetry Key Response
class SymmetryKeyResponse(ResponseHeader):
    def __init__(self, id: bytes = b"", encrypted_aes_key : bytes = b""):
        super().__init__()
        self.code = ServerResponseCode.RESPONSE_SYMMETRY_KEY.value
        self.id = id
        self.encrypted_aes_key = encrypted_aes_key
        self.payload = ID_SIZE + len(self.encrypted_aes_key)

    # Packing the server data response
    def pack(self) -> bytes:

        try:
            data = struct.pack(f"<BHL {ID_SIZE}s {len(self.encrypted_aes_key)}s", self.version, self.code, self.payload,
                               self.id, self.encrypted_aes_key)
            return data
        except:
            print(f"[ERROR] Error occurred when trying to pack the server's response data.")
            return b""

# Handle Reconnection Response
class ReconnectionResponse(ResponseHeader):
    def __init__(self, code : int, id : bytes = b"",encrypted_aes_key : bytes = b""):
        super().__init__()
        self.code = code
        self.id = id
        self.encrypted_aes_key = encrypted_aes_key

    # Packing the server data response
    def pack(self) -> bytes:
        self.payload = ID_SIZE + len(self.encrypted_aes_key)
        try:
            if self.code == ServerResponseCode.REJECTED_RECONNECTION.value:
                data = struct.pack(f"<BHL {ID_SIZE}s", self.version, self.code, self.payload,
                                   self.id)
                return data
            else:
                data = struct.pack(f"<BHL {ID_SIZE}s {len(self.encrypted_aes_key)}s", self.version, self.code, self.payload,
                                   self.id, self.encrypted_aes_key)
                return data
        except:
            print(f"[ERROR] Error occurred when trying to pack the server's response data.")
            return b""
# Handle Send File Response
class SendFileResponse(ResponseHeader):
    def __init__(self, code : int, id : bytes ,content_size: int ,file_name : bytes, checksum : int):
        super().__init__()
        self.code = code
        self.id = id
        self.content_size = content_size
        self.file_name = file_name
        self.checksum = checksum

    # Packing the server data response
    def pack(self) -> bytes:
        try:
            data = struct.pack(f"<BHL {ID_SIZE}s L {FILE_NAME_SIZE}s L", self.version, self.code, self.payload,self.id,self.content_size, self.file_name, self.checksum)
            return data
        except:
            print(f"[ERROR] Error occurred when trying to pack the server's response data.")
            return b""
# Handle Accept Message Response
class AcceptMessageResponse(ResponseHeader):
    def __init__(self,code: int ,id: bytes):
        super().__init__()
        self.code = code
        self.id = id

    # Packing the server data response
    def pack(self) -> bytes:
        try:
            data = struct.pack(f"<BHL {ID_SIZE}s ", self.version, self.code, self.payload,self.id)
            return data
        except:
            print(f"[ERROR] Error occurred when trying to pack the server's response data.")
            return b""
# Handle General Error Response
class GeneralErrorResponse(ResponseHeader):
    def __init__(self,code: int):
        super().__init__()
        self.code = code

    # Packing the server data response
    def pack(self) -> bytes:
        try:
            data = struct.pack(f"<BHL", self.version, self.code, self.payload)
            return data
        except:
            print(f"[ERROR] Error occurred when trying to pack the server's response data.")
            return b""

