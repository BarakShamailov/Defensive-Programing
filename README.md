# Storage Server

This project is a client-server software that allows clients to transfer files encrypted from their computers to the server for storage. The server is written in Python and the client is written in C++.

* In this project, SQL is used to store data about the clients registered on the server and to store the transferred files on the server.
* Usage of parallel programming and mutual exclusion.
* Asymmetric and symmetric encryption are used to transfer the content of the file in an encrypted manner. The server side uses the PyCryptodome library, while the client side uses the CryptoPP library.
* TCP communication is used, with the client side utilizing the boost library.

## Architecture

The software architecture is based on a client-server model. The client initiates communication with the server, exchanges encryption keys with it, and then transfers the requested file to the server using encrypted communication.

The client ensures that the server receives the file correctly by comparing checksums on both sides. If the file transfer fails, the client attempts to resend it up to three times.

![image](https://github.com/BarakShamailov/Defensive-Programing/assets/62948065/dc13b0de-8ecd-4a9f-8ef4-ae4f40848e9c)

## Prerequisites
1. Install CryptoPP package for the client side.
2. Install PyCryptodome for the server side:
   ```bash
   > pip install pycryptodome
   ```
