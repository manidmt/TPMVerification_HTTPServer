# TPMVerification_Server

This repository contains two main files: `server.go` and `client.go`. These are designed to be used in a Raspberry Pi device.

## Interaction Overview

The interaction between these two files is as follows:

1. **Server Initialization**: 
   - First, the server is activated and starts running on port 8080.
   
2. **Client Initialization**: 
   - Once the server is running, the client can interact with it. 
   - The client will initialize its TPM (Trusted Platform Module) and retrieve its data to send to the server for validation using a CA (Certificate Authority) certificate.

3. **Server Validation**: 
   - If the validation is successful, the server will generate a challenge using the Public EK (Endorsement Key) that the client previously sent and will send this challenge to the client.

4. **Client Challenge Response**: 
   - The client must solve this challenge to continue with the verification process. 
   - Once the challenge has been passed, the server will create a nonce which allows the client to create the attestation platform parameters and send them back to the server.

5. **Parameter Verification**: 
   - The server will check these parameters, and if everything is correct, a value of the PCR (Platform Configuration Register) will be used to store the client data in a database. 
   - This data will be identified with a randomly generated session ID.

## Getting Started

### Prerequisites

- Go programming language installed
- TPM device or simulator
- CA certificate for validation
- MariaDB installed

### Running the Server

1. Navigate to the directory containing `server.go`.
2. Run the following command to start the server:
   ```sh
   go run server.go

### Running the Client
1. Navigate to the directory containing `client.go`.
2. Run the following command to start the client:
   ```sh
   go run client.go
3. You can run as many client as you want
