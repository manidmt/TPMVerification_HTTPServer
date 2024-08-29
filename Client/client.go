/**
 * Client program
 *
 * This program is the client side of the attestation process.
 * It initializes the TPM, gets the TPM data, sends the attestation parameters to the server,
 * receives the encrypted credentials, decrypts them, sends the secret to the server, performs the attestation,
 * sends the attestation parameters to the server and receives the UID.
 *
 * @authors: Manuel Díaz-Meco, Miguel Ángel Mesa
 * @version: 2.0
 */

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	"github.com/google/go-attestation/attest"
)

/**
 * sendRequest function
 *
 * Sends a POST request to the server with the given URL, content type, body and client.
 * Returns the response body and an error if any.
 *
 * @param url string - URL to send the request to
 * @param contentType string - Content type of the request
 * @param body []byte - Body of the request
 * @param client *http.Client - HTTP client to use for the request
 *
 * @return []byte, error
 */

func sendRequest(url string, contentType string, body []byte, client *http.Client) ([]byte, error) {

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)

	//fmt.Printf("Data being sent: %s\n", string(body))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	//fmt.Printf("Response from server: %s\n", responseBody)
	return responseBody, nil
}

/**
 * tpmData function
 *
 * Gets the TPM data and generates the attestation key.
 * Returns the attestation key and the attestation parameters.
 *
 * @param tpm *attest.TPM - TPM to get the data from
 *
 * @return []byte, []byte
 */

func tpmData(tpm *attest.TPM) ([]byte, []byte) {

	// Get endorsement keys (EKs) from the TPM
	eks, err := tpm.EKs() // Returns the EKs stored in the TPM
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting EKs from TPM: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "There is %d EKs in TPM 2.0 chip\n", len(eks))
	ek := eks[0]

	// Get TPM information
	tpmInfo, err := tpm.Info() // Gets all info from the TPM, manufacturer, version, etc.
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Vendor Name from TPM: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Version of TPM 2.0 chip : %v\n", tpmInfo.Version)
	fmt.Fprintf(os.Stdout, "Interface of TPM 2.0 chip : %v\n", tpmInfo.Interface)
	fmt.Fprintf(os.Stdout, "Vendor info of TPM 2.0 chip : %v\n", tpmInfo.VendorInfo)
	fmt.Fprintf(os.Stdout, "Vendor Name of TPM 2.0 chip : %s\n", tpmInfo.Manufacturer.String())
	fmt.Fprintf(os.Stdout, "Firmware version of TPM 2.0 chip : %d.%d\n", tpmInfo.FirmwareVersionMajor, tpmInfo.FirmwareVersionMinor)

	// Generate a new Attestation Key (AK)
	akConfig := &attest.AKConfig{} // Encapsulates config for the AK key
	ak, err := tpm.NewAK(akConfig) // Create new attestation key
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating AK in TPM: %v\n", err)
		os.Exit(1)
	}

	akAttestParams := ak.AttestationParameters() // Returns info about the AK for credential activation challenge
	akBytes, err := ak.Marshal()                 // Serializes the AK
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling AK: %v\n", err)
		ak.Close(tpm)
		os.Exit(1)
	}

	// Next step: Send attestation parameters to Attestation CA and wait for OK
	type Message struct {
		TPMVersion attest.TPMVersion
		EKPublic   []byte
		EKCert     x509.Certificate
		AK         attest.AttestationParameters
	}

	// Convert the EK public key to PEM format
	derBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		fmt.Print(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
	fmt.Print("\nSending the attestation parameters to server...\n")

	// Create the message with attestation parameters and send it to the server
	data2send := Message{attest.TPMVersion20, pemBytes, *eks[0].Certificate, akAttestParams}
	m2s, _ := json.Marshal(data2send)

	return m2s, akBytes
}

/**
 * exitError function
 *
 * Exits the program with an error message if an error is found.
 *
 * @param err error - Error to check
 * @param message string - Message to print
 */

func exitError(err error, message string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", message, err)
		os.Exit(1)
	}
}

/**
 * main function
 *
 * Main function of the client program.
 * It initializes the TPM, gets the TPM data, sends the attestation parameters to the server,
 * receives the encrypted credentials, decrypts them, sends the secret to the server, performs the attestation,
 * sends the attestation parameters to the server and receives the UID.
 */

func main() {

	url := "http://localhost:8080"
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
		Jar:     jar,
	}

	// Initialize TPM access
	config := &attest.OpenConfig{}     // Configures settings to open the TPM
	tpm, err := attest.OpenTPM(config) // Opens the TPM
	exitError(err, "Error opening the TPM")
	defer tpm.Close()

	m2s, akBytes := tpmData(tpm)
	body, err := sendRequest(url+"/tpmData", "application/json", m2s, client)
	exitError(err, "Error sending attestation parameters to server")

	type EnCred struct {
		EncryptedCredential attest.EncryptedCredential
	}
	var ec EnCred

	fmt.Print("Receiving encrypted credentials from server...\n")
	err = json.Unmarshal(body, &ec)
	exitError(err, "Error unmarshalling encrypted credentials")

	// Deserialize the AK
	ak, err := tpm.LoadAK(akBytes)
	exitError(err, "Error loading AK")

	// Decrypts the EnCred using the key, proving that the AK was generated by the same TPM as the EK
	secret, err := ak.ActivateCredential(tpm, ec.EncryptedCredential)
	exitError(err, "Error activating Credential Activation Challenge")

	nonce, err := sendRequest(url+"/challenge", "application/octet-stream", secret, client)
	exitError(err, "Error sending the secret to server")

	// Perform the attestation: Full PCR read is performed
	fmt.Print("Starting attestation... \n\n")
	params, err := tpm.AttestPlatform(ak, []byte(nonce), &attest.PlatformAttestConfig{EventLog: []byte{0}})
	exitError(err, "Error attesting platform state")

	// Send attestation parameters
	type attestParams struct {
		Parameters attest.PlatformParameters
		AKPublic   []byte
	}
	params2send := attestParams{*params, akBytes}
	p2s, _ := json.Marshal(params2send)

	//fmt.Printf("Sending attestation parameters to server %v\n", p2s)
	body, err = sendRequest(url+"/dbRegistation", "application/json", p2s, client)
	exitError(err, "Error sending attestation parameters to server")

	// Receive the UID from the Attestation CA to be able to communicate with ACME CA
	sessionID := string(body)
	fmt.Printf("Session ID generated: %s \n", sessionID)

	/*
		// Next step would be calling the ACME Client to start the ACME challenge
		// There, the UID would be checked for validity
		cmd := exec.Command("./test-device-attest", "-serial", sessionID)
		stdout, err := cmd.Output()

		if err != nil {
			fmt.Println(err.Error())
			return
		}
		// Print the output
		fmt.Println(string(stdout))

		os.Exit(0)*/
}
