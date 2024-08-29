/**
 * Server
 *
 * This is the server side of the attestation protocol.
 * It receives the TPM data from the client, verifies it and generates a challenge.
 * The client sends the challenge back to the server, which verifies it and generates a nonce.
 * The client sends the nonce back to the server, which verifies the attestation data and registers the client in the database.
 *
 * @authors: Manuel Díaz-Meco, Miguel Ángel Mesa
 * @version: 2.0
 */

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/go-attestation/attest"
	"github.com/tjarratt/babble"
)

/**
 * Message struct
 *
 * This struct is used to store the message received from the client.
 * It contains the TPM version, the EK public key, the EK certificate and the attestation parameters.
 */

type Message struct {
	TPMVersion attest.TPMVersion
	EKPublic   []byte
	EKCert     x509.Certificate
	AK         attest.AttestationParameters
}

/**
 * attestParams struct
 *
 * This struct is used to store the attestation parameters received from the client.
 * It contains the platform parameters and the AK public key.
 */

type attestParams struct {
	Parameters attest.PlatformParameters
	AKPublic   []byte
}

/**
 * ClientData struct
 *
 * This struct is used to store the data of the client that is connecting to the server.
 * It contains the secret, nonce and the message that the client sends to the server.
 * The secret is used to verify the client's identity, the nonce is used to verify the attestation data
 * and the message contains the data that the client sends to the server.
 */
type ClientData struct {
	secret []byte
	nonce  []byte
	m      Message
}

var clients = make(map[string]ClientData)
var mutex = &sync.Mutex{}

/**
 * generateRandomID function
 *
 * This function generates a random ID.
 * It generates a random number and converts it to a string.
 *
 * @param max int64 - The maximum value of the random number.
 *
 * @return string - The random ID generated.
 * @return error - The error that occurred while generating the random ID.
 */

func generateRandomID(max int64) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", n.Int64()+1), nil
}

/**
 * generateNonce function
 *
 * This function generates a random nonce of 32 bytes.
 * It uses the crypto/rand package to generate the random bytes.
 *
 * @return []byte - The nonce generated.
 * @return error - The error that occurred while generating the nonce.
 */

func generateNonce() ([]byte, error) {

	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		fmt.Printf("Failed to generate nonce: %v \n", err)
		return nil, err
	}
	return nonce, nil
}

/**
 * VerifyCertificate function
 *
 * This function verifies the certificate of the EK.
 * It reads the CA certificate from the file system and verifies the EK certificate.
 *
 * @param caCertPath string - The path to the CA certificate.
 * @param cert x509.Certificate - The certificate to verify.
 *
 * @return bool - The result of the verification.
 * @return error - The error that occurred while verifying the certificate.
 */

func VerifyCertificate(caCertPath string, cert x509.Certificate) (bool, error) {

	//First step is to removed unhandled extensions, otherwise Verify will fail
	cert.UnhandledCriticalExtensions = nil

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return false, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Create a new CertPool and add the CA's certificate
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify the certificate: Need to check Intermediate & Root otherwise it fails. KeyUsages is also added as
	// EK Cert can only sign, otherwise it would fail.
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return false, fmt.Errorf("failed to verify certificate: %w", err)
	}

	return true, nil
}

/**
 * downloadCACert function
 *
 * This function downloads the CA certificate from the URL provided.
 * It reads the certificate from the URL and saves it to the file system.
 *
 * @param URL string - The URL to download the CA certificate from.
 *
 * @return string - The name of the file where the certificate was saved.
 * @return error - The error that occurred while downloading the certificate.
 */

func downloadCACert(URL string) (string, error) {

	req, _ := http.NewRequest("GET", URL, nil)
	CertName := path.Base(URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed downloading the certificate: %w", err)
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(CertName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)

		// Following the Read function recommendation:
		if n > 0 {
			f.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			// Directly return the error if it's not io.EOF
			return "", fmt.Errorf("error while downloading: %w", err)
		}
	}
	return CertName, nil
}

/**
 * verifyTPMData function
 *
 * This function verifies the TPM data received from the client.
 * It checks the URL inside the certificate and downloads the CA certificate.
 * It then verifies the certificate using the CA certificate.
 *
 * @param m Message - The message received from the client.
 *
 * @return error - The error that occurred while verifying the TPM data.
 */

func verifyTPMData(m Message) error {

	//Check the URL inside and that it points to a "valid verified" URL, then download Intermediate CA
	EKCertificate := m.EKCert
	CertURL := EKCertificate.IssuingCertificateURL
	if len(CertURL) < 1 {
		fmt.Println("No Issuing Certificate URL found in the certificate.")
		//http.Error(w, "No Issuing Certificate URL found in the certificate.", http.StatusBadRequest)
		return fmt.Errorf("No Issuing Certificate URL found in the certificate.")
	}

	// Checking if the CA URL is pointing to a known URL that contains the CA.
	// This is not secure, a DNS change can point it to another IP with a bad cert (?)
	pattern := `^https://pki.infineon.com/OptigaRsaMfrCA\d{3}\/OptigaRsaMfrCA\d{3}\.crt$`

	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Printf("Failed to compile regex: %v\n", err)
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	matched := re.MatchString(CertURL[0])
	if !matched {
		fmt.Printf("CA URL does not seem to be in the list of valid CAs")
		//http.Error(w, "CA URL does not seem to be in the list of valid CAs", http.StatusBadRequest)
		return errors.New("CA URL does not seem to be in the list of valid CAs")
	}

	// Now, download the CA cert:
	CACertName, err := downloadCACert(CertURL[0])
	if err != nil {
		fmt.Printf("Failed downloading the Cert: %v\n", err)
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	// Verify the cert:
	verified, err := VerifyCertificate(CACertName, EKCertificate)
	if err != nil {
		fmt.Printf("Certificate verification failed: %s\n", err)
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	} else {
		fmt.Printf("Certificate verified: %t\n", verified)
	}

	return nil
}

/**
 * generateChallenge function
 *
 * This function generates a challenge for the client.
 * It generates the activation parameters for the client and returns the challenge.
 *
 * @param m Message - The message received from the client.
 *
 * @return []byte - The challenge generated.
 * @return []byte - The secret generated.
 * @return error - The error that occurred while generating the challenge.
 */

func generateChallenge(m Message) ([]byte, []byte, error) {

	// Generate the Activation parameters for the Client:
	pubKeyBytes := m.EKPublic // Decode the PEM public key from EK Cert
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("Failed to parse PEM block containing the public key \n")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse DER encoded public key: %s \n", err)
		return nil, nil, err
	}

	var publicKey crypto.PublicKey
	// Assert the type of the public key
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKey = pub
	case *ecdsa.PublicKey:
		publicKey = pub
	default:
		return nil, nil, fmt.Errorf("Unknown type of public key \n")
	}

	// Server validates EK Certificate by returning an encrypted credential that the client needs to return
	akActivationParams := attest.ActivationParameters{ //Input for activating the AK
		TPMVersion: m.TPMVersion,
		EK:         publicKey,
		AK:         m.AK,
	}

	fmt.Print("Passed Activation Parameter \n")

	// Returns a credential activation challenge to verify the TPM
	secret, encryptedCredentials, err := akActivationParams.Generate()
	if err != nil {
		fmt.Printf("Error generating the challenge: %v \n", err)
		return nil, nil, err
	}
	fmt.Print("Created the challenge correctly, sending it... \n")

	// Send params to Client and receive their answer
	type EnCred struct {
		EncryptedCredential attest.EncryptedCredential
	}

	EnCred2Send := EnCred{*encryptedCredentials}
	ec2s, err := json.Marshal(EnCred2Send)
	if err != nil {
		fmt.Printf("Error unmarshalling encrypted credentials: %v \n", err)
		return nil, nil, err
	}

	return ec2s, secret, nil
}

/**
 * verifyAttestationData function
 *
 * This function verifies the attestation data received from the client.
 * It verifies the attestation data by checking the PCR values and the nonce.
 *
 * @param params attestParams - The attestation parameters received from the client.
 * @param m Message - The message received from the client.
 * @param nonce []byte - The nonce generated.
 *
 * @return attest.PCR - PRC value that will be used to register the Client in the Data Base.
 * @return error - The error that occurred while verifying the attestation data.
 */

func verifyAttestationData(params attestParams, m Message, nonce []byte) (attest.PCR, error) {

	// Check if the attestation data is correct by checking if there is a difference
	// Between the TPM signed values and the ones from the IMA in the OS
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		fmt.Print("Error opening TPM \n")
		return params.Parameters.PCRs[0], err
	}

	ak, err := tpm.LoadAK(params.AKPublic)
	if err != nil {
		fmt.Print("Error loading AK \n")
		return params.Parameters.PCRs[0], err
	}

	pubKeyAttest, err := attest.ParseAKPublic(m.TPMVersion, ak.AttestationParameters().Public)
	if err != nil {
		fmt.Printf("Failed to parse AK public: %v", err)
		return params.Parameters.PCRs[0], err
	}

	// The client parameters quotes are verified using the PCR values and the nonce
	parameters := params.Parameters
	for i, q := range parameters.Quotes {
		if err := pubKeyAttest.Verify(q, parameters.PCRs, nonce); err != nil {
			fmt.Printf("quote[%d] verification failed: %v", i, err)
			return parameters.PCRs[0], err
		} else {
			fmt.Print("The quote was checked successfully! \n")
		}
	}

	return parameters.
		PCRs[10], nil
}

/**
 * registerClient function
 *
 * This function registers the client in the database.
 * It stores the client's data in the database.
 *
 * @param db *sql.DB - The database connection.
 * @param m Message - The message received from the client.
 * @param boot_aggregate attest.PCR - The PCR value to store in the database.
 *
 * @return string - The session ID generated.
 * @return error - The error that occurred while registering the client.
 */

func registerClient(db *sql.DB, m Message, boot_aggregate attest.PCR) (string, error) {

	// Prepare the values of the timestamp and the boot_aggregate from IMA to be stored in DB
	timestamp := (time.Now().Unix())

	// A unique token will be provided to the device that passed the attestation CA to link both CAs
	// Generate 3 random words to make it more human legible
	babbler := babble.NewBabbler()
	babbler.Count = 3

	// Generate a 32B random number
	b := make([]byte, 32)
	rand.Read(b) //Done using the system's secure RNG (In this case the TPM)
	randInt := base64.StdEncoding.EncodeToString(b)

	// Parse the ID for the session
	SessionID := babbler.Babble() + "-" + randInt
	fmt.Printf("ID for the session: %v \n", SessionID)

	// DB Configuration
	cfg := mysql.Config{
		User:                 "root",
		Passwd:               "root",
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306",
		DBName:               "attestationdata",
		AllowNativePasswords: true,
	}
	// Get a database handle.
	var errdb error
	db, errdb = sql.Open("mysql", cfg.FormatDSN())
	if errdb != nil {
		return "", fmt.Errorf("error opening database %v", errdb)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		return "", fmt.Errorf("error writing on the database %v", pingErr)
	}
	fmt.Println("Connected!")

	// Add the values to the DB
	pcrvalue := fmt.Sprintf("%v ", boot_aggregate)
	db.Exec("INSERT INTO attestationdata (pcr,transactionid,timerequest,uniqueid) VALUES (?, ?, ?, ?)", pcrvalue, SessionID, timestamp, base64.StdEncoding.EncodeToString(m.EKPublic))

	return SessionID, nil
}

/**
 * writeToClient function
 *
 * This function writes data to the client.
 * It writes the data to the client's response.
 *
 * @param w http.ResponseWriter - The response writer.
 * @param m2s []byte - The data to write to the client.
 * @param content_t string - The content type of the data.
 *
 * @return error - The error that occurred while writing to the client.
 */

func writeToClient(w http.ResponseWriter, m2s []byte, content_t string) error {

	w.Header().Set("Content-Type", content_t)
	_, err := w.Write(m2s)
	if err != nil {
		fmt.Printf("Error writing to client: %v \n", err)
		return err
	}
	return nil
}

/**
 * readFromClient function
 *
 * This function reads data from the client.
 * It reads the data from the client's request.
 *
 * @param r *http.Request - The request from the client.
 *
 * @return []byte - The data read from the client.
 * @return error - The error that occurred while reading from the client.
 */

func readFromClient(r *http.Request) ([]byte, error) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Error reading from client: %v \n", err)
		return nil, err
	}
	return body, nil
}

/**
 * handleTPMData function
 *
 * This function handles the TPM data received from the client.
 * It verifies the TPM data and generates a challenge for the client.
 *
 * @param w http.ResponseWriter - The response writer.
 * @param r *http.Request - The request from the client.
 */

func handleTPMData(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	cookie, err := r.Cookie("clientID")
	if err != nil {
		var clientID string
		for {
			clientID, err = generateRandomID(1000000)
			if err != nil {
				http.Error(w, "Error generating client ID", http.StatusInternalServerError)
				return
			}

			// Verify that the client ID is not already in use
			mutex.Lock()
			_, exists := clients[clientID]
			mutex.Unlock()

			if !exists {
				break
			}
		}

		cookie = &http.Cookie{
			Name:  "clientID",
			Value: clientID,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}

	mutex.Lock()
	defer mutex.Unlock()

	defer r.Body.Close()
	message, err := readFromClient(r)
	if err != nil {
		http.Error(w, "Error reading from client\n", http.StatusBadRequest)
		return
	}

	var m Message

	//fmt.Printf("Message received: %v \n", message[:10])
	json.Unmarshal(message, &m) //Unmarshalling the message

	verifyTPMData(m)
	var ec2s []byte
	ec2s, secret, err := generateChallenge(m)
	if err != nil {
		http.Error(w, "Error generating challenge\n", http.StatusBadRequest)
		return
	}
	clients[cookie.Value] = ClientData{secret, nil, m}
	err = writeToClient(w, ec2s, "application/json")
	if err != nil {
		http.Error(w, "Error writing to client\n", http.StatusBadRequest)
		return
	}
}

/**
 * handleChallegne function
 *
 * This function handles the challenge received from the client.
 * It verifies the challenge and generates a nonce for the client.
 *
 * @param w http.ResponseWriter - The response writer.
 * @param r *http.Request - The request from the client.
 */

func handleChallenge(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	cookie, err := r.Cookie("clientID")
	if err != nil {
		http.Error(w, "Client not identified", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	defer r.Body.Close()
	secretReceived, err := readFromClient(r)
	if err != nil {
		http.Error(w, "Error reading from client\n", http.StatusBadRequest)
		return
	}

	if len(secretReceived) < 1 {
		http.Error(w, "No secret received\n", http.StatusBadRequest)
		return
	}

	client := clients[cookie.Value]

	//fmt.Printf("Secret sent: %v \n", secret[:10])
	//fmt.Printf("Secret received: %v \n", secretReceived[:10])

	if reflect.DeepEqual(client.secret, secretReceived) {
		fmt.Printf("Secrets match, client with ID %s passed the challenge! \n", cookie.Value)
	} else {
		fmt.Printf("Secrets do not match, client with ID %s did not pass the challenge! \n", cookie.Value)
		http.Error(w, "Secrets do not match, challenge failed! \n", http.StatusBadRequest)
		return
	}

	fmt.Printf("Generating nonce for client with ID:%s... \n", cookie.Value)

	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "Error generating nonce\n", http.StatusBadRequest)
		return
	}
	client.nonce = nonce
	//fmt.Printf("Nonce generated: %s ,%v\n", cookie.Value, client.nonce)
	err = writeToClient(w, client.nonce, "application/octet-stream")
	if err != nil {
		http.Error(w, "Error writing to client\n", http.StatusBadRequest)
		return
	}
	clients[cookie.Value] = client
}

/**
 * handleDBRegister function
 *
 * This function handles the database registration received from the client.
 * It verifies the attestation data and registers the client in the database.
 *
 * @param w http.ResponseWriter - The response writer.
 * @param r *http.Request - The request from the client.
 */

func handleDBRegister(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	cookie, err := r.Cookie("clientID")
	if err != nil {
		http.Error(w, "Cliente not identified", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	client, ok := clients[cookie.Value]
	mutex.Unlock()
	if !ok {
		http.Error(w, "Client Data not found", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	attestationData, err := readFromClient(r)
	if err != nil || len(attestationData) < 1 {
		http.Error(w, "No attestation data received\n", http.StatusBadRequest)
		return
	}

	//fmt.Printf("Param received: %v\n", attestationData)
	var params attestParams
	json.Unmarshal(attestationData, &params)
	boot_aggregate, err := verifyAttestationData(params, client.m, client.nonce)
	if err != nil {
		http.Error(w, "Error verifying attestation data\n", http.StatusBadRequest)
		return
	}

	var db *sql.DB
	sessionID, err := registerClient(db, client.m, boot_aggregate)
	if err != nil {
		http.Error(w, "Error registering client\n", http.StatusBadRequest)
		return
	}
	fmt.Printf("Client with ID:%s was registered successfully! \n", cookie.Value)

	err = writeToClient(w, []byte(sessionID), "application/octet-stream")
	if err != nil {
		http.Error(w, "Error writing to client\n", http.StatusBadRequest)
		return
	}
}

/**
 * main function
 *
 * This is the main function of the server.
 * It starts the server and listens for incoming connections.
 */

func main() {

	http.HandleFunc("/tpmData", handleTPMData)
	http.HandleFunc("/challenge", handleChallenge)
	http.HandleFunc("/dbRegistation", handleDBRegister)
	fmt.Println("Serving on port: 8080")
	err := http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Server Closed\n")
	} else if err != nil {
		fmt.Printf("Error Starting Server: %s\n", err)
		os.Exit(1)
	}
}
