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
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/go-attestation/attest"
	"github.com/tjarratt/babble"
)

type Message struct {
	TPMVersion attest.TPMVersion
	EKPublic   []byte
	EKCert     x509.Certificate
	AK         attest.AttestationParameters
}

type attestParams struct {
	Parameters attest.PlatformParameters
	AKPublic   []byte
}

var tpmInfoReceived = false
var isSecretReceived = false
var paramReceived = false
var nonceGenerated = false
var secret []byte
var nonce []byte
var m Message

func start() {

	tpmInfoReceived = false
	isSecretReceived = false
	paramReceived = false
	nonceGenerated = false
}

func generateNonce() ([]byte, error) {

	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		fmt.Printf("Failed to generate nonce: %v \n", err)
		return nil, err
	}
	return nonce, nil
}

// VerifyCertificate checks if the certificate is signed by a valid CA
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

// This function downloads the Intermediate CA that is referenced in the Certificate
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

	return parameters.PCRs[10], nil
}

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

func writeToClient(w http.ResponseWriter, m2s []byte, content_t string) error {

	w.Header().Set("Content-Type", content_t)
	_, err := w.Write(m2s)
	if err != nil {
		fmt.Printf("Error writing to client: %v \n", err)
		return err
	}
	return nil
}

func readFromClient(r *http.Request) ([]byte, error) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Error reading from client: %v \n", err)
		return nil, err
	}
	return body, nil
}

func handleConnection(w http.ResponseWriter, r *http.Request) {

	if !tpmInfoReceived {

		defer r.Body.Close()
		message, err := readFromClient(r)
		if err != nil {
			return
		}

		fmt.Printf("Message received: %v \n", message[:10])
		json.Unmarshal(message, &m) //Unmarshalling the message

		verifyTPMData(m)
		var ec2s []byte
		ec2s, secret, err = generateChallenge(m)
		if err != nil {
			return
		}
		err = writeToClient(w, ec2s, "application/json")
		if err != nil {
			return
		}
		tpmInfoReceived = true
	}

	if !isSecretReceived {

		defer r.Body.Close()
		secretReceived, err := readFromClient(r)
		if err != nil {
			start()
			return
		}

		if len(secretReceived) < 1 {
			fmt.Print("No secret received, retrying...\n")
			return
		}

		//fmt.Printf("Secret sent: %v \n", secret[:10])
		//fmt.Printf("Secret received: %v \n", secretReceived[:10])

		if reflect.DeepEqual(secret, secretReceived) {
			fmt.Fprintf(os.Stdout, "Secrets match, challenge was successful! \n")
		} else {
			fmt.Fprintf(os.Stderr, "Secrets do not match, challenge failed! \n")
			start()
			return
		}
		isSecretReceived = true
	}

	if !nonceGenerated {
		fmt.Print("Generating nonce... \n")
		var err error
		nonce, err = generateNonce()
		if err != nil {
			start()
			return
		}
		err = writeToClient(w, nonce, "application/octet-stream")
		if err != nil {
			start()
			return
		}
		nonceGenerated = true
	}

	if !paramReceived {
		defer r.Body.Close()
		attestationData, err := readFromClient(r)
		if err != nil || len(attestationData) < 1 {
			fmt.Print("No attestation data received, retrying...\n")
			return
		}

		//fmt.Printf("Param received: %v\n", attestationData)
		var params attestParams
		json.Unmarshal(attestationData, &params)
		boot_aggregate, err := verifyAttestationData(params, m, nonce)
		if err != nil {
			start()
			return
		}

		var db *sql.DB
		sessionID, err := registerClient(db, m, boot_aggregate)
		if err != nil {
			start()
			return
		}
		fmt.Printf("Client registered successfully! \n")

		err = writeToClient(w, []byte(sessionID), "application/octet-stream")
		if err != nil {
			start()
			return
		}
		paramReceived = true
	}

	if paramReceived && isSecretReceived && tpmInfoReceived && nonceGenerated {
		start()
	}
}

func main() {

	http.HandleFunc("/", handleConnection)
	fmt.Println("Serving on port: 8080")
	err := http.ListenAndServe(":8080", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Server Closed\n")
	} else if err != nil {
		fmt.Printf("Error Starting Server: %s\n", err)
		os.Exit(1)
	}
}
