package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"bytes"


	"golang.org/x/crypto/ssh"
)

const sshDir = ".ssh"

// initialize_ssh_env creates the .ssh folder (if missing) and generates
// a new ed25519 SSH key pair inside it. Idempotent: if the private key
// already exists, nothing is overwritten.
func initialize_ssh_env() error {
	info, err := os.Stat(sshDir)
	if err == nil && info.IsDir() {
		log.Printf("%s folder already exists, skipping creation.", sshDir)
	} else if err != nil || !info.IsDir() {
		log.Printf("%s folder does not exists, creating folder.", sshDir)
		// Create the .ssh folder with 0700 permissions (owner only).
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return fmt.Errorf("failed to create %s folder: %w", sshDir, err)
		}
		log.Printf("Created %s folder", sshDir)
	}

	privateKeyPath := fmt.Sprintf("%s/id_ed25519", sshDir)
	publicKeyPath := fmt.Sprintf("%s/id_ed25519.pub", sshDir)

	// Return/Skip generation if the key pair already exists.
	if _, err := os.Stat(privateKeyPath); err == nil {
		log.Printf("SSH key already exists at %s, skipping generation", privateKeyPath)
		return nil
	}

	// Generate a new ed25519 key pair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	// Marshal into OpenSSH format.
	privatePem, err := ssh.MarshalPrivateKey(privKey, "sftp-backup")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Write private key (0600) and public key (0644).
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(privatePem), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", privateKeyPath, err)
	}
	if err := os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(sshPubKey), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", publicKeyPath, err)
	}

	log.Printf("Generated SSH key pair: %s and %s", privateKeyPath, publicKeyPath)
	return nil
}

func main() {
	initialize_ssh_env()
	var hostKey ssh.PublicKey
	number_is := 1
	fmt.Println(number_is)
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	config := &ssh.ClientConfig{
		User: "demo",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	client, err := ssh.Dial("tcp", "test.rebex.net:22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	log.Println("Connected to the server")
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/usr/bin/whoami"); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	fmt.Println(b.String())
}