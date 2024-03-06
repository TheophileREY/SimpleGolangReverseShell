package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
    "net"
    "os"
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
    // Ecouter sur le port TCP les connexions entrantes
    listener, err := net.Listen("tcp", ":port")
    if err != nil {
        // Si erreur, afficher l'erreur et terminer
        fmt.Println("Erreur (ecoute):", err)
        return
    }
    // Assure que le listener sera ferme proprement a la fin de l'execution de main
    defer listener.Close()
    fmt.Println("En attente de connexion...")

    // Bloque jusqu'a ce qu'une connexion soit etablie
    conn, err := listener.Accept()
    if err != nil {
        // En cas d'erreur lors de l'acceptation d'une connexion, affiche l'erreur et termine
        fmt.Println("Erreur lors de la connexion:", err)
        return
    }
    // Pour fermer la connexion proprement une fois l'arret du prgm
    defer conn.Close()
    fmt.Println("Connexion etablie.")

    // Boucle infinie pour traiter les commandes
    for {
        // Entree de la commande
        fmt.Print("Shell>: ")
        reader := bufio.NewReader(os.Stdin)
        // Lire
        command, _ := reader.ReadString('\n')

        // Chiffre la commande lue avant de l'envoyer
        encryptedCommand, err := encrypt([]byte(command))
        if err != nil {
            // En cas d'erreur de chiffrement, afficher l'erreur et continuer
            fmt.Println("Erreur lors du chiffrement:", err)
            continue
        }
        // Envoie la commande chiffree via la connexion TCP
        conn.Write(encryptedCommand)

        // Prepare un buffer pour recevoir la sortie chiffree du client
        outputBuffer := make([]byte, 8192)
        // Lire la sortie chiffree envoyee par le client
        length, _ := conn.Read(outputBuffer)
        // Isoler la portion du buffer qui contient les donnees de la commande
        encryptedOutput := outputBuffer[:length]
        // Dechiffre la sortie reçue
        output, err := decrypt(encryptedOutput)
        if err != nil {
            // En cas d'erreur de dechiffrement, afficher l'erreur et continuer
            fmt.Println("Erreur lors du dechiffrement:", err)
            continue
        }
        // Affiche la sortie dechiffree
        fmt.Println(string(output))
    }
}
