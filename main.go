package main
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "crypto/sha1"
    "encoding/base64"
    "errors"
    "fmt"
    "bytes"
	"flag"
	"os"
)
var KDF_SALT = []byte{0x75, 0xb8, 0x49, 0x83, 0x90, 0xbc, 0x2a, 0x65, 0x9c, 0x56, 0x93, 0xe7, 0xe5, 0xc5, 0xf0, 0x24}
func checkMasterKey(key string) ([]byte, error) {
    if len(key) == 0 {
        return []byte("p1a2l3o4a5l6t7o8"), nil
    } else if len(key) == 16 {
        return []byte(key), nil
    } else {
        return nil, errors.New("Master key must be exactly 16 characters")
    }
}
func md5Digest(input []byte) [16]byte {
    return md5.Sum(input)
}
func sha1Digest(input []byte) [20]byte {
    h := sha1.New()
    h.Write(input)
    var result [20]byte
    copy(result[:], h.Sum(nil))
    return result
}
func panosDeriveKey(key []byte) ([]byte, error) {
    input := append(key, KDF_SALT...)
    digest := md5Digest(input)
    return append(digest[:], digest[:]...), nil
}
func panosDecrypt(key string, input string) (string, error) {
    masterKey, err := checkMasterKey(key)
    if err != nil {
        return "", fmt.Errorf("Invalid master key: %v", err)
    }

    if input[0] != '-' {
        return "", fmt.Errorf("Input starts with '%c', expected '-'", input[0])
    }
    version, err := base64.StdEncoding.DecodeString(input[1:5])
    if err != nil || version[0] != 1 {
        return "", errors.New("Incompatible version detected")
    }
    hash, err := base64.StdEncoding.DecodeString(input[5:33])
    if err != nil {
        fmt.Println("hash:", hash)
		return "", fmt.Errorf("Failed to base64-decode hash: %v", err)
    }
    ct, err := base64.StdEncoding.DecodeString(input[33:])
    if err != nil {
        return "", fmt.Errorf("Failed to base64-decode value: %v", err)
    }
    if len(ct)%aes.BlockSize != 0 {
        return "", errors.New("Invalid ciphertext length")
    }
    iv := make([]byte, aes.BlockSize)
    derivedKey, err := panosDeriveKey(masterKey)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher(derivedKey[:32])
    if err != nil {
        return "", err
    }
    decrypted := make([]byte, len(ct))
    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(decrypted, ct)
    return string(decrypted), nil
}
func panosEncrypt(key string, input string) (string, error) {
    masterKey, err := checkMasterKey(key)
    if err != nil {
        return "", fmt.Errorf("Invalid master key: %v", err)
    }
    if len(input) == 0 {
        return "", errors.New("No input")
    }
    version := base64.StdEncoding.EncodeToString([]byte{1})
    sha1Hash := sha1Digest([]byte(input))
    hash := base64.StdEncoding.EncodeToString(sha1Hash[:])
    iv := make([]byte, aes.BlockSize)
    derivedKey, err := panosDeriveKey(masterKey)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher(derivedKey[:32])
    if err != nil {
        return "", err
    }
    paddedInput := pad([]byte(input), aes.BlockSize)
    encrypted := make([]byte, len(paddedInput))
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(encrypted, paddedInput)
    ct := base64.StdEncoding.EncodeToString(encrypted)
    return "-" + version + hash + ct, nil
}
func pad(data []byte, blockSize int) []byte {
    padding := blockSize - len(data)%blockSize
    padText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padText...)
}
func equal(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
func main() {
	var decrypt bool
    var encrypt bool
    var input string
    var key string
    flag.BoolVar(&decrypt, "d", false, "Decrypt the input string")
    flag.BoolVar(&encrypt, "e", false, "Encrypt the input string")
    flag.StringVar(&input, "s", "", "String to be encrypted or decrypted")
    flag.StringVar(&key, "k", "", "Master key for encryption/decryption (default is 'p1a2l3o4a5l6t7o8')")
    flag.Parse()
	if input == "" {
        fmt.Println("Input string is required")
        flag.Usage()
        os.Exit(1)
    }
    if encrypt {
        result, err := panosEncrypt(key, input)
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(-1)
		}
		fmt.Println("Encrypted:", result)
    } else if decrypt {
        result, err := panosDecrypt(key, input)
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(-1)
		}
		fmt.Println("Decrypted:", result)
    } else {
        fmt.Println("You must specify either -e (encrypt) or -d (decrypt)")
        flag.Usage()
        os.Exit(1)
    }
}