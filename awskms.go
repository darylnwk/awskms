package awskms

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

var (
	// Client contains AWS KMS client
	Client kmsiface.KMSAPI

	// KeyID contains the master key
	KeyID string
)

// Encrypt performs encryption on plaintext with AWS KMS
// Returns empty []byte on error
func Encrypt(plaintext []byte) ([]byte, error) {
	input := &kms.EncryptInput{
		KeyId:     aws.String(KeyID),
		Plaintext: plaintext,
	}

	res, err := Client.Encrypt(input)
	if err != nil {
		return []byte{}, err
	}

	return res.CiphertextBlob, nil
}

// Decrypt performs decryption on ciphertext with AWS KMS
// Returns empty []byte on error
func Decrypt(ciphertext []byte) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}

	res, err := Client.Decrypt(input)
	if err != nil {
		return []byte{}, err
	}

	return res.Plaintext, nil
}
