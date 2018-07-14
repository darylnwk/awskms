package awskms_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/darylnwk/awskms"
	"github.com/stretchr/testify/assert"
)

type mockKMSClient struct {
	kmsiface.KMSAPI
}

func (m *mockKMSClient) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	switch {
	case bytes.Equal(input.Plaintext, []byte("error")):
		return &kms.EncryptOutput{}, errors.New("AWS KMS error!")
	default:
		return &kms.EncryptOutput{
			CiphertextBlob: []byte("ciphertext"),
		}, nil
	}
}

func (m *mockKMSClient) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	switch {
	case bytes.Equal(input.CiphertextBlob, []byte("error")):
		return &kms.DecryptOutput{}, errors.New("AWS KMS error!")
	default:
		return &kms.DecryptOutput{
			Plaintext: []byte("plaintext"),
		}, nil
	}
}

func init() {
	awskms.Client = &mockKMSClient{}
	awskms.KeyID = "keyID"
}

func TestAwsKms_Encrypt(t *testing.T) {
	plaintext := []byte("plaintext")
	ciphertext, err := awskms.Encrypt(plaintext)
	assert.Nil(t, err)
	assert.Equal(t, []byte("ciphertext"), ciphertext)
}

func TestAwsKms_Encrypt_Error(t *testing.T) {
	plaintext := []byte("error")
	ciphertext, err := awskms.Encrypt(plaintext)
	assert.NotNil(t, err)
	assert.Equal(t, "AWS KMS error!", err.Error())
	assert.Equal(t, []byte(""), ciphertext)
}

func TestAwsKms_Decrypt(t *testing.T) {
	ciphertext := []byte("ciphertext")
	plaintext, err := awskms.Decrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, []byte("plaintext"), plaintext)
}

func TestAwsKms_Decrypt_Error(t *testing.T) {
	ciphertext := []byte("error")
	plaintext, err := awskms.Decrypt(ciphertext)
	assert.NotNil(t, err)
	assert.Equal(t, "AWS KMS error!", err.Error())
	assert.Equal(t, []byte(""), plaintext)
}