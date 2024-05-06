package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"os"
)

type TokenRepository interface { //repo (secondary port)
	BuildToken(jwt.Claims) (string, *errs.AppError)
	GetHash(string) string
	GetClaimsFromToken(string, string) (interface{}, *errs.AppError)
}

type DefaultTokenRepository struct { //adapter
	builder       josejwt.NestedBuilder
	rsaPrivateKey *rsa.PrivateKey
}

func NewDefaultTokenRepository() DefaultTokenRepository {
	rsaPrivateKey := getKey()
	if rsaPrivateKey == nil {
		//retry
		generateKey()
		rsaPrivateKey = getKey()
		if rsaPrivateKey == nil { //problem is not with generation of new key
			logger.Fatal("Failed to get key")
		}
	}

	// Get instance of a signer using RSASSA-PSS (SHA512), using the private key.
	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       rsaPrivateKey,
		},
		(&jose.SignerOptions{}).WithType("JWT").WithContentType("JWT"),
	)
	if err != nil {
		logger.Fatal("Error while creating nested JWT signer: " + err.Error())
	}

	// Get instance of an encrypter using RSA-OAEP with AES128-GCM, using the public key.
	publicKey := &rsaPrivateKey.PublicKey
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       publicKey,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
	)
	if err != nil {
		logger.Fatal("Error while creating nested JWT encrypter: " + err.Error())
	}

	// Get instance of a JWE/JWS builder to initialize the repo with.
	builder := josejwt.SignedAndEncrypted(sig, enc)

	return DefaultTokenRepository{builder, rsaPrivateKey}
}

// getKey tries to access and parse into a pointer to rsa.PrivateKey any file that exists at the path specified by
// the ENCRYPTION_FILEPATH environment variable.
func getKey() *rsa.PrivateKey {
	keyFilePath := os.Getenv("ENCRYPTION_FILEPATH")

	keyBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		logger.Error("Error while reading from key pair file: " + err.Error())
		return nil
	}

	k, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		logger.Error("Error while parsing key pair: " + err.Error())
		return nil
	}

	rsaPrivateKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		logger.Error("Error while type asserting key pair to RSA private key type: " + err.Error())
		return nil
	}

	return rsaPrivateKey
}

// generateKey tries to create a new RSA public/private key pair and write it as bytes in PEM format.
// Any errors in the process causes the program to exit. Calling this method rewrites any file that exists at
// the path specified by the ENCRYPTION_FILEPATH environment variable.
func generateKey() {
	logger.Info("Generating new key pair file...")

	keyFilePath := os.Getenv("ENCRYPTION_FILEPATH")

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Fatal("Error while generating new key pair: " + err.Error())
	}

	var b []byte
	b, err = x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		logger.Fatal("Error while marshalling new key pair: " + err.Error())
	}
	if err = os.WriteFile(keyFilePath, b, 0666); err != nil { //A text file has 666 permissions (file owner - group owner - other users), which grants read and write permission to everyone
		logger.Fatal("Error while writing key pair to new file: " + err.Error())
	}

	logger.Info("Successfully created new key pair file.")
}

// BuildToken encodes the given claims into JWE/JWS, signs and encrypts, then serializes it into an encrypted JWT.
func (r DefaultTokenRepository) BuildToken(claims jwt.Claims) (string, *errs.AppError) {
	tokenStr, err := r.builder.Claims(claims).CompactSerialize()
	if err != nil {
		logger.Fatal("Error while encoding claims into JWE/JWS: " + err.Error())
	}

	return tokenStr, nil
}

// GetHash returns the 64-byte hash of the token string.
func (r DefaultTokenRepository) GetHash(tokenStr string) string {
	h := sha256.New() //create new instance each time so that hash state is not preserved between calls
	h.Write([]byte(tokenStr))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GetClaimsFromToken parses the given tokenStr into an encrypted JWT, which is then decrypted into a nested JWT.
// It is then deserialized into claims of the given claimsType. The claims should be validated after calling this
// method as it does not do so.
func (r DefaultTokenRepository) GetClaimsFromToken(tokenStr string, claimsType string) (interface{}, *errs.AppError) {
	token, err := josejwt.ParseSignedAndEncrypted(tokenStr)
	if err != nil {
		logger.Error("Error while parsing token string: " + err.Error())
		return nil, errs.NewAuthenticationError(fmt.Sprintf("Invalid %s", claimsType))
	}

	nested, err := token.Decrypt(r.rsaPrivateKey)
	if err != nil {
		logger.Error("Error while decrypting token: " + err.Error())
		return nil, errs.NewAuthenticationError(fmt.Sprintf("Invalid %s", claimsType))
	}

	publicKey := r.rsaPrivateKey.PublicKey
	var deserializeErr error
	if claimsType == TokenTypeAccess {
		claims := AccessTokenClaims{}
		deserializeErr = nested.Claims(&publicKey, &claims)
		if deserializeErr == nil {
			return &claims, nil
		}
	} else if claimsType == TokenTypeRefresh {
		claims := RefreshTokenClaims{}
		deserializeErr = nested.Claims(&publicKey, &claims)
		if deserializeErr == nil {
			return &claims, nil
		}
	} else if claimsType == TokenTypeOneTime {
		claims := OneTimeTokenClaims{}
		deserializeErr = nested.Claims(&publicKey, &claims)
		if deserializeErr == nil {
			return &claims, nil
		}
	} else {
		logger.Error("Unknown claims type")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	logger.Error("Error while deserializing token into claims: " + deserializeErr.Error())
	return nil, errs.NewAuthenticationError(fmt.Sprintf("Invalid %s", claimsType))
}
