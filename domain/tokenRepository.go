package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type TokenRepository interface { //repo (secondary port)
	BuildToken(jwt.Claims) (string, *errs.AppError)
	GetClaimsFromToken(string, string) (interface{}, *errs.AppError)
}

type DefaultTokenRepository struct { //adapter
	builder       josejwt.NestedBuilder
	rsaPrivateKey *rsa.PrivateKey
}

func NewDefaultTokenRepository() DefaultTokenRepository {
	// Generate a public/private key pair.
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Fatal("Error while generating public/private key pair: " + err.Error())
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

// BuildToken encodes the given claims into JWE/JWS, signs and encrypts, then serializes it into an encrypted JWT.
func (r DefaultTokenRepository) BuildToken(claims jwt.Claims) (string, *errs.AppError) {
	tokenStr, err := r.builder.Claims(claims).CompactSerialize()
	if err != nil {
		logger.Fatal("Error while encoding claims into JWE/JWS: " + err.Error())
	}

	return tokenStr, nil
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

	nested, err := token.Decrypt(r.rsaPrivateKey) //check logged in: "Error while decrypting token: go-jose/go-jose: error in cryptographic primitive"
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
