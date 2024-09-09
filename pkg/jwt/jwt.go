package jwt

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/DimTur/lp_auth/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// for now there's no reason for err segregation & uniq processing
	// but its good idea to have list of error which module can return
	ErrKeyParsing      = fmt.Errorf("parsing error")
	ErrTokenGeneration = fmt.Errorf("token generation error")
	ErrSigning         = fmt.Errorf("signing error")
	ErrValidation      = fmt.Errorf("token validation errror")
)

type JWTManager struct {
	issuer           string
	accessExpiresIn  time.Duration
	refreshExpiresIn time.Duration
	publicKey        interface{}
	privateKey       interface{}
}

func NewJWTManager(issuer string, AccessExpiresIn, RefreshExpiresIn time.Duration, publicKey, privateKey []byte) (*JWTManager, error) {
	pubKey, err := jwt.ParseEdPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	privKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyParsing, err)
	}

	return &JWTManager{
		issuer:           issuer,
		accessExpiresIn:  AccessExpiresIn,
		refreshExpiresIn: RefreshExpiresIn,
		publicKey:        pubKey,
		privateKey:       privKey,
	}, nil
}

func (j *JWTManager) GetRefreshExpiresIn() time.Duration {
	return j.refreshExpiresIn
}

func (j *JWTManager) IssueAccessToken(userID, appID int64) (string, error) {
	claims := jwt.MapClaims{
		"iss":    j.issuer,
		"sub":    userID,
		"app_id": appID,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(j.accessExpiresIn).Unix(),
		"type":   "access",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signed, err := token.SignedString(j.privateKey.(ed25519.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}
	return signed, nil
}

func (j *JWTManager) IssueRefreshToken(userID, appID int64) (string, error) {
	claims := jwt.MapClaims{
		"iss":    j.issuer,
		"sub":    userID,
		"app_id": appID,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(j.refreshExpiresIn).Unix(),
		"type":   "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	signed, err := token.SignedString(j.privateKey.(ed25519.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrSigning, err)
	}
	return signed, nil
}

func (j *JWTManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrValidation
		}
		return j.publicKey, nil
	},
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err)
	}

	return token, nil
}

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodEdDSA)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
