// Package duo_go implments the Duo Security WebSDK.
package duo_go

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	SignatureSeparator = ":"
	ValueSeparator     = "|"

	DuoPrefix  = "TX"
	AppPrefix  = "APP"
	AuthPrefix = "AUTH"

	DuoExpire = 300
	AppExpire = 3600

	IKEYLen = 20
	SKEYLen = 40
	AKEYLen = 40

	ErrUser  = "ERR|The username passed to SignRequest() is invalid."
	ErrIKEY  = "ERR|The Duo integration key passed to SignRequest() is invalid."
	ErrSKEY  = "ERR|The Duo secret key passed to SignRequest() is invalid."
	ErrAKEY  = "ERR|The application secret key passed to SignRequest() must be at least 40 characters."
	ErrParse = "ERR|The response could not be parsed."
)

// Web holds configuration necessary to communicate with the Duo service.
type Web struct {
	Ikey string
	Skey string
	Akey string
}

func sha1Hmac(key string, value string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(value))
	result := hex.EncodeToString(mac.Sum(nil))

	return result
}

func signValues(key string, values string, prefix string, expiration int64) string {
	expirationTime := strconv.FormatInt(time.Now().Unix()+expiration, 10)

	value := strings.Join([]string{values, expirationTime}, ValueSeparator)
	b64Value := base64.StdEncoding.EncodeToString([]byte(value))

	cookie := strings.Join([]string{prefix, b64Value}, ValueSeparator)
	cookieSignature := sha1Hmac(key, cookie)

	return strings.Join([]string{cookie, cookieSignature}, ValueSeparator)
}

// SignRequest signs a 2FA request for consumption by the Duo service.
func SignRequest(configuration *Web, username string) (signature string, err error) {
	if len(username) == 0 || strings.Contains(username, ValueSeparator) {
		return "", errors.New(ErrUser)
	}

	if len(configuration.Ikey) != IKEYLen {
		return "", errors.New(ErrIKEY)
	}

	if len(configuration.Skey) != SKEYLen {
		return "", errors.New(ErrSKEY)
	}

	if len(configuration.Akey) < AKEYLen {
		return "", errors.New(ErrAKEY)
	}

	signatureValues := strings.Join([]string{username, configuration.Ikey}, ValueSeparator)

	duoSignature := signValues(
		configuration.Skey,
		signatureValues,
		DuoPrefix,
		DuoExpire)

	applicationSignature := signValues(
		configuration.Akey,
		signatureValues,
		AppPrefix,
		AppExpire)

	return strings.Join([]string{duoSignature, applicationSignature}, SignatureSeparator), nil
}

func parseValues(key string, value string, prefix string, ikey string) (string, error) {
	if strings.Count(value, ValueSeparator) != 2 {
		return "", errors.New(ErrParse)
	}

	currentTime := time.Now().Unix()

	parts := strings.Split(value, ValueSeparator)
	uPrefix := parts[0]
	uB64Value := parts[1]
	uSignature := parts[2]

	message := strings.Join([]string{uPrefix, uB64Value}, ValueSeparator)
	signature := sha1Hmac(key, message)
	if !hmac.Equal([]byte(signature), []byte(uSignature)) {
		return "", errors.New(ErrParse)
	}

	if prefix != uPrefix {
		return "", errors.New(ErrParse)
	}

	uB64Decoded, err := base64.StdEncoding.DecodeString(uB64Value)
	if err != nil {
		return "", err
	}
	if strings.Count(string(uB64Decoded), ValueSeparator) != 2 {
		return "", errors.New(ErrParse)
	}

	parts = strings.Split(string(uB64Decoded), ValueSeparator)
	username := parts[0]
	uIkey := parts[1]
	expiration := parts[2]

	if ikey != uIkey {
		return "", errors.New(ErrParse)
	}

	expired, err := strconv.ParseInt(expiration, 10, 64)
	if err != nil {
		return "", err
	}
	if currentTime >= expired {
		return "", errors.New(ErrParse)
	}

	return username, nil
}

// VerifyResponse verifies a 2FA response received from the Duo service.
func VerifyResponse(configuration *Web, response string) (username string, err error) {
	if strings.Count(response, SignatureSeparator) != 1 {
		return "", errors.New(ErrParse)
	}

	parts := strings.Split(response, SignatureSeparator)
	authenticationSignature := parts[0]
	applicationSignature := parts[1]

	authenticationUser, err := parseValues(
		configuration.Skey,
		authenticationSignature,
		AuthPrefix,
		configuration.Ikey)
	if err != nil {
		return "", err
	}

	applicationUser, err := parseValues(
		configuration.Akey,
		applicationSignature,
		AppPrefix,
		configuration.Ikey)
	if err != nil {
		return "", err
	}

	if authenticationUser != applicationUser {
		return "", errors.New(ErrParse)
	}

	return authenticationUser, nil
}
