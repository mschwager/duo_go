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
	SIGNATURE_SEPARATOR = ":"
	VALUE_SEPARATOR     = "|"

	DUO_PREFIX  = "TX"
	APP_PREFIX  = "APP"
	AUTH_PREFIX = "AUTH"

	DUO_EXPIRE = 300
	APP_EXPIRE = 3600

	IKEY_LEN = 20
	SKEY_LEN = 40
	AKEY_LEN = 40

	ERR_USER  = "ERR|The username passed to SignRequest() is invalid."
	ERR_IKEY  = "ERR|The Duo integration key passed to SignRequest() is invalid."
	ERR_SKEY  = "ERR|The Duo secret key passed to SignRequest() is invalid."
	ERR_AKEY  = "ERR|The application secret key passed to SignRequest() must be at least 40 characters."
	ERR_PARSE = "ERR|The response could not be parsed."
)

type Web struct {
	Ikey string
	Skey string
	Akey string
}

func Sha1Hmac(key string, value string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(value))
	result := hex.EncodeToString(mac.Sum(nil))

	return result
}

func SignValues(key string, values string, prefix string, expiration int64) string {
	expiration_time := strconv.FormatInt(time.Now().Unix()+expiration, 10)

	value := strings.Join([]string{values, expiration_time}, VALUE_SEPARATOR)
	b64_value := base64.StdEncoding.EncodeToString([]byte(value))

	cookie := strings.Join([]string{prefix, b64_value}, VALUE_SEPARATOR)
	cookie_signature := Sha1Hmac(key, cookie)

	return strings.Join([]string{cookie, cookie_signature}, VALUE_SEPARATOR)
}

func SignRequest(configuration *Web, username string) (string, error) {
	if len(username) == 0 || strings.Contains(username, VALUE_SEPARATOR) {
		return "", errors.New(ERR_USER)
	}

	if len(configuration.Ikey) != IKEY_LEN {
		return "", errors.New(ERR_IKEY)
	}

	if len(configuration.Skey) != SKEY_LEN {
		return "", errors.New(ERR_SKEY)
	}

	if len(configuration.Akey) < AKEY_LEN {
		return "", errors.New(ERR_AKEY)
	}

	signature_values := strings.Join([]string{username, configuration.Ikey}, VALUE_SEPARATOR)

	duo_signature := SignValues(
		configuration.Skey,
		signature_values,
		DUO_PREFIX,
		DUO_EXPIRE)

	application_signature := SignValues(
		configuration.Akey,
		signature_values,
		APP_PREFIX,
		APP_EXPIRE)

	return strings.Join([]string{duo_signature, application_signature}, SIGNATURE_SEPARATOR), nil
}

func ParseValues(key string, value string, prefix string, ikey string) (string, error) {
	if strings.Count(value, VALUE_SEPARATOR) != 2 {
		return "", errors.New(ERR_PARSE)
	}

	current_time := time.Now().Unix()

	parts := strings.Split(value, VALUE_SEPARATOR)
	u_prefix := parts[0]
	u_b64_value := parts[1]
	u_signature := parts[2]

	message := strings.Join([]string{u_prefix, u_b64_value}, VALUE_SEPARATOR)
	signature := Sha1Hmac(key, message)
	if !hmac.Equal([]byte(signature), []byte(u_signature)) {
		return "", errors.New(ERR_PARSE)
	}

	if prefix != u_prefix {
		return "", errors.New(ERR_PARSE)
	}

	u_b64_decoded, err := base64.StdEncoding.DecodeString(u_b64_value)
	if err != nil {
		return "", err
	}
	if strings.Count(string(u_b64_decoded), VALUE_SEPARATOR) != 2 {
		return "", errors.New(ERR_PARSE)
	}

	parts = strings.Split(string(u_b64_decoded), VALUE_SEPARATOR)
	username := parts[0]
	u_ikey := parts[1]
	expiration := parts[2]

	if ikey != u_ikey {
		return "", errors.New(ERR_PARSE)
	}

	expired, err := strconv.ParseInt(expiration, 10, 64)
	if err != nil {
		return "", err
	}
	if current_time >= expired {
		return "", errors.New(ERR_PARSE)
	}

	return username, nil
}

func VerifyResponse(configuration *Web, response string) (string, error) {
	if strings.Count(response, SIGNATURE_SEPARATOR) != 1 {
		return "", errors.New(ERR_PARSE)
	}

	parts := strings.Split(response, SIGNATURE_SEPARATOR)
	authentication_signature := parts[0]
	application_signature := parts[1]

	authentication_user, err := ParseValues(
		configuration.Skey,
		authentication_signature,
		AUTH_PREFIX,
		configuration.Ikey)
	if err != nil {
		return "", err
	}

	application_user, err := ParseValues(
		configuration.Akey,
		application_signature,
		APP_PREFIX,
		configuration.Ikey)
	if err != nil {
		return "", err
	}

	if authentication_user != application_user {
		return "", errors.New(ERR_PARSE)
	}

	return authentication_user, nil
}
