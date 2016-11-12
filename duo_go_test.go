package duo_go_test

import (
	"strings"
	"testing"

	"github.com/mschwager/duo_go"
)

const (
	IKEY       = "DIXXXXXXXXXXXXXXXXXX"
	WRONG_IKEY = "DIXXXXXXXXXXXXXXXXXY"
	SKEY       = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AKEY       = "useacustomerprovidedapplicationsecretkey"
	WRONG_AKEY = "invalidinvalidinvalidinvalidinvalidinvalid"

	USER = "testuser"

	INVALID_RESPONSE      = "AUTH|INVALID|SIG"
	EXPIRED_RESPONSE      = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702"
	FUTURE_RESPONSE       = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef"
	WRONG_PARAMS_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|6cdbec0fbfa0d3f335c76b0786a4a18eac6cdca7"
	WRONG_PARAMS_APP      = "APP|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|7c2065ea122d028b03ef0295a4b4c5521823b9b5"
)

func TestBasic(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	if signature == "" || err != nil {
		t.Error("Failed to create signature:", err)
	}
}

func TestEmptyUsername(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, "")

	if signature != "" || err.Error() != duo_go.ERR_USER {
		t.Error("Failed error situation:", err)
	}
}

func TestUsernameWithValueSeparator(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, "in|valid")

	if signature != "" || err.Error() != duo_go.ERR_USER {
		t.Error("Failed error situation:", err)
	}
}

func TestInvalidIkey(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: "invalid",
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	if signature != "" || err.Error() != duo_go.ERR_IKEY {
		t.Error("Failed error situation:", err)
	}
}

func TestInvalidSkey(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: "invalid",
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	if signature != "" || err.Error() != duo_go.ERR_SKEY {
		t.Error("Failed error situation:", err)
	}
}

func TestInvalidAkey(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: "invalid",
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	if signature != "" || err.Error() != duo_go.ERR_AKEY {
		t.Error("Failed error situation:", err)
	}
}

func TestInvalidResponse(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	parts := strings.Split(signature, duo_go.SIGNATURE_SEPARATOR)
	valid_application_signature := parts[1]

	invalid_response := strings.Join([]string{INVALID_RESPONSE, valid_application_signature}, duo_go.SIGNATURE_SEPARATOR)

	username, err := duo_go.VerifyResponse(duo_configuration, invalid_response)

	if username != "" || err.Error() != duo_go.ERR_PARSE {
		t.Error("Failed error situation:", err)
	}
}

func TestExpiredResponse(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	parts := strings.Split(signature, duo_go.SIGNATURE_SEPARATOR)
	valid_application_signature := parts[1]

	invalid_response := strings.Join([]string{EXPIRED_RESPONSE, valid_application_signature}, duo_go.SIGNATURE_SEPARATOR)

	username, err := duo_go.VerifyResponse(duo_configuration, invalid_response)

	if username != "" || err.Error() != duo_go.ERR_PARSE {
		t.Error("Failed error situation:", err)
	}
}

func TestFutureResponse(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	parts := strings.Split(signature, duo_go.SIGNATURE_SEPARATOR)
	valid_application_signature := parts[1]

	valid_response := strings.Join([]string{FUTURE_RESPONSE, valid_application_signature}, duo_go.SIGNATURE_SEPARATOR)

	username, err := duo_go.VerifyResponse(duo_configuration, valid_response)

	if username != USER || err != nil {
		t.Error("Failed valid situation:", username, err)
	}
}

func TestFutureInvalidResponse(t *testing.T) {
	invalid_duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: WRONG_AKEY,
	}

	signature, err := duo_go.SignRequest(invalid_duo_configuration, USER)

	parts := strings.Split(signature, duo_go.SIGNATURE_SEPARATOR)
	invalid_application_signature := parts[1]

	invalid_response := strings.Join([]string{FUTURE_RESPONSE, invalid_application_signature}, duo_go.SIGNATURE_SEPARATOR)

	valid_duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	username, err := duo_go.VerifyResponse(valid_duo_configuration, invalid_response)

	if username != "" || err.Error() != duo_go.ERR_PARSE {
		t.Error("Failed error situation:", err)
	}
}

func TestIncorrectParametersResponse(t *testing.T) {
	duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(duo_configuration, USER)

	parts := strings.Split(signature, duo_go.SIGNATURE_SEPARATOR)
	valid_application_signature := parts[1]

	invalid_response := strings.Join([]string{WRONG_PARAMS_RESPONSE, valid_application_signature}, duo_go.SIGNATURE_SEPARATOR)

	username, err := duo_go.VerifyResponse(duo_configuration, invalid_response)

	if username != "" || err.Error() != duo_go.ERR_PARSE {
		t.Error("Failed error situation:", err)
	}
}

func TestInvalidIkeyResponse(t *testing.T) {
	valid_duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	signature, err := duo_go.SignRequest(valid_duo_configuration, USER)

	parts := strings.Split(signature, duo_go.SIGNATURE_SEPARATOR)
	valid_application_signature := parts[1]

	valid_response := strings.Join([]string{FUTURE_RESPONSE, valid_application_signature}, duo_go.SIGNATURE_SEPARATOR)

	invalid_duo_configuration := &duo_go.Web{
		Ikey: WRONG_IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	username, err := duo_go.VerifyResponse(invalid_duo_configuration, valid_response)

	if username != "" || err.Error() != duo_go.ERR_PARSE {
		t.Error("Failed error situation:", err)
	}
}

func TestWrongApplicationParametersResponse(t *testing.T) {
	valid_duo_configuration := &duo_go.Web{
		Ikey: IKEY,
		Skey: SKEY,
		Akey: AKEY,
	}

	invalid_response := strings.Join([]string{FUTURE_RESPONSE, WRONG_PARAMS_APP}, duo_go.SIGNATURE_SEPARATOR)

	username, err := duo_go.VerifyResponse(valid_duo_configuration, invalid_response)

	if username != "" || err.Error() != duo_go.ERR_PARSE {
		t.Error("Failed error situation:", err)
	}
}
