package nadeo

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// TokenInfo contains information about the access token.
type TokenInfo struct {
	Header struct {
		Alg string // "HS256"
		Env string // "trackmania-prod"
		Ver string // "1"
	}

	Payload struct {
		Jti string // Json Web Token ID
		Iss string // "NadeoServices"
		Iat uint32 // Issued At Time
		Rat uint32 // Refresh At Time
		Exp uint32 // Expiration time
		Aud string // "NadeoLiveServices"
		Usg string // "Server"
		Sid string // ?? UUID
		Sub string // ?? UUID
		Aun string // Authenticated login
		Rtk bool   // false
		Pce bool   // false
	}

	Signature []byte
}

func parseTokenInfo(token string) TokenInfo {
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	parse := strings.Split(token, ".")

	dataHeader, _ := b64.DecodeString(parse[0])
	dataPayload, _ := b64.DecodeString(parse[1])
	dataSignature, _ := b64.DecodeString(parse[2])

	ret := TokenInfo{}
	json.Unmarshal(dataHeader, &ret.Header)
	json.Unmarshal(dataPayload, &ret.Payload)
	ret.Signature = dataSignature

	return ret
}
