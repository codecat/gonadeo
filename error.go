package nadeo

import (
	"encoding/json"
)

func getError(res []byte) string {
	respError := errorResponse{}
	err := json.Unmarshal(res, &respError)
	if err != nil {
		return err.Error()
	}
	if respError.Error != "" {
		return respError.Message + " (" + respError.Error + ")"
	}
	return respError.Message
}
