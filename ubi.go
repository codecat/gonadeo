package nadeo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
)

// Ubi provides access to the Ubisoft API.
type Ubi interface {
	Authenticate(email, password string) error

	Get(url string, useCache bool) (string, error)
	Post(url, data string) (string, error)

	CheckRefresh() error

	GetTicket() string
}

type ubi struct {
	appID  string
	ticket string

	requestCache *cache.Cache
}

func (u *ubi) Authenticate(email, password string) error {
	body := bytes.NewReader([]byte("{}"))

	req, err := http.NewRequest("POST", "https://public-ubiservices.ubi.com/v3/profiles/sessions", body)
	if err != nil {
		return fmt.Errorf("unable to make ubi request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Ubi-AppId", u.appID)
	req.SetBasicAuth(email, password)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform ubi request: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("error %d from ubi server", resp.StatusCode)
	}

	resBytes := make([]byte, resp.ContentLength)
	io.ReadFull(resp.Body, resBytes)

	res := ubiAuthResponse{}
	json.Unmarshal(resBytes, &res)

	u.ticket = res.Ticket
	return nil
}

func (u *ubi) Get(url string, useCache bool) (string, error) {
	return u.request("GET", url, useCache, "")
}

func (u *ubi) Post(url, data string) (string, error) {
	return u.request("POST", url, false, data)
}

func (u *ubi) CheckRefresh() error {
	//TODO
	return nil
}

func (u *ubi) GetTicket() string {
	return u.ticket
}

func (u *ubi) request(method, url string, useCache bool, data string) (string, error) {
	if useCache {
		cachedResponse, cacheFound := u.requestCache.Get(url)
		if cacheFound {
			return cachedResponse.(string), nil
		}
	}

	err := u.CheckRefresh()
	if err != nil {
		return "", err
	}

	var body io.Reader
	if method == "POST" {
		body = bytes.NewReader([]byte(data))
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return "", fmt.Errorf("unable to make ubi request: %s", err.Error())
	}

	req.Header.Add("Authorization", "ubi_v1 t="+u.ticket)
	req.Header.Add("Ubi-AppId", u.appID)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to perform ubi request: %s", err.Error())
	}

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read from ubi stream: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		//respError := errorResponse{}
		//err := json.Unmarshal(resBytes, &respError)
		return "", fmt.Errorf("error from ubi server: %s", string(resBytes))
		//return "", fmt.Errorf("error %d from server: %s", respError.Code, respError.Message)
	}

	if useCache {
		u.requestCache.Set(url, string(resBytes), cache.DefaultExpiration)
	}

	return string(resBytes), nil
}

// NewUbi creates a new Ubi object ready for authentication.
func NewUbi(appID string) Ubi {
	return &ubi{
		appID: appID,

		requestCache: cache.New(1*time.Minute, 5*time.Minute),
	}
}
