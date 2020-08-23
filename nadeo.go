package nadeo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/codecat/go-libs/log"
	"github.com/patrickmn/go-cache"
)

// Nadeo provides access to the Nadeo Live Services API.
type Nadeo interface {
	AuthenticateUbi(email, password string) error
	AuthenticateUbiTicket(ticket string) error
	Authenticate(username, password string) error
	GetTokenInfo() TokenInfo

	Get(url string, useCache bool) (string, error)
	Post(url, data string) (string, error)

	CheckRefresh() error

	SetLogging(enabled bool)
}

type nadeo struct {
	audience string

	accessToken  string
	refreshToken string

	tokenRefreshTime    uint32
	tokenExpirationTime uint32

	requestCache *cache.Cache

	logRequests bool
}

func (n *nadeo) AuthenticateUbi(email, password string) error {
	body := bytes.NewReader([]byte("{}"))

	req, err := http.NewRequest("POST", "https://public-ubiservices.ubi.com/v3/profiles/sessions", body)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Ubi-AppId", "86263886-327a-4328-ac69-527f0d20a237")
	req.SetBasicAuth(email, password)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes := make([]byte, resp.ContentLength)
	io.ReadFull(resp.Body, resBytes)

	if resp.StatusCode != 200 {
		respError := ubiErrorResponse{}
		json.Unmarshal(resBytes, &respError)
		return fmt.Errorf("error from server: %s", respError.Message)
	}

	res := ubiAuthResponse{}
	json.Unmarshal(resBytes, &res)

	return n.AuthenticateUbiTicket(res.Ticket)
}

func (n *nadeo) AuthenticateUbiTicket(ticket string) error {
	body := bytes.NewReader([]byte("{\"audience\":\"" + n.audience + "\"}"))

	req, err := http.NewRequest("POST", "https://prod.trackmania.core.nadeo.online/v2/authentication/token/ubiservices", body)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "ubi_v1 t="+ticket)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes := make([]byte, resp.ContentLength)
	io.ReadFull(resp.Body, resBytes)

	if resp.StatusCode != 200 {
		return fmt.Errorf("error from server: %s", getError(resBytes))
	}

	res := authResponse{}
	json.Unmarshal(resBytes, &res)

	n.accessToken = res.AccessToken
	n.refreshToken = res.RefreshToken

	tokenInfo := parseTokenInfo(n.accessToken)
	n.tokenRefreshTime = tokenInfo.Payload.Rat
	n.tokenExpirationTime = tokenInfo.Payload.Exp

	return nil
}

func (n *nadeo) Authenticate(username, password string) error {
	body := bytes.NewReader([]byte("{\"audience\":\"" + n.audience + "\"}"))

	req, err := http.NewRequest("POST", "https://prod.trackmania.core.nadeo.online/v2/authentication/token/basic", body)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes := make([]byte, resp.ContentLength)
	io.ReadFull(resp.Body, resBytes)

	if resp.StatusCode != 200 {
		// 401: "Username could not be found."  -> Invalid username
		// 401: "Invalid credentials."          -> Invalid password
		//   0: "There was a validation error." -> Invalid audience
		return fmt.Errorf("error from server: %s", getError(resBytes))
	}

	res := authResponse{}
	json.Unmarshal(resBytes, &res)

	n.accessToken = res.AccessToken
	n.refreshToken = res.RefreshToken

	tokenInfo := parseTokenInfo(n.accessToken)
	n.tokenRefreshTime = tokenInfo.Payload.Rat
	n.tokenExpirationTime = tokenInfo.Payload.Exp

	return nil
}

func (n *nadeo) GetTokenInfo() TokenInfo {
	return parseTokenInfo(n.accessToken)
}

func (n *nadeo) Get(url string, useCache bool) (string, error) {
	return n.request("GET", url, useCache, "")
}

func (n *nadeo) Post(url, data string) (string, error) {
	return n.request("POST", url, false, data)
}

func (n *nadeo) CheckRefresh() error {
	now := uint32(time.Now().Unix())
	if now > n.tokenRefreshTime {
		err := n.refreshNow()
		if err != nil {
			return fmt.Errorf("unable to refresh token: %s", err.Error())
		}
	}
	return nil
}

func (n *nadeo) SetLogging(enabled bool) {
	n.logRequests = enabled
}

func (n *nadeo) request(method string, url string, useCache bool, data string) (string, error) {
	if useCache {
		cachedResponse, cacheFound := n.requestCache.Get(url)
		if cacheFound {
			return cachedResponse.(string), nil
		}
	}

	if n.logRequests {
		log.Trace("Nadeo request: %s => %s", method, url)
	}

	err := n.CheckRefresh()
	if err != nil {
		return "", err
	}

	var body io.Reader
	if method == "POST" {
		body = bytes.NewReader([]byte(data))
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return "", fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Authorization", "nadeo_v1 t="+n.accessToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read from stream: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("error from server: %s", getError(resBytes))
	}

	if useCache {
		n.requestCache.Set(url, string(resBytes), cache.DefaultExpiration)
	}

	return string(resBytes), nil
}

func (n *nadeo) refreshNow() error {
	req, err := http.NewRequest("POST", "https://prod.trackmania.core.nadeo.online/v2/authentication/token/refresh", nil)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Authorization", "nadeo_v1 t="+n.refreshToken)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes := make([]byte, resp.ContentLength)
	io.ReadFull(resp.Body, resBytes)

	if resp.StatusCode != 200 {
		return fmt.Errorf("error from server: %s", getError(resBytes))
	}

	res := authResponse{}
	json.Unmarshal(resBytes, &res)

	n.accessToken = res.AccessToken
	n.refreshToken = res.RefreshToken

	tokenInfo := parseTokenInfo(n.accessToken)
	n.tokenRefreshTime = tokenInfo.Payload.Rat
	n.tokenExpirationTime = tokenInfo.Payload.Exp

	return nil
}

// NewNadeo creates a new Nadeo object ready for authentication.
func NewNadeo() Nadeo {
	return NewNadeoWithAudience("NadeoLiveServices")
}

// NewNadeoWithAudience creates a new Nadeo object ready for authentication with the given audience.
func NewNadeoWithAudience(audience string) Nadeo {
	return &nadeo{
		audience:     audience,
		requestCache: cache.New(1*time.Minute, 5*time.Minute),
	}
}
