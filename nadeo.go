package nadeo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/codecat/go-libs/log"
	"github.com/patrickmn/go-cache"
)

type AsyncResponse struct {
	buf []byte
	err error
}

// Nadeo provides access to the Nadeo Live Services API.
type Nadeo interface {
	AuthenticateUbi(email, password string) error
	AuthenticateUbiTicket(ticket string) error
	AuthenticateBasic(username, password string) error
	AuthenticateBasicEmail(email, password, region string) error
	GetTokenInfo() TokenInfo

	Get(url string, useCache bool) ([]byte, error)
	Options(url string, useCache bool) ([]byte, error)
	Head(url string, useCache bool) ([]byte, error)
	Post(url, data string) ([]byte, error)
	Put(url, data string) ([]byte, error)
	Patch(url, data string) ([]byte, error)
	Delete(url string) ([]byte, error)

	AsyncGet(url string, useCache bool) chan AsyncResponse
	AsyncOptions(url string, useCache bool) chan AsyncResponse
	AsyncHead(url string, useCache bool) chan AsyncResponse
	AsyncPost(url, data string) chan AsyncResponse
	AsyncPut(url, data string) chan AsyncResponse
	AsyncPatch(url, data string) chan AsyncResponse
	AsyncDelete(url string) chan AsyncResponse

	CheckRefresh() error

	SetUserAgent(userAgent string)
	SetLogging(enabled bool)
	GetRequestCount() uint64
}

type nadeo struct {
	userAgent string

	baseURLCore string
	region      string
	audience    string

	accessToken  string
	refreshToken string

	tokenRefreshTime    uint32
	tokenExpirationTime uint32

	requestCache *cache.Cache

	logRequests  bool
	requestCount uint64
}

func (n *nadeo) AuthenticateUbi(email, password string) error {
	ubi := NewUbi("86263886-327a-4328-ac69-527f0d20a237")
	ubi.Authenticate(email, password)
	return n.AuthenticateUbiTicket(ubi.GetTicket())
}

func (n *nadeo) AuthenticateUbiTicket(ticket string) error {
	body := bytes.NewReader([]byte("{\"audience\":\"" + n.audience + "\"}"))

	req, err := http.NewRequest("POST", n.baseURLCore+"/v2/authentication/token/ubiservices", body)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "ubi_v1 t="+ticket)
	if n.userAgent != "" {
		req.Header.Add("User-Agent", n.userAgent)
	}

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

func (n *nadeo) AuthenticateBasic(username, password string) error {
	body := bytes.NewReader([]byte("{\"audience\":\"" + n.audience + "\"}"))

	req, err := http.NewRequest("POST", n.baseURLCore+"/v2/authentication/token/basic", body)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	if n.userAgent != "" {
		req.Header.Add("User-Agent", n.userAgent)
	}
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

func (n *nadeo) AuthenticateBasicEmail(email, password, region string) error {
	body := bytes.NewReader([]byte("{\"audience\":\"" + n.audience + "\"}"))

	req, err := http.NewRequest("POST", n.baseURLCore+"/v2/authentication/token/basic", body)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	if n.userAgent != "" {
		req.Header.Add("User-Agent", n.userAgent)
	}

	auth := "basic_email_v1 c="
	auth += base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
	if region != "" {
		auth += " r=" + region
	}
	req.Header.Set("Authorization", auth)

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

func (n *nadeo) Get(url string, useCache bool) ([]byte, error) {
	return n.request("GET", url, useCache, "")
}

func (n *nadeo) Options(url string, useCache bool) ([]byte, error) {
	return n.request("OPTIONS", url, useCache, "")
}

func (n *nadeo) Head(url string, useCache bool) ([]byte, error) {
	return n.request("HEAD", url, useCache, "")
}

func (n *nadeo) Post(url, data string) ([]byte, error) {
	return n.request("POST", url, false, data)
}

func (n *nadeo) Put(url, data string) ([]byte, error) {
	return n.request("PUT", url, false, data)
}

func (n *nadeo) Patch(url, data string) ([]byte, error) {
	return n.request("PATCH", url, false, data)
}

func (n *nadeo) Delete(url string) ([]byte, error) {
	return n.request("DELETE", url, false, "")
}

func (n *nadeo) AsyncGet(url string, useCache bool) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Get(url, useCache)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncOptions(url string, useCache bool) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Options(url, useCache)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncHead(url string, useCache bool) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Head(url, useCache)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncPost(url, data string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Post(url, data)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncPut(url, data string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Put(url, data)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncPatch(url, data string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Patch(url, data)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncDelete(url string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Delete(url)
		ret <- AsyncResponse{res, err}
	}()
	return ret
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

func (n *nadeo) SetUserAgent(userAgent string) {
	n.userAgent = userAgent
}

func (n *nadeo) SetLogging(enabled bool) {
	n.logRequests = enabled
}

func (n *nadeo) GetRequestCount() uint64 {
	return n.requestCount
}

func (n *nadeo) request(method string, url string, useCache bool, data string) ([]byte, error) {
	if useCache {
		cachedResponse, cacheFound := n.requestCache.Get(url)
		if cacheFound {
			return cachedResponse.([]byte), nil
		}
	}

	if n.logRequests {
		log.Trace("Nadeo request: %s => %s", method, url)
	}
	n.requestCount++

	err := n.CheckRefresh()
	if err != nil {
		return []byte{}, err
	}

	var body io.Reader
	if method == "POST" || method == "PUT" || method == "PATCH" {
		body = bytes.NewReader([]byte(data))
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Authorization", "nadeo_v1 t="+n.accessToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	if n.userAgent != "" {
		req.Header.Add("User-Agent", n.userAgent)
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to read from stream: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return []byte{}, fmt.Errorf("error from server: %s", getError(resBytes))
	}

	if useCache {
		n.requestCache.Set(url, string(resBytes), cache.DefaultExpiration)
	}

	return resBytes, nil
}

func (n *nadeo) refreshNow() error {
	req, err := http.NewRequest("POST", n.baseURLCore+"/v2/authentication/token/refresh", nil)
	if err != nil {
		return fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Authorization", "nadeo_v1 t="+n.refreshToken)
	if n.userAgent != "" {
		req.Header.Add("User-Agent", n.userAgent)
	}

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
	return NewNadeoWithCoreAndAudience(
		"https://prod.trackmania.core.nadeo.online",
		audience,
	)
}

// NewNadeoWithCoreAndAudience creates a new Nadeo object ready for authentication with the given core API base URL and audience.
func NewNadeoWithCoreAndAudience(core, audience string) Nadeo {
	return &nadeo{
		baseURLCore: core,
		audience:    audience,

		requestCache: cache.New(1*time.Minute, 5*time.Minute),
	}
}
