package nadeo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/codecat/go-libs/log"
	"github.com/patrickmn/go-cache"
)

// AsyncResponse contains the result of an asynchronous API request.
type AsyncResponse struct {
	Buf []byte
	Err error
}

// Nadeo provides access to Nadeo Services.
type Nadeo interface {
	AuthenticateUbi(email, password string) error
	AuthenticateUbiTicket(ticket string) error
	AuthenticateBasic(username, password string) error
	AuthenticateBasicEmail(email, password, region string) error
	GetTokenInfo() TokenInfo

	Get(url string, cacheTime time.Duration) ([]byte, error)
	Options(url string, cacheTime time.Duration) ([]byte, error)
	Head(url string, cacheTime time.Duration) ([]byte, error)
	Post(url string, data []byte) ([]byte, error)
	Put(url string, data []byte) ([]byte, error)
	Patch(url string, data []byte) ([]byte, error)
	Delete(url string) ([]byte, error)

	GetUncached(url string) ([]byte, error)
	OptionsUncached(url string) ([]byte, error)
	HeadUncached(url string) ([]byte, error)

	AsyncGet(url string, cacheTime time.Duration) chan AsyncResponse
	AsyncOptions(url string, cacheTime time.Duration) chan AsyncResponse
	AsyncHead(url string, cacheTime time.Duration) chan AsyncResponse
	AsyncPost(url string, data []byte) chan AsyncResponse
	AsyncPut(url string, data []byte) chan AsyncResponse
	AsyncPatch(url string, data []byte) chan AsyncResponse
	AsyncDelete(url string) chan AsyncResponse

	AsyncGetUncached(url string) chan AsyncResponse
	AsyncOptionsUncached(url string) chan AsyncResponse
	AsyncHeadUncached(url string) chan AsyncResponse

	CheckRefresh() error

	SetUserAgent(userAgent string)
	SetLogging(enabled bool)
	GetRequestCount() uint64
	SetIdempotency(enabled bool)
	SetTimeout(timeout time.Duration)
}

type nadeo struct {
	client http.Client

	idempotency    sync.Map
	useIdempotency bool

	userAgent string

	baseURLCore string
	audience    string

	accessToken  string
	refreshToken string

	tokenRefreshTime    uint32
	tokenExpirationTime uint32
	tokenRefreshMutex   sync.Mutex

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

	resp, err := n.client.Do(req)
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

	resp, err := n.client.Do(req)
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

	resp, err := n.client.Do(req)
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

func (n *nadeo) Get(url string, cacheTime time.Duration) ([]byte, error) {
	return n.request("GET", url, cacheTime, nil)
}

func (n *nadeo) Options(url string, cacheTime time.Duration) ([]byte, error) {
	return n.request("OPTIONS", url, cacheTime, nil)
}

func (n *nadeo) Head(url string, cacheTime time.Duration) ([]byte, error) {
	return n.request("HEAD", url, cacheTime, nil)
}

func (n *nadeo) Post(url string, data []byte) ([]byte, error) {
	return n.request("POST", url, 0, data)
}

func (n *nadeo) Put(url string, data []byte) ([]byte, error) {
	return n.request("PUT", url, 0, data)
}

func (n *nadeo) Patch(url string, data []byte) ([]byte, error) {
	return n.request("PATCH", url, 0, data)
}

func (n *nadeo) Delete(url string) ([]byte, error) {
	return n.request("DELETE", url, 0, nil)
}

func (n *nadeo) GetUncached(url string) ([]byte, error) {
	return n.request("GET", url, 0, nil)
}

func (n *nadeo) OptionsUncached(url string) ([]byte, error) {
	return n.request("OPTIONS", url, 0, nil)
}

func (n *nadeo) HeadUncached(url string) ([]byte, error) {
	return n.request("HEAD", url, 0, nil)
}

func (n *nadeo) AsyncGet(url string, cacheTime time.Duration) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Get(url, cacheTime)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncOptions(url string, cacheTime time.Duration) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Options(url, cacheTime)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncHead(url string, cacheTime time.Duration) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Head(url, cacheTime)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncPost(url string, data []byte) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Post(url, data)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncPut(url string, data []byte) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.Put(url, data)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncPatch(url string, data []byte) chan AsyncResponse {
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

func (n *nadeo) AsyncGetUncached(url string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.GetUncached(url)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncOptionsUncached(url string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.OptionsUncached(url)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) AsyncHeadUncached(url string) chan AsyncResponse {
	ret := make(chan AsyncResponse)
	go func() {
		res, err := n.HeadUncached(url)
		ret <- AsyncResponse{res, err}
	}()
	return ret
}

func (n *nadeo) CheckRefresh() error {
	n.tokenRefreshMutex.Lock()
	defer n.tokenRefreshMutex.Unlock()

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

func (n *nadeo) SetIdempotency(enabled bool) {
	n.useIdempotency = enabled
}

func (n *nadeo) SetTimeout(timeout time.Duration) {
	n.client.Timeout = timeout
}

func (n *nadeo) request(method string, url string, cacheTime time.Duration, data []byte) ([]byte, error) {
	var lock *sync.Mutex
	defer func() {
		if lock != nil {
			lock.Unlock()
		}
	}()

	if cacheTime > 0 {
		if n.useIdempotency {
			lockAny, _ := n.idempotency.LoadOrStore(url, &sync.Mutex{})
			lock = lockAny.(*sync.Mutex)
			lock.Lock()
		}

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
		return nil, err
	}

	var body io.Reader
	if data != nil && (method == "POST" || method == "PUT" || method == "PATCH") {
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("unable to make request: %s", err.Error())
	}

	req.Header.Add("Authorization", "nadeo_v1 t="+n.accessToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	if n.userAgent != "" {
		req.Header.Add("User-Agent", n.userAgent)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to perform request: %s", err.Error())
	}

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read from stream: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return resBytes, fmt.Errorf("error %d from server: %s", resp.StatusCode, getError(resBytes))
	}

	if cacheTime > 0 {
		n.requestCache.Set(url, resBytes, cacheTime)
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

	resp, err := n.client.Do(req)
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
		client: http.Client{
			Timeout: 1 * time.Minute,
		},

		useIdempotency: true,

		baseURLCore: core,
		audience:    audience,

		requestCache: cache.New(1*time.Minute, 5*time.Minute),
	}
}
