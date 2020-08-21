package nadeo

type ubiAuthResponse struct {
	PlatformType                  string
	Ticket                        string
	TwoFactorAuthenticationTicket string
	ProfileID                     string
	UserID                        string
	NameOnPlatform                string
	Environment                   string
	Expiration                    string
	SpaceID                       string
	ClientIP                      string
	ClientIPCountry               string
	ServerTime                    string
	SessionID                     string
	SessionKey                    string
	RememberMeTicket              string
}

type authResponse struct {
	AccessToken  string
	RefreshToken string
}

type errorResponse struct {
	Error   string // NLS
	Message string // NLS & Core
	Code    int    // Core

	TraceID       string // NLS
	CorrelationID string `json:"correlation_id"` // Core
}

type ubiErrorResponse struct {
	Message         string
	ErrorCode       int
	HTTPCode        int
	ErrorContext    string
	MoreInfo        string
	TransactionTime string
	TransactionID   string
	Environment     string
}
