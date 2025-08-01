package registry

// Option is the registry token authorization server configuration options
type Option struct {
	// an Authorizer implementation to authorize registry users
	Authorizer Authorizer
	// an Authenticator implementation to authenticate registry users
	Authenticator Authenticator
	// a pluggable tokenGenerator
	TokenGenerator TokenGenerator
	// .crt & .key file to sign JWT tokens
	Certfile string
	Keyfile  string
	// token expiration time
	TokenExpiration int64
	// token issuer specified in docker registry configuration file
	TokenIssuer string

	Logger Logger
}

type TokenOption struct {
	Expire int64
	Issuer string
}

// AuthorizationRequest is the authorization request data
type AuthorizationRequest struct {
	Account string
	Service string
	Type    string
	Name    string
	IP      string
	Actions []string
}

type Logger interface {
	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
}
