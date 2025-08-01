package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const signAuth = "AUTH"

// AuthServer is the token authentication server
type AuthServer struct {
	authorizer     Authorizer
	authenticator  Authenticator
	tokenGenerator TokenGenerator
	logger         Logger
	crt, key       string
}

// NewAuthServer creates a new AuthServer
func NewAuthServer(opt *Option) (*AuthServer, error) {
	if opt.Authenticator == nil {
		opt.Authenticator = &DefaultAuthenticator{}
	}
	if opt.Authorizer == nil {
		opt.Authorizer = &DefaultAuthorizer{}
	}

	if opt.Logger == nil {
		opt.Logger = logger{}
	}

	pb, prk, err := loadCertAndKey(opt.Certfile, opt.Keyfile)
	if err != nil {
		return nil, err
	}
	tk := &TokenOption{Expire: opt.TokenExpiration, Issuer: opt.TokenIssuer}
	if opt.TokenGenerator == nil {
		opt.TokenGenerator = newTokenGenerator(pb, prk, tk)
	}
	return &AuthServer{
		authorizer:     opt.Authorizer,
		authenticator:  opt.Authenticator,
		logger:         opt.Logger,
		tokenGenerator: opt.TokenGenerator, crt: opt.Certfile, key: opt.Keyfile,
	}, nil
}

func (srv *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.logger.Debugf("[%s] request received", r.URL.Path)
	// grab user's auth parameters
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	srv.logger.Debugf("[%s] request from user '%s'", r.URL.Path, username)

	if r.Context().Err() != nil {
		srv.logger.Debugf("[%s] user %s disconnected before authentication (%s)", r.URL.Path, username, r.Context().Err())
		http.Error(w, "unauthorized: disconnected too early (code 1)", http.StatusRequestTimeout)
		return
	}

	if err := srv.authenticator.Authenticate(r.Context(), username, password); err != nil {
		http.Error(w, "unauthorized: invalid auth credentials", http.StatusUnauthorized)
		return
	}
	srv.logger.Debugf("[%s] user %s authenticated", username)

	req := srv.parseRequest(r, username)

	if r.Context().Err() != nil {
		srv.logger.Debugf("[%s] user %s disconnected before authorization (%s)", r.URL.Path, username, r.Context().Err())
		http.Error(w, "unauthorized: disconnected too early (code 2)", http.StatusRequestTimeout)
		return
	}

	actions, err := srv.authorizer.Authorize(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	srv.logger.Debugf("[%s] user %s authorized", username)

	if r.Context().Err() != nil {
		srv.logger.Debugf("[%s] user %s disconnected before token generation (%s)", r.URL.Path, username, r.Context().Err())
		http.Error(w, "unauthorized: disconnected too early (code 3)", http.StatusRequestTimeout)
		return
	}
	// create token for this user using the actions returned
	// from the authorization check
	tk, err := srv.tokenGenerator.Generate(r.Context(), req, actions)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	srv.logger.Debugf("[%s] token generated to user %s", username)

	srv.ok(w, tk)
}

func (srv *AuthServer) parseRequest(r *http.Request, username string) *AuthorizationRequest {
	q := r.URL.Query()
	req := &AuthorizationRequest{
		Service: q.Get("service"),
		Account: username,
	}
	parts := strings.Split(r.URL.Query().Get("scope"), ":")
	if len(parts) > 0 {
		req.Type = parts[0]
	}
	if len(parts) > 1 {
		req.Name = parts[1]
	}
	if len(parts) > 2 {
		req.Actions = strings.Split(parts[2], ",")
	}
	return req
}

func (srv *AuthServer) Run(addr string) error {
	http.Handle("/", srv)
	fmt.Printf("Authentication server running at %s", addr)
	return http.ListenAndServeTLS(addr, srv.crt, srv.key, nil)
}

func (srv *AuthServer) ok(w http.ResponseWriter, tk *Token) {
	data, _ := json.Marshal(tk)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func encodeBase64(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
