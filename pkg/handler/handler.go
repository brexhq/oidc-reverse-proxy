package handler

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/twz123/oidc-reverse-proxy/pkg/auth"
	"github.com/twz123/oidc-reverse-proxy/pkg/sessions"
	"github.com/yhat/wsutil"
)

type Upstream struct {
	URL       *url.URL
	Transport *http.Transport
}

func NewAuthProxyHandler(upstream *Upstream, flow auth.Flow, sessions sessions.Store, sessionCookieTemplate *http.Cookie) http.Handler {
	handler := &handler{
		flow:                  flow,
		reverseProxy:          httputil.NewSingleHostReverseProxy(upstream.URL),
		wsReverseProxy:        wsutil.NewSingleHostReverseProxy(toWebsocketURL(upstream.URL)),
		sessions:              sessions,
		sessionCookieTemplate: sessionCookieTemplate,
	}

	handler.reverseProxy.Transport = upstream.Transport
	handler.reverseProxy.ModifyResponse = handler.modifyProxyResponse

	if upstream.URL.Scheme == "https" {
		handler.wsReverseProxy.Dial = upstream.Transport.DialTLS
	} else {
		handler.wsReverseProxy.Dial = upstream.Transport.Dial
	}

	return handler
}

type handler struct {
	flow                  auth.Flow
	reverseProxy          *httputil.ReverseProxy
	wsReverseProxy        *wsutil.ReverseProxy
	sessions              sessions.Store
	sessionCookieTemplate *http.Cookie
}

func (h *handler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	sessionID, err := h.sessionID(request)
	if err != nil {
		handleRedirect(h, responseWriter, request)
		return
	}

	session := h.sessions.Get(sessionID)
	if session == nil {
		handleRedirect(h, responseWriter, request)
		return
	}

	var responseFunc func(responseWriter http.ResponseWriter)
	session.DoWith(func(locked sessions.LockedSession) {
		responseFunc = h.serveSession(locked, request)
	})

	responseFunc(responseWriter)
}

func (h *handler) serveSession(session sessions.LockedSession, request *http.Request) func(responseWriter http.ResponseWriter) {
	authenticator := session.Authenticator()
	authentication, newAuthenticator, err := authenticator.Authenticate(request)
	if err != nil {
		return func(responseWriter http.ResponseWriter) {
			badRequest(err, responseWriter, request)
		}
	}

	if newAuthenticator != nil && newAuthenticator != authenticator {
		session.SetAuthenticator(newAuthenticator)
	}

	return func(responseWriter http.ResponseWriter) {
		redirectURL := authentication.InjectInto(request)

		if redirectURL == nil {
			if wsutil.IsWebSocketRequest(request) {
				h.wsReverseProxy.ServeHTTP(responseWriter, request)
			} else {
				h.reverseProxy.ServeHTTP(responseWriter, request)
			}
		} else {
			http.Redirect(responseWriter, request, redirectURL.String(), http.StatusTemporaryRedirect)
		}
	}
}

func (h *handler) sessionID(request *http.Request) (string, error) {
	request.Cookies()
	sessionCookie, err := request.Cookie(h.sessionCookieTemplate.Name)
	if err != nil {
		return "", err
	}

	return sessionCookie.Value, nil
}

func toWebsocketURL(original *url.URL) *url.URL {
	result := *original

	if result.Scheme == "https" {
		result.Scheme = "wss"
	} else {
		result.Scheme = "ws"
	}

	return &result
}
