package oserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type ContentType string

const (
	ContentTypeJSON ContentType = "application/json"
	ContentTypeForm ContentType = "application/x-www-form-urlencoded"
)

type Handler struct {
	server      OServer
	contentType ContentType
}

func NewHandler(server OServer, contentType ContentType) Handler {
	return Handler{server: server, contentType: contentType}
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := AuthRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
	resp, err := h.server.Authorize(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// redirect back
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	s := u.Query()
	s.Set("code", resp.Code)
	if resp.State != "" {
		s.Set("state", resp.State)
	}
	u.RawQuery = s.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// TokenHandler handles /token POST requests
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	req, err := h.parseTokenRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := h.server.Token(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.writeResponse(w, r, resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	req, err := h.parseRevocationRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.server.Revoke(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	req, err := h.parseIntrospectRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := h.server.Introspect(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.writeResponse(w, r, resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) JWKs(w http.ResponseWriter, r *http.Request) {
	resp, err := h.server.JWKs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.writeResponse(w, r, resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func (h *Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var client OAuthClient
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	out, err := h.server.RegisterClient(r.Context(), &client)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.writeResponse(w, r, out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func (h *Handler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	// assume mux sets url param "id"
	id := strings.TrimPrefix(r.URL.Path, "/clients/")
	var client OAuthClient
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	client.ClientID = id
	out, err := h.server.UpdateClient(r.Context(), &client)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.writeResponse(w, r, out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func (h *Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/clients/")
	if err := h.server.DeleteClient(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/clients/")
	out, err := h.server.GetClient(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := h.writeResponse(w, r, out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	acc := r.URL.Query().Get("account_id")
	out, err := h.server.ListClients(r.Context(), acc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.writeResponse(w, r, out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) SetClientImage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/clients/")
	id = strings.TrimSuffix(id, "/image")
	if err := h.server.SetClientImage(r, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
func (h *Handler) SendClientImage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/clients/")
	id = strings.TrimSuffix(id, "/image")
	if err := h.server.SendClientImage(w, r, id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
	}
}

// HasAccessMiddleware wraps a handler to enforce RBAC via HasAccess()
func (h *Handler) HasAccessMiddleware(resource string, hasRbacAccess func(string, string, ...string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, err := h.server.HasAccess(r, resource, hasRbacAccess)
			if err != nil || !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeResponse serializes `data` either as JSON or
// as URL-encoded form data, based on h.respType.
func (h *Handler) writeResponse(w http.ResponseWriter, r *http.Request, data interface{}) error {
	requestType := r.Header.Get("Content-Type")
	if requestType == "" {
		requestType = string(h.contentType)
	}
	switch ContentType(requestType) {
	case ContentTypeJSON:
		w.Header().Set("Content-Type", string(ContentTypeJSON))
		return json.NewEncoder(w).Encode(data)

	case ContentTypeForm:
		w.Header().Set("Content-Type", string(ContentTypeForm))
		// marshal→map→url.Values→string
		b, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("form-encode marshal: %w", err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("form-encode unmarshal: %w", err)
		}
		vals := url.Values{}
		for k, v := range m {
			vals.Set(k, fmt.Sprintf("%v", v))
		}
		_, err = w.Write([]byte(vals.Encode()))
		return err

	default:
		return fmt.Errorf("unsupported response type: %s", requestType)
	}
}

// parseRevocationRequest supports both form and JSON bodies.
func (h *Handler) parseRevocationRequest(r *http.Request) (RevocationRequest, error) {
	var req RevocationRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), string(ContentTypeForm)) {
		if err := r.ParseForm(); err != nil {
			return req, err
		}
		req = RevocationRequest{
			Token:        r.Form.Get("token"),
			TokenType:    r.Form.Get("token_type_hint"),
			ClientID:     r.Form.Get("client_id"),
			ClientSecret: r.Form.Get("client_secret"),
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return req, err
		}
	}
	return req, nil
}

// parseIntrospectRequest likewise.
func (h *Handler) parseIntrospectRequest(r *http.Request) (IntrospectRequest, error) {
	var req IntrospectRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), string(ContentTypeForm)) {
		if err := r.ParseForm(); err != nil {
			return req, err
		}
		req = IntrospectRequest{
			Token:     r.Form.Get("token"),
			TokenType: r.Form.Get("token_type_hint"),
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return req, err
		}
	}
	return req, nil
}

// parseIntrospectRequest likewise.
func (h *Handler) parseTokenRequest(r *http.Request) (TokenRequest, error) {
	var req TokenRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), string(ContentTypeForm)) {
		if err := r.ParseForm(); err != nil {
			return req, err
		}
		req = TokenRequest{
			GrantType:    r.Form.Get("grant_type"),
			Code:         r.Form.Get("code"),
			RedirectURI:  r.Form.Get("redirect_uri"),
			RefreshToken: r.Form.Get("refresh_token"),
			ClientID:     r.Form.Get("client_id"),
			ClientSecret: r.Form.Get("client_secret"),
			CodeVerifier: r.Form.Get("code_verifier"),
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return req, err
		}
	}
	return req, nil
}
