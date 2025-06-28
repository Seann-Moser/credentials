package oserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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

// Authorize handles the OAuth 2.0 authorization endpoint requests.
// It now includes logic to display an optional consent page.
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

	// --- New Logic for Consent Page ---
	// Determine if the consent page should be shown.
	// In a real application, this logic would be more robust:
	// - Check if the user is authenticated.
	// - Check if the user has previously granted consent for this client and requested scopes.
	// - Based on your OAuth server's policy, you might always show consent,
	//   or only for new clients/scopes, or for sensitive scopes.
	// For this example, we'll use a query parameter `force_consent=true` to trigger it.
	forceConsent := q.Get("force_consent") == "true"

	// Retrieve client details. First try mock clients, then the actual OServer.
	client, err := h.server.GetClient(r.Context(), req.ClientID)
	if err != nil || client == nil {
		http.Error(w, fmt.Sprintf("client not found or unable to retrieve client details: %s", req.ClientID), http.StatusBadRequest)
		return
	}

	if forceConsent { // Replace this condition with your actual consent policy
		// Prepare data for the consent HTML template.
		data := ConsentPageData{
			ClientName:          client.Name,
			ClientImageURL:      client.ImageURL,
			RequestedScopes:     req.Scope,
			ResponseType:        req.ResponseType,
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			Scope:               req.Scope,
			State:               req.State,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := consentTemplate.Execute(w, data); err != nil {
			http.Error(w, "failed to render consent page", http.StatusInternalServerError)
		}
		return // Stop the flow here; the user will interact with the consent page and submit to /consent
	}
	// --- End New Logic ---

	// If no consent page is needed (or after consent is given via /consent endpoint),
	// proceed with the original authorization flow.
	h.proceedAuthorization(w, r, req)
}

// proceedAuthorization is a helper function to encapsulate the logic for
// completing the authorization flow and redirecting the user.
func (h *Handler) proceedAuthorization(w http.ResponseWriter, r *http.Request, req AuthRequest) {
	resp, err := h.server.Authorize(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Construct the redirect URI with the authorization code and state.
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

func (h *Handler) parseAuthRequest(r *http.Request) (*AuthRequest, error) {
	var req AuthRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), string(ContentTypeForm)) {
		// Parse the form data submitted from the consent page.
		if err := r.ParseForm(); err != nil {
			return nil, err
		}

		// Get the user's decision (accept/deny).
		decision := r.Form.Get("decision")
		if decision == "" {
			return nil, errors.New("decision is required")
		}

		// Reconstruct the original authorization request from hidden form fields.
		return &AuthRequest{
			ResponseType:        r.Form.Get("response_type"),
			ClientID:            r.Form.Get("client_id"),
			Decision:            decision,
			RedirectURI:         r.Form.Get("redirect_uri"),
			Scope:               r.Form.Get("scope"),
			State:               r.Form.Get("state"),
			CodeChallenge:       r.Form.Get("code_challenge"),
			CodeChallengeMethod: r.Form.Get("code_challenge_method"),
		}, nil
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
	}
	return &req, nil
}

// Consent handles the POST request from the consent page.
// It processes the user's decision (accept or deny) and continues the OAuth flow accordingly.
func (h *Handler) Consent(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := h.parseAuthRequest(r)
	// Parse the form data submitted from the consent page.
	if err != nil {
		http.Error(w, "failed to parse form data", http.StatusBadRequest)
		return
	}
	// Reconstruct the original authorization request from hidden form fields.
	switch req.Decision {
	case "accept":
		h.proceedAuthorization(w, r, *req)
	case "deny":
		u, err := url.Parse(req.RedirectURI)
		if err != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		q := u.Query()
		q.Set("error", "access_denied")
		if req.State != "" {
			q.Set("state", req.State)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	default:
		http.Error(w, "invalid consent decision", http.StatusBadRequest)
	}
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
func (h *Handler) HasAccessMiddleware(resource string, hasRbacAccess func(string, string, string, ...string) bool) func(http.Handler) http.Handler {
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

// ConsentPageData holds the necessary data to render the consent HTML template.
type ConsentPageData struct {
	ClientName      string
	ClientImageURL  string
	RequestedScopes string // Comma-separated string of requested scopes
	// Original authorization request parameters to be passed back to the /consent endpoint
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// consentPageHTML is the embedded HTML template for the OAuth consent page.
// It uses Tailwind CSS for styling and includes placeholders for dynamic content.
const consentPageHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Application</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f3f4f6;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
    </style>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-lg shadow-xl max-w-md w-full border border-gray-200">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 text-center">Authorize Application</h1>
        <div class="flex flex-col items-center mb-6">
            {{if .ClientImageURL}}
                <img src="{{.ClientImageURL}}" alt="{{.ClientName}} Logo" class="w-24 h-24 rounded-full border-4 border-indigo-500 shadow-md mb-4 object-cover">
            {{else}}
                <div class="w-24 h-24 rounded-full bg-gray-300 flex items-center justify-center text-gray-600 text-5xl font-semibold mb-4 border-4 border-gray-400">
                    {{if .ClientName}}{{.ClientName | firstChar}}{{else}}&#x1F4BB;{{end}}
                </div>
            {{end}}
            <h2 class="text-2xl font-semibold text-gray-900 text-center">{{.ClientName}}</h2>
        </div>

        <p class="text-gray-700 text-center mb-6">
            <span class="font-medium">"{{.ClientName}}"</span> would like to access your account.
        </p>

        <div class="bg-blue-50 p-4 rounded-lg mb-6 border border-blue-200">
            <h3 class="text-lg font-semibold text-blue-800 mb-2">This application is requesting the following permissions:</h3>
            <ul class="list-disc list-inside text-blue-700">
                {{range .RequestedScopes | split ","}}
                    <li class="mb-1"><code>{{.}}</code></li>
                {{end}}
            </ul>
            <p class="text-sm text-blue-600 mt-3">
                Granting these permissions allows "{{.ClientName}}" to perform actions on your behalf.
            </p>
        </div>

        <form action="/consent" method="POST" class="space-y-4">
            <!-- Hidden fields to pass original authorization request parameters -->
            <input type="hidden" name="response_type" value="{{.ResponseType}}">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="scope" value="{{.Scope}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

            <button type="submit" name="decision" value="accept"
                    class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-4 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-opacity-75">
                Accept and Continue
            </button>
            <button type="submit" name="decision" value="deny"
                    class="w-full bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-3 px-4 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-75">
                Deny
            </button>
        </form>
        <p class="text-xs text-gray-500 text-center mt-6">
            By clicking "Accept and Continue", you grant "{{.ClientName}}" access to your requested data.
        </p>
    </div>
</body>
</html>
`

// consentTemplate is the parsed HTML template for efficient rendering.
var consentTemplate *template.Template

// init function to parse the HTML template and register custom functions.
func init() {
	funcMap := template.FuncMap{
		// split function splits a string by a separator and returns a slice of strings.
		"split": func(s string, sep string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, sep)
		},
		// firstChar returns the first character of a string, or an empty string if the input is empty.
		"firstChar": func(s string) string {
			if len(s) > 0 {
				return string(s[0])
			}
			return ""
		},
	}
	// Parse the template with custom functions. template.Must panics if parsing fails.
	consentTemplate = template.Must(template.New("consent").Funcs(funcMap).Parse(consentPageHTML))
}
