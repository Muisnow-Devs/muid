package httpx

import (
	"encoding/json"
	"net/http"

	"sanzi.io/muid/pkg/log"
)

// JSON writes v as a JSON response with the given status code.
func JSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Logger(r.Context()).Warn("failed to encode json response", "error", err.Error())
	}
}

// errorBody is the gateway's generic error envelope. It deliberately omits
// internal detail so raw errors never leak to clients.
type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Error writes a JSON error envelope. The code/description are safe, public
// values (e.g. OAuth error codes), never raw internal errors.
func Error(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, ErrorDescription: description})
}
