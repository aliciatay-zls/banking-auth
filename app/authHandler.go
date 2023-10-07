package app

import (
	"encoding/json"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/http"
)

type AuthHandler struct { //REST handler (adapter)
	service service.AuthService //REST handler depends on service (service is a field)
}

func (h AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding json body of login request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	response, appErr := h.service.Login(loginRequest)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.Message)
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

func (h AuthHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") == "" {
		logger.Error("No token in url")
		writeVerificationJsonResponse(w, http.StatusForbidden, "Missing token", false)
		return
	}
	verifyRequest := dto.VerifyRequest{
		TokenString: r.URL.Query().Get("token"),
		RouteName:   r.URL.Query().Get("route_name"),
		CustomerId:  r.URL.Query().Get("customer_id"),
		AccountId:   r.URL.Query().Get("account_id"),
	}

	if err := h.service.Verify(verifyRequest); err != nil {
		writeVerificationJsonResponse(w, err.Code, err.Message, false)
		return
	}

	writeVerificationJsonResponse(w, http.StatusOK, "success", true)
}

func (h AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var refreshRequest dto.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		logger.Error("Error while decoding json body of refresh request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	if refreshRequest.AccessToken == "" || refreshRequest.RefreshToken == "" {
		logger.Error("Field(s) missing or empty in request body")
		writeJsonResponse(w, http.StatusBadRequest,
			"Field(s) missing or empty in request body: access_token, refresh_token")
		return
	}

	response, err := h.service.Refresh(refreshRequest)
	if err != nil {
		writeJsonResponse(w, err.Code, err.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000") //frontend domain
	w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Add("Access-Control-Allow-Headers", "*")
}

func writeJsonResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}

func writeVerificationJsonResponse(w http.ResponseWriter, code int, msg string, isAuthorized bool) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	response := map[string]interface{}{
		"is_authorized": isAuthorized,
		"message":       msg,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

//jwt.Parse(): verify signing method, etc, then call keyFunc() --> (*)
//https://github.com/golang-jwt/jwt/blob/v5.0.0/parser.go#L202
//
//keyFunc(): the function passed into jwt.Parse(). We have to make it return our secret (key) so that jwt.Parse()
//can use our key to verify the signature
//https://github.com/golang-jwt/jwt/blob/v5.0.0/parser.go#L94
//
//Keyfunc will be used by the Parse methods as a callback function to supply the key for verification. --> (*)
//The function receives the parsed, but unverified Token. This allows you to use properties in the Header of the token
//(such as `kid`) to identify which key to use. --> in the case where our app allows multiple signing algos
//https://pkg.go.dev/github.com/golang-jwt/jwt/v5@v5.0.0#Keyfunc
//
//jwt.ParseWithClaims(): verify signing method, keyFunc passed in, signature, claims passed in
//hence no need to verify signing method and signature after this call already (if managed to return jwt.Token,
//means valid so far)
//https://github.com/golang-jwt/jwt/blob/v5.0.0/parser.go#L55
