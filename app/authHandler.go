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
	loginRequestDTO := dto.LoginRequestDTO{}

	if err := json.NewDecoder(r.Body).Decode(&loginRequestDTO); err != nil {
		logger.Error("Error while decoding json body of login request: " + err.Error())
		writeTextResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	token, appErr := h.service.Login(loginRequestDTO)
	if appErr != nil {
		writeTextResponse(w, appErr.Code, appErr.Message)
		return
	}

	writeTextResponse(w, http.StatusOK, token)
}

func (h AuthHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") == "" {
		logger.Error("No token in url")
		writeVerificationJsonResponse(w, http.StatusUnauthorized, "Missing token", false)
		return
	}
	verifyRequestDTO := dto.VerifyRequestDTO{
		TokenString: r.URL.Query().Get("token"),
		RouteName:   r.URL.Query().Get("route_name"),
		CustomerId:  r.URL.Query().Get("customer_id"),
		AccountId:   r.URL.Query().Get("account_id"),
	}

	success, err := h.service.IsVerificationSuccess(verifyRequestDTO)
	if !success || err != nil {
		writeVerificationJsonResponse(w, err.Code, err.Message, false)
		return
	}

	writeVerificationJsonResponse(w, http.StatusOK, "success", true)
}

func writeTextResponse(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	if _, err := w.Write([]byte(msg)); err != nil {
		logger.Fatal("Error while sending response")
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
