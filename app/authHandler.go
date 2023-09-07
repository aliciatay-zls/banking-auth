package app

import (
	"encoding/json"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/http"
)

type AuthHandler struct { //REST handler (adapter)
	service service.LoginService //REST handler depends on service (service is a field)
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
	//verify validity of the token: verify signature
	tokenString := r.URL.Query().Get("token")
	t, err := domain.GetValidToken(tokenString)
	if err != nil {
		writeTextResponse(w, err.Code, err.Message)
		return
	}

	//verify validity of the token: verify expiry
	isTokenExpired, appErr := t.IsExpired()
	if isTokenExpired || appErr != nil {
		writeTextResponse(w, appErr.Code, appErr.Message)
		return
	}

	//admin can access all routes (get role from token Body)
	if t.CustomClaims.IsRoleAdmin() {
		writeTextResponse(w, http.StatusOK, "Admin can access all routes")
		return
	}

	//user can only access some routes
	route := r.URL.Query().Get("route_name")
	isRouteForbidden, appErr := t.CustomClaims.IsForbidden(route)
	if isRouteForbidden || appErr != nil {
		writeTextResponse(w, appErr.Code, appErr.Message)
		return
	}

	//user can only access his own routes (get customer_id from token Body)
	customerId := r.URL.Query().Get("customer_id")
	accountId := r.URL.Query().Get("account_id")
	hasMismatch, appErr := t.CustomClaims.HasMismatch(route, customerId, accountId)
	if hasMismatch || appErr != nil {
		writeTextResponse(w, appErr.Code, appErr.Message)
		return
	}

	writeTextResponse(w, http.StatusOK, "Client is authorized to access this route")
}

func writeTextResponse(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	if _, err := w.Write([]byte(msg)); err != nil {
		logger.Fatal("Error while sending response")
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
