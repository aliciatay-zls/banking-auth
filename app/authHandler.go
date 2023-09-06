package app

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"log"
	"net/http"
	"time"
)

type AuthHandler struct { //REST handler (adapter)
	service service.LoginService //REST handler depends on service (service is a field)
}

func (h AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	loginRequestDTO := dto.LoginRequestDTO{}

	if err := json.NewDecoder(r.Body).Decode(&loginRequestDTO); err != nil {
		logger.Error("Error while decoding json body of login request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	token, appErr := h.service.Login(loginRequestDTO)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, token)
}

func (h AuthHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("pinged from banking")
	//writeJsonResponse(w, http.StatusOK, "successfully pinged auth from banking")

	//verify validity of the token: verify expiry + verify signature
	tokenString := r.URL.Query().Get("token")
	token, err := jwt.Parse(tokenString,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}), //same as checking if Method==alg inside keyFunc?
	)
	if !token.Valid {
		logger.Error("Invalid token: " + err.Error())
		errs.NewAuthenticationError("Token is invalid")
	}

	date, err := token.Claims.GetExpirationTime() //registered claims
	if err != nil {
		logger.Error("Error while getting parsed token's expiry time: " + err.Error())
		errs.NewUnexpectedError("Unexpected authentication error")
	}
	if date.Time.After(time.Now()) {
		logger.Error("Expired token")
		errs.NewAuthenticationError("Token has expired")
	}

	//admin can access all routes (get role from token Body) //public claims

	//user can only access some routes

	//user can only access his own routes (get customer_id from token Body)
}

func writeJsonResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
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
