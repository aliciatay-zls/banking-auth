package app

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/http"
	"strings"
	"time"
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
	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		logger.Error("No token in url")
		newErr := errs.NewUnexpectedError("Unexpected authentication error")
		writeTextResponse(w, newErr.Code, newErr.Message)
		return
	}

	//verify validity of the token: verify expiry + verify signature
	claims := domain.CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(domain.SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}), //same as checking if Method==alg inside keyFunc?
	)
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		newErr := errs.NewUnexpectedError("Unexpected authentication error")
		writeTextResponse(w, newErr.Code, newErr.Message)
		return
	}
	if !token.Valid {
		logger.Error("Invalid token")
		newErr := errs.NewAuthenticationError("Token is invalid")
		writeTextResponse(w, newErr.Code, newErr.Message)
		return
	}

	date, err := claims.GetExpirationTime() //registered claims
	if err != nil {
		logger.Error("Error while getting parsed token's expiry time: " + err.Error())
		newErr := errs.NewUnexpectedError("Unexpected authentication error")
		writeTextResponse(w, newErr.Code, newErr.Message)
		return
	}
	if !date.Time.After(time.Now()) { //token expiry date is before or at current time = expired
		logger.Error("Expired token")
		newErr := errs.NewAuthenticationError("Token has expired")
		writeTextResponse(w, newErr.Code, newErr.Message)
		return
	}

	//admin can access all routes (get role from token Body) //public claims "customer_id", "role", etc
	if claims.Role == "admin" {
		writeTextResponse(w, http.StatusOK, "Admin can access all routes")
	} else if claims.Role == "user" {
		//user can only access some routes
		route := r.URL.Query().Get("route_name")
		if route == "GetAllCustomers" || route == "NewAccount" {
			logger.Error("User trying to access admin-only routes")
			newErr := errs.NewAuthenticationError("Access denied")
			writeTextResponse(w, newErr.Code, newErr.Message)
			return
		}

		//user can only access his own routes (get customer_id from token Body)
		customerIdRouteVar := r.URL.Query().Get("customer_id")
		customerIdClaim := claims.CustomerId
		if route == "GetCustomer" {
			if customerIdRouteVar != customerIdClaim {
				logger.Error("User trying to access another customer's details")
				newErr := errs.NewAuthenticationError("Access denied")
				writeTextResponse(w, newErr.Code, newErr.Message)
				return
			}
		} else if route == "NewTransaction" {
			accountIdRouteVar := r.URL.Query().Get("account_id")
			accountIdClaim := strings.Split(claims.AllAccountIds, ",")
			for _, accountId := range accountIdClaim {
				if accountIdRouteVar == accountId {
					writeTextResponse(w, http.StatusOK, "User can access new transaction route for himself")
					return
				}
			}
			logger.Error("User trying to make transaction for another customer's account")
			newErr := errs.NewAuthenticationError("Access denied")
			writeTextResponse(w, newErr.Code, newErr.Message)
		}
	} else {
		newErr := errs.NewAuthenticationError("Unknown role")
		writeTextResponse(w, newErr.Code, newErr.Message)
	}
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
