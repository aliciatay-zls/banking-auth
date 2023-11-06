package app

import (
	"encoding/json"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/errs"
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
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}

	response, appErr := h.service.Login(loginRequest)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

func (h AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	var tokenStrings dto.TokenStrings
	if err := json.NewDecoder(r.Body).Decode(&tokenStrings); err != nil {
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject("Missing token"))
		return
	}
	if appErr := tokenStrings.ValidateRefreshToken(); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	if appErr := h.service.Logout(tokenStrings.RefreshToken); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, errs.NewMessageObject(""))
}

func (h AuthHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") == "" {
		logger.Error("No token in url")
		writeJsonResponse(w, http.StatusForbidden, errs.NewMessageObject("Missing token"))
		return
	}
	verifyRequest := dto.VerifyRequest{
		TokenString: r.URL.Query().Get("token"),
		RouteName:   r.URL.Query().Get("route_name"),
		CustomerId:  r.URL.Query().Get("customer_id"),
		AccountId:   r.URL.Query().Get("account_id"),
	}

	if appErr := h.service.Verify(verifyRequest); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, errs.NewMessageObject(""))
}

func (h AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	var refreshRequest dto.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		logger.Error("Error while decoding json body of refresh request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}
	if appErr := refreshRequest.TokenStrings.Validate(); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	response, appErr := h.service.Refresh(refreshRequest)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

func (h AuthHandler) ContinueHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	var continueRequest dto.ContinueRequest
	if err := json.NewDecoder(r.Body).Decode(&continueRequest); err != nil {
		logger.Error("Error while decoding json body of continue request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}
	if appErr := continueRequest.TokenStrings.Validate(); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	response, appErr := h.service.CheckAlreadyLoggedIn(continueRequest)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

// enableCORS is called at the start of the handler of any exposed APIs in order to accept requests from the frontend
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
