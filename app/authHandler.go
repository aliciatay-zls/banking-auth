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
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding json body of login request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}

	if appErr := loginRequest.Validate(); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
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
	var tokenStrings dto.TokenStrings
	if err := json.NewDecoder(r.Body).Decode(&tokenStrings); err != nil {
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
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

func (h AuthHandler) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") == "" {
		logger.Error("No token in url")
		writeJsonResponse(w, http.StatusUnauthorized, errs.NewMessageObject(errs.MessageMissingToken))
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
	var tokenStrings dto.TokenStrings
	if err := json.NewDecoder(r.Body).Decode(&tokenStrings); err != nil {
		logger.Error("Error while decoding json body of refresh request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}
	if appErr := tokenStrings.Validate(); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	response, appErr := h.service.Refresh(tokenStrings)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

func (h AuthHandler) ContinueHandler(w http.ResponseWriter, r *http.Request) {
	var tokenStrings dto.TokenStrings
	if err := json.NewDecoder(r.Body).Decode(&tokenStrings); err != nil {
		logger.Error("Error while decoding json body of continue request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}
	if appErr := tokenStrings.Validate(); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	response, appErr := h.service.CheckAlreadyLoggedIn(tokenStrings)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, response)
}

func writeJsonResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
