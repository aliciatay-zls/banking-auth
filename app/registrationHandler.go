package app

import (
	"encoding/json"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/http"
)

type RegistrationHandler struct { //REST handler (adapter)
	service service.RegistrationService
}

func (h RegistrationHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	var registrationRequest dto.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&registrationRequest); err != nil {
		logger.Error("Error while decoding json body of registration request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}

	//if appErr := registrationRequest.Validate(); appErr != nil { //TODO: parse fields + sanitize
	//	writeJsonResponse(w, appErr.Code, appErr.AsMessage())
	//	return
	//}

	response, appErr := h.service.Register(registrationRequest)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusCreated, response)
}

func (h RegistrationHandler) CheckRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	tokenString := r.URL.Query().Get("ott")
	if tokenString == "" {
		logger.Error("No token in url")
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(errs.MessageMissingToken))
		return
	}

	isConfirmed, appErr := h.service.CheckRegistration(tokenString)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}
	if isConfirmed {
		writeJsonResponse(w, http.StatusOK, errs.NewMessageObject("Registration already confirmed"))
		return
	}

	writeJsonResponse(w, http.StatusOK, errs.NewMessageObject(""))
}

func (h RegistrationHandler) ResendHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	tokenString := r.URL.Query().Get("ott")
	if tokenString == "" {
		logger.Error("No token in url")
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(errs.MessageMissingToken))
		return
	}

	if appErr := h.service.ResendLink(tokenString); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, errs.NewMessageObject(""))
}

func (h RegistrationHandler) FinishRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)

	var request dto.FinishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		logger.Error("Error while decoding json body of finish registration request: " + err.Error())
		writeJsonResponse(w, http.StatusBadRequest, errs.NewMessageObject(err.Error()))
		return
	}
	if request.Token == "" {
		logger.Error("One time token missing or empty in request body")
		writeJsonResponse(w, http.StatusUnprocessableEntity,
			errs.NewMessageObject("Field missing or empty in request body: refresh_token"))
		return
	}

	if appErr := h.service.FinishRegistration(request.Token); appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusOK, errs.NewMessageObject(""))
}
