package app

import (
	"encoding/json"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/http"
)

type RegistrationHandler struct {
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

	response, appErr := h.service.Register(registrationRequest)
	if appErr != nil {
		writeJsonResponse(w, appErr.Code, appErr.AsMessage())
		return
	}

	writeJsonResponse(w, http.StatusCreated, response)
}