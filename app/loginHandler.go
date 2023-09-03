package app

import (
	"banking-auth/dto"
	"banking-auth/service"
	"encoding/json"
	"net/http"
)

type LoginHandler struct { //REST handler (adapter)
	service service.LoginService //REST handler depends on service (service is a field)
}

func (h LoginHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	loginRequestDTO := dto.LoginRequestDTO{}

	err := json.NewDecoder(r.Body).Decode(&loginRequestDTO)
	if err != nil {
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

func writeJsonResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
