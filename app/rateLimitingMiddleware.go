package app

import (
	"fmt"
	"github.com/aliciatay-zls/banking-auth/domain"
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/logger"
	"github.com/gorilla/mux"
	"net"
	"net/http"
	"os"
)

type RateLimitingMiddleware struct {
	repo domain.VisitorRepository
}

// RateLimitingHandler ensures that for login and registration routes, requests per user (based on IP address)
// cannot be too frequent. For all routes, it responds to preflight requests with the necessary headers.
// Reference used to write this file, visitor.go and visitorRepository.go:
// https://www.alexedwards.net/blog/how-to-rate-limit-http-requests
func (m *RateLimitingMiddleware) RateLimitingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		if r.Method == http.MethodOptions {
			writeJsonResponse(w, http.StatusOK, errs.NewMessageObject(""))
			return
		}

		routeName := mux.CurrentRoute(r).GetName()
		if routeName == "Login" || routeName == "Register" {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				logger.Error("Error getting IP address of visitor")
				writeJsonResponse(w, http.StatusInternalServerError, errs.NewMessageObject("Unexpected server-side error"))
				return
			}

			visitor := m.repo.GetVisitor(ip)

			if !visitor.Limiter.Allow() {
				logger.Error(fmt.Sprintf("Too many %s requests in 1 sec", routeName))
				writeJsonResponse(w, http.StatusTooManyRequests, errs.NewMessageObject("Too many attempts"))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Add("Access-Control-Allow-Origin",
		fmt.Sprintf("https://%s", os.Getenv("FRONTEND_SERVER_DOMAIN")))
	w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
