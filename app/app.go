package app

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql" //important
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/service"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

func checkEnvVars() {
	envVars := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"MAILHOG_SERVER_ADDRESS",
		"MAILHOG_SERVER_PORT",
		"FRONTEND_SERVER_ADDRESS",
		"FRONTEND_SERVER_PORT",
		"DB_USER",
		"DB_PASSWORD",
		"DB_ADDRESS",
		"DB_PORT",
		"DB_NAME",
	}

	for _, key := range envVars {
		if os.Getenv(key) == "" {
			logger.Fatal(fmt.Sprintf("Environment variable %s was not defined", key))
		}
	}
}

func Start() {
	checkEnvVars()

	mailClient, disconnectCallback := getMailClient()

	router := mux.NewRouter()

	dbClient := getDbClient()
	authRepositoryDb := domain.NewAuthRepositoryDb(dbClient)
	registrationRepositoryDb := domain.NewRegistrationRepositoryDb(dbClient)
	emailRepositoryDb := domain.NewEmailRepositoryDb(mailClient, disconnectCallback)
	ah := AuthHandler{service.NewDefaultAuthService(authRepositoryDb, registrationRepositoryDb, domain.NewRolePermissions())}
	rh := RegistrationHandler{service.NewRegistrationService(registrationRepositoryDb, emailRepositoryDb)}

	router.HandleFunc("/auth/login", ah.LoginHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/logout", ah.LogoutHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.VerifyHandler).Methods(http.MethodGet)
	router.HandleFunc("/auth/refresh", ah.RefreshHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/continue", ah.ContinueHandler).Methods(http.MethodPost)

	router.HandleFunc("/auth/register", rh.RegisterHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/register/check", rh.CheckRegistrationHandler).Methods(http.MethodGet)
	router.HandleFunc("/auth/register/finish", rh.FinishRegistrationHandler).Methods(http.MethodPost)

	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	err := http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router)
	if err != nil {
		logger.Fatal(err.Error())
	}
}

func getDbClient() *sqlx.DB {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbAddress := os.Getenv("DB_ADDRESS")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dataSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbAddress, dbPort, dbName)
	db, err := sqlx.Open("mysql", dataSource)
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	return db
}

// getMailClient starts the smtp server and gets a client connected to it
func getMailClient() (*smtp.Client, func()) {
	serverAddr := os.Getenv("SERVER_ADDRESS")
	mailhogPort := os.Getenv("MAILHOG_SERVER_PORT")

	addr := fmt.Sprintf("%s:%s", serverAddr, mailhogPort)
	logger.Info("Starting SMTP server...")
	mailClient, err := smtp.Dial(addr)
	if err != nil {
		logger.Fatal("Error while starting SMTP server: " + err.Error())
	}

	return mailClient, func() {
		defer func() {
			logger.Info("Disconnecting from SMTP server...")
			if err = mailClient.Close(); err != nil {
				logger.Fatal("Error while closing connection to SMTP server: " + err.Error())
			}
		}()
	}
}
