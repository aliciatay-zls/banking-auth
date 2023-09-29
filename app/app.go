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
	"os"
	"time"
)

func checkEnvVars() {
	envVars := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
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

	router := mux.NewRouter()

	dbClient := getDbClient()
	userRepository := domain.NewUserRepositoryDb(dbClient)
	ah := AuthHandler{service.NewDefaultAuthService(userRepository, domain.NewRolePermissions())}

	router.HandleFunc("/auth/login", ah.LoginHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.VerificationHandler).Methods(http.MethodGet)
	router.HandleFunc("/auth/refresh", ah.RefreshHandler).Methods(http.MethodPost)

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
