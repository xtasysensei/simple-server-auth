package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"simple-server-auth/passwordhashing"
	"syscall"
	"time"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslations "github.com/go-playground/validator/v10/translations/en"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
)

type User struct {
	Username string `json:"username" validate:"required,min=5,max=20,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=5,customPassword"`
}

var connStr, dbname string

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	host := os.Getenv("POSTGRES_SERVER")
	dbname = os.Getenv("POSTGRES_DB")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")

	connStr = fmt.Sprintf("user=%s dbname=%s password=%s host=%s sslmode=disable", user, dbname, password, host)
}

// handles the shutdown of the server
func gracefulShutdown(server *http.Server) {
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		log.Println("Service interrupt received")

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP server Shutdown error: %v", err)
		}
		log.Println("Shutdown complete")
		close(idleConnsClosed)
	}()

	<-idleConnsClosed
	log.Println("Service stopped")
}

func translateError(err error, trans ut.Translator) (errs []error) {
	if err == nil {
		return nil
	}
	validatorErrs := err.(validator.ValidationErrors)
	for _, e := range validatorErrs {
		translatedErr := fmt.Errorf(e.Translate(trans))
		errs = append(errs, translatedErr)
	}
	return errs
}

// handles connection to postgresql database
func databaseHandler() {
	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to the database: "+err.Error(), http.StatusInternalServerError)

	}
	defer db.Close() // Ensure database connection is closed

	// Test the connection to the database
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	} else {
		log.Println("Successfully Connected to " + dbname)
	}
}

func getFormData(w http.ResponseWriter, r *http.Request) (string, string, string, User) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

	}

	validate := validator.New()
	english := en.New()
	uni := ut.New(english, english)
	trans, _ := uni.GetTranslator("en")
	_ = enTranslations.RegisterDefaultTranslations(validate, trans)

	// Register custom validation function
	_ = validate.RegisterValidation("customPassword", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()
		if len(password) < 8 {
			return false
		}

		// Check for at least one uppercase letter, one lowercase letter, one digit, and one special character
		var (
			hasUpper    = false
			hasLower    = false
			hasDigit    = false
			hasSpecial  = false
			specialChar = regexp.MustCompile(`[[:^alnum:]]`) // matches non-alphanumeric characters
		)

		for _, char := range password {
			switch {
			case 'A' <= char && char <= 'Z':
				hasUpper = true
			case 'a' <= char && char <= 'z':
				hasLower = true
			case '0' <= char && char <= '9':
				hasDigit = true
			case specialChar.MatchString(string(char)):
				hasSpecial = true
			}

			// Exit early if all conditions are met
			if hasUpper && hasLower && hasDigit && hasSpecial {
				return true
			}
		}

		return false
	})
	username := user.Username
	email := user.Email
	password := user.Password

	if err := validate.Struct(user); err != nil {
		// Validation failed, handle the error
		errors := translateError(err, trans)
		http.Error(w, fmt.Sprintf("Validation error: %s", errors), http.StatusBadRequest)
		return "", "", "", user
	}

	if username == "" || email == "" || password == "" {
		log.Printf("Missing form data: username=%s, email=%s, password=%s", username, email, password)
		http.Error(w, "Missing form data", http.StatusBadRequest)
		return "", "", "", user
	}

	return username, email, password, user
}

// handles creating user
func createUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method != "POST" {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username, email, password, user := getFormData(w, r)
	if username == "" || email == "" || password == "" {
		// Error already handled in getFormData
		return
	}
	passwordhash, _ := passwordhashing.HashPassword(password)

	databaseHandler()

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		http.Error(w, "Failed to open database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	exists, err := usernameAndEmailExists(db, email, username)
	if err != nil {
		log.Printf("Failed to check username existence: %v", err)
		http.Error(w, "Failed to check username existence", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}
	insertUserDB(db, username, email, passwordhash, w)

	json.NewEncoder(w).Encode(user)
	// Create an instance of the Form struct
}

func usernameAndEmailExists(db *sql.DB, email, username string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2", username, email).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func insertUserDB(db *sql.DB, username, email, passwordhash string, w http.ResponseWriter) {

	if username != "" && email != "" && passwordhash != "" {
		query := "INSERT INTO users(username, email, password_hash) VALUES ($1, $2, $3)"
		if _, err := db.Exec(query, username, email, passwordhash); err != nil {
			http.Error(w, "Query to database failed: "+err.Error(), http.StatusInternalServerError)
			log.Printf("An error occurred while executing query: %v", err)
			return
		}

		log.Println("Data successfully inserted")
		log.Println("User creation successful")

	} else {
		log.Println("Username, email, and password hash must not be empty")
	}
}

func loginUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	queryUsername, _, inputPassword, user := getFormData(w, r)
	if inputPassword == "" {
		return // Error already logged and response sent in getFormData
	}

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Retrieve user data from database

	_, _, storedPasswordHash, _ := retrieveUserDB(db, queryUsername)
	if storedPasswordHash == "" {
		log.Printf("Failed to retrieve user data for username: %s", queryUsername)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	match := passwordhashing.VerifyPassword(inputPassword, storedPasswordHash)
	if !match {
		log.Printf("Login failed for username: %s. Passwords do not match.", queryUsername)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Login successful
	log.Printf("Login successful for username: %s", queryUsername)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
	// Optionally, respond with more data (e.g., user information)
	json.NewEncoder(w).Encode(user.Username)
}

func retrieveUserDB(db *sql.DB, query_username string) (string, string, string, error) {
	var getusername string
	var getemail string
	var getpassword string

	query := "SELECT username, email, password_hash FROM users WHERE username = $1"
	err := db.QueryRow(query, query_username).Scan(&getusername, &getemail, &getpassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", "", fmt.Errorf("user not found")
		}
		return "", "", "", fmt.Errorf("error retrieving user data: %v", err)
	}

	return getusername, getemail, getpassword, nil
}
func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintf(w, "Welcome")
}

// Handles endpoints
func routes(r *httprouter.Router) {
	r.GET("/", Index)
	r.GET("/health", handleHealth)
	r.POST("/create-user", createUser)
	r.POST("/login-user", loginUser)
}

// checks if server is running
func handleHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	response := []byte("Server is up and running!")

	_, err := w.Write(response)

	if err != nil {
		fmt.Println(err)
	}
}

func startServer() *http.Server {
	router := httprouter.New()
	routes(router)

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	return server
}

func main() {

	main_server := startServer()

	log.Printf("Server is starting at port %s", main_server.Addr)
	go func() {
		if err := main_server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server ListenAndServe: %v", err)
		}
	}()
	gracefulShutdown(main_server)
}
