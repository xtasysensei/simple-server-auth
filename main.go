package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"simple-server-auth/passwordhashing"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
)

type User struct {
	Username     string `db:"username"`
	Email        string `db:"email"`
	PasswordHash string `db:"password_hash"`
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

func getFormData(w http.ResponseWriter, r *http.Request) (string, string, string) {
	err := r.ParseForm()
	if err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return "", "", ""
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if username == "" || email == "" || password == "" {
		log.Printf("Missing form data: username=%s, email=%s, password=%s", username, email, password)
		http.Error(w, "Missing form data", http.StatusBadRequest)
		return "", "", ""
	}

	return username, email, password
}

// handles creating user
func createUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method != "POST" {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username, email, password := getFormData(w, r)
	passwordhash, _ := passwordhashing.HashPassword(password)

	databaseHandler()

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		http.Error(w, "Failed to open database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()
	insertUserDB(db, username, email, passwordhash, w)
	// Create an instance of the Form struct
}

func insertUserDB(db *sql.DB, username, email, passwordhash string, w http.ResponseWriter) {
	userInfo := &User{
		Username:     username,
		Email:        email,
		PasswordHash: passwordhash,
	}

	if userInfo.Username != "" && userInfo.Email != "" && userInfo.PasswordHash != "" {
		query := "INSERT INTO users(username, email, password_hash) VALUES ($1, $2, $3)"
		if _, err := db.Exec(query, userInfo.Username, userInfo.Email, userInfo.PasswordHash); err != nil {
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
	_, _, inputPassword := getFormData(w, r)
	if inputPassword == "" {
		// Error already logged and response sent in getFormData
		return
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, _, storedPasswordHash := retrieveUserDB(db)
	if storedPasswordHash == "" {
		log.Println("Failed to retrieve user data from the database.")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	match := passwordhashing.VerifyPassword(inputPassword, storedPasswordHash)
	if !match {
		log.Println("Login failed. Passwords do not match.")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	log.Println("Login successful.")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

func retrieveUserDB(db *sql.DB) (string, string, string) {
	var getusername string
	var getemail string
	var getpassword string

	query := "SELECT username, email, password_hash FROM users WHERE id = 10"
	if err := db.QueryRow(query).Scan(&getusername, &getemail, &getpassword); err != nil {
		//http.Error(w, "Query to database failed: "+err.Error(), http.StatusInternalServerError)
		log.Printf("An error occurred while executing query: %v", err)
	}
	return getusername, getemail, getpassword

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
