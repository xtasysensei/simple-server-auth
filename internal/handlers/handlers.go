package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"simple-server-auth/internal/utils"
	"simple-server-auth/passwordhashing"

	"github.com/julienschmidt/httprouter"
)

func LoginUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	queryUsername, _, inputPassword, user := utils.GetFormData(w, r)
	if inputPassword == "" {
		return // Error already logged and response sent in getFormData
	}

	// Open database connection
	db, err := sql.Open("postgres", utils.Connstr)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Retrieve user data from database

	_, _, storedPasswordHash, _ := utils.RetrieveUserDB(db, queryUsername)
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

// handles creating user
func CreateUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if r.Method != "POST" {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username, email, password, user := utils.GetFormData(w, r)
	if username == "" || email == "" || password == "" {
		// Error already handled in getFormData
		return
	}
	passwordhash, _ := passwordhashing.HashPassword(password)

	utils.DatabaseHandler()

	db, err := sql.Open("postgres", utils.Connstr)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		http.Error(w, "Failed to open database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	exists, err := utils.UsernameAndEmailExists(db, email, username)
	if err != nil {
		log.Printf("Failed to check username existence: %v", err)
		http.Error(w, "Failed to check username existence", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}
	utils.InsertUserDB(db, username, email, passwordhash, w)

	json.NewEncoder(w).Encode(user)
	// Create an instance of the Form struct
}
