package handlers

import (
	"encoding/json"
	"fmt"
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
	db := utils.DBConnection(w)

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
	w.Write([]byte("Login successful for "))
	// Optionally, respond with more data (e.g., user information)
	json.NewEncoder(w).Encode(user.Username)
}

// handles creating user
func CreateUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	username, email, password, user := utils.GetFormData(w, r)
	if username == "" || email == "" || password == "" {
		// Error already handled in getFormData
		return
	}
	passwordhash, _ := passwordhashing.HashPassword(password)

	utils.DatabaseHandler()

	db := utils.DBConnection(w)

	exists, err := utils.UsernameAndEmailExists(db, email, username)
	if err != nil {
		log.Printf("Failed to check username and email existence: %v", err)
		http.Error(w, "Failed to check username and email existence", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}
	utils.InsertUserDB(db, username, email, passwordhash, w)

	response := []byte("Sucessfully registered " + user.Username)

	if _, err := w.Write(response); err != nil {
		fmt.Println(err)
	}
	// Create an instance of the Form struct
}

/*func DeleteUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params)  {

}*/

func DeleteUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	db := utils.DBConnection(w)
	username, _, _, _ := utils.GetFormData(w, r)

	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		log.Println("Username is empty in form data")
		return
	}

	// Delete user from database
	err := utils.DeleteUserDB(db, username, w)
	if err != nil {
		log.Printf("Failed to delete user: %v", err)
		// Error response already handled in DeleteUserDB
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User successfully deleted"))
	log.Printf("User %s successfully deleted", username)

}
