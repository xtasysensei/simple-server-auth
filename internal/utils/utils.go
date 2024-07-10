package utils

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"simple-server-auth/internal/models"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslations "github.com/go-playground/validator/v10/translations/en"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
)

var Connstr, dbname string

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	host := os.Getenv("POSTGRES_SERVER")
	dbname = os.Getenv("POSTGRES_DB")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")

	Connstr = fmt.Sprintf("user=%s dbname=%s password=%s host=%s sslmode=disable", user, dbname, password, host)
}

func TranslateError(err error, trans ut.Translator) (errs []error) {
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
func DatabaseHandler() {
	db, err := sqlx.Connect("postgres", Connstr)
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

func UsernameAndEmailExists(db *sql.DB, email, username string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2", username, email).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func InsertUserDB(db *sql.DB, username, email, passwordhash string, w http.ResponseWriter) {

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

func RetrieveUserDB(db *sql.DB, query_username string) (string, string, string, error) {
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

func GetFormData(w http.ResponseWriter, r *http.Request) (string, string, string, models.User) {
	var user models.User
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
		errors := TranslateError(err, trans)
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

// checks if server is running
func HandleHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	response := []byte("Server is up and running!")

	_, err := w.Write(response)

	if err != nil {
		fmt.Println(err)
	}
}
func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintf(w, "Welcome")
}
