package models

type User struct {
	Username string `json:"username" validate:"required,min=5,max=20,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=5,customPassword"`
}
