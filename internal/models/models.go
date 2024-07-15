package models

type User struct {
	Username string `json:"username" validate:"required,min=5,max=20,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=5,customPassword"`
}
type Option struct {
	Text  string `json:"text" validate:"max=100"`
	Votes int    `json:"votes"`
}

type Poll struct {
	Question string   `json:"question" validate:"required,min=10,max=200"`
	Options  []Option `json:"options"`
}
