package routes

import (
	"simple-server-auth/internal/handlers"
	"simple-server-auth/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// Handles endpoints
func Routes(r *httprouter.Router) {
	r.GET("/", utils.Index)
	r.GET("/health", utils.HandleHealth)
	r.POST("/create-user", handlers.CreateUser)
	r.POST("/login-user", handlers.LoginUser)
	r.DELETE("/delete-user", handlers.DeleteUser)
}
