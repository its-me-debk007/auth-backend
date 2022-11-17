package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/its-me-debk007/auth-backend/database"
	"github.com/its-me-debk007/auth-backend/route"
)

func main() {
	database.ConnectDatabase()

	app := gin.Default()

	app.Use(gin.Recovery())

	app.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowCredentials: true,
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPatch},
		AllowHeaders:     []string{"Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
	}))

	route.SetupRoutes(app)

	port := os.Getenv("PORT")

	if err := app.Run(":" + port); err != nil {
		log.Fatal("App listen error:-\n" + err.Error())
	}
}
