package route

import (
	"github.com/gin-gonic/gin"
	"github.com/its-me-debk007/auth-backend/controller"
)

func SetupRoutes(app *gin.Engine) {
	apiGroup := app.Group("/api/v1/auth")
	{
		apiGroup.POST("/login", controller.Login)
		apiGroup.POST("/signup", controller.Signup)
		apiGroup.POST("/send-otp", controller.SendOtp)
		apiGroup.POST("/verify", controller.VerifyOtp)
		apiGroup.POST("/reset", controller.ResetPassword)
	}

	app.GET("/api/v1", controller.Home)
}
