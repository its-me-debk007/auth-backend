package controller

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/its-me-debk007/auth-backend/model"
	"github.com/its-me-debk007/auth-backend/util"
)

func Home(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if header == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, model.Message{"no token provided"})
		return
	}

	token := header[7:]

	name, err := util.ParseToken(token, true)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, model.Message{err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.Message{fmt.Sprintf("Hello, %s!", name)})
}
