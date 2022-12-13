package controller

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/its-me-debk007/auth-backend/database"
	"github.com/its-me-debk007/auth-backend/model"
	"github.com/its-me-debk007/auth-backend/util"
	"golang.org/x/crypto/bcrypt"
)

func Login(c *gin.Context) {
	input := new(struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	})

	if err := c.ShouldBindJSON(input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	input.Email = strings.TrimSpace(input.Email)
	input.Email = strings.ToLower(input.Email)
	input.Password = strings.TrimSpace(input.Password)

	var user model.User

	if db := database.DB.First(&user, "email = ?", input.Email); db.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"no account found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"invalid password"})
		return
	}

	if !user.IsVerified {
		c.AbortWithStatusJSON(http.StatusUnauthorized, model.Message{"user not verified"})
		return
	}

	accessToken, err := util.GenerateToken(user.Email, "ACCESS", 24*7)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, model.Message{err.Error()})
		return
	}

	refreshToken, err := util.GenerateToken(user.Email, "REFRESH", 1)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, model.Message{err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func Signup(c *gin.Context) {
	input := model.User{}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	input.Email = strings.TrimSpace(input.Email)
	input.Email = strings.ToLower(input.Email)
	input.Name = strings.TrimSpace(input.Name)
	input.Password = strings.TrimSpace(input.Password)

	if validation := util.IsValidPassword(input.Password); validation != "ok" {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{validation})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), 10)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, model.Message{err.Error()})
		return
	}

	input.Password = string(hashedPassword)

	if err := database.DB.Create(&input); err.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"email already registered"})
		return
	}

	bigIntOtp, _ := rand.Int(rand.Reader, big.NewInt(900000))
	bigIntOtp.Add(bigIntOtp, big.NewInt(100000))

	otp := bigIntOtp.Int64()

	go util.SendEmail(input.Email, otp)

	otpStruct := model.Otp{
		Email:     input.Email,
		SignUpOtp: otp,
		CreatedAt: time.Now(),
	}

	if db := database.DB.Save(&otpStruct); db.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, model.Message{db.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, model.Message{"successfully signed up and sent otp"})
}

func VerifyOtp(c *gin.Context) {
	input := new(struct {
		Email string `json:"email"    binding:"required,email"`
		Otp   int    `json:"otp"    binding:"required"`
	})

	if err := c.ShouldBindJSON(input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{err.Error()})
		return
	}

	input.Email = strings.TrimSpace(input.Email)
	input.Email = strings.ToLower(input.Email)

	otpStruct := model.Otp{}

	if db := database.DB.First(&otpStruct, "email = ?", input.Email); db.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"otp not generated for this email"})
		return
	}

	if timeDiff := time.Since(otpStruct.CreatedAt); timeDiff > (time.Minute * 5) {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"otp expired"})
		return
	}

	if otpStruct.SignUpOtp != int64(input.Otp) {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"otp incorrect"})
		return
	}

	database.DB.Model(&model.User{}).Where("email = ?", input.Email).Update("is_verified", true)

	c.JSON(http.StatusOK, model.Message{"otp verified successfully"})
}

func ResetPassword(c *gin.Context) {
	input := new(struct {
		Otp      int    `json:"otp"    binding:"required"`
		Email    string `json:"email"    binding:"required,email"`
		Password string `json:"new_password"    binding:"required"`
	})

	if err := c.ShouldBindJSON(input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	input.Email = strings.TrimSpace(input.Email)
	input.Email = strings.ToLower(input.Email)
	input.Password = strings.TrimSpace(input.Password)

	otpStruct := model.Otp{}

	database.DB.First(&otpStruct, "email = ?", input.Email)

	if otpStruct.Email == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"otp not generated for this email"})
		return
	}

	if timeDiff := time.Since(otpStruct.CreatedAt); timeDiff > (time.Minute * 5) {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"otp expired"})
		return
	}

	if otpStruct.ResetPasswordOtp != int64(input.Otp) {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"otp incorrect"})
		return
	}

	if validation := util.IsValidPassword(input.Password); validation != "ok" {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{validation})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), 10)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, model.Message{err.Error()})
		return
	}

	input.Password = string(hashedPassword)

	database.DB.Model(&model.User{}).Where("email = ?", input.Email).Update("password", input.Password)

	c.JSON(http.StatusOK, model.Message{"successfully changed password"})
}

func SendOtp(c *gin.Context) {
	input := new(struct {
		Email     string `json:"email"    binding:"required,email"`
		ForSignUp bool   `json:"for_signup"`
	})

	if err := c.ShouldBindJSON(input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{err.Error()})
		return
	}

	input.Email = strings.TrimSpace(input.Email)
	input.Email = strings.ToLower(input.Email)

	var user model.User

	if db := database.DB.First(&user, "email = ?", input.Email); db.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"user not registered"})
		return
	}

	if !user.IsVerified && !input.ForSignUp {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"user not verified for changing password"})
		return
	}

	if user.IsVerified && input.ForSignUp {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.Message{"user already signed up"})
		return
	}

	bigIntOtp, _ := rand.Int(rand.Reader, big.NewInt(900000))
	bigIntOtp.Add(bigIntOtp, big.NewInt(100000))

	otp := bigIntOtp.Int64()

	go util.SendEmail(input.Email, otp)

	var otpStruct model.Otp

	if input.ForSignUp {
		otpStruct = model.Otp{
			Email:     input.Email,
			CreatedAt: time.Now(),
			SignUpOtp: otp,
		}

	} else {
		otpStruct = model.Otp{
			Email:            input.Email,
			CreatedAt:        time.Now(),
			ResetPasswordOtp: otp,
			SignUpOtp:        0,
		}
	}

	if db := database.DB.Save(&otpStruct); db.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, model.Message{db.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, model.Message{"otp sent successfully"})
}
