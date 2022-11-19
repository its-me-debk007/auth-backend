package util

import (
	"bytes"
	"errors"
	"html/template"
	"log"
	"net/smtp"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/its-me-debk007/auth-backend/database"
	"github.com/its-me-debk007/auth-backend/model"
)

const (
	SMTP_HOST = "smtp.gmail.com"
	SMTP_PORT = "587"
)

func GenerateToken(username string, subject string, expirationTime time.Duration) (string, error) {
	registeredClaims := jwt.RegisteredClaims{
		Issuer:  username,
		Subject: subject,
		ExpiresAt: &jwt.NumericDate{
			Time: time.Now().Add(time.Hour * expirationTime),
		},
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, registeredClaims)

	secretKey := os.Getenv("SECRET_KEY")

	token, err := claims.SignedString([]byte(secretKey))

	if err != nil {
		return token, err
	}

	return token, nil
}

func ParseToken(tokenString string, typeShouldBeAccess bool) (string, error) {
	secretKey := os.Getenv("SECRET_KEY")

	registeredClaims := jwt.RegisteredClaims{}

	_, err := jwt.ParseWithClaims(tokenString, &registeredClaims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	var errorMsg string
	var user model.User
	db := database.DB.First(&user, "email = ?", registeredClaims.Issuer)

	switch {
	case err != nil:
		errorMsg = "invalid token"

	case typeShouldBeAccess && registeredClaims.Subject != "ACCESS":
		errorMsg = "invalid token (required type is access token)"

	case !typeShouldBeAccess && registeredClaims.Subject == "ACCESS":
		errorMsg = "invalid token (required type is refresh token)"

	case db.Error != nil:
		errorMsg = "user not signed up"

	case time.Since(registeredClaims.ExpiresAt.Time) >= 0:
		errorMsg = "token expired"
	}

	if errorMsg != "" {
		return "", errors.New(errorMsg)
	}

	return user.Name, nil
}

func IsValidPassword(password string) string {
	isDigit, isLowercase, isUppercase, isSpecialChar := 0, 0, 0, 0
	for _, ch := range password {
		switch {
		case ch >= '0' && ch <= '9':
			isDigit = 1

		case ch >= 'a' && ch <= 'z':
			isLowercase = 1

		case ch >= 'A' && ch <= 'Z':
			isUppercase = 1

		case ch == '$' || ch == '!' || ch == '@' || ch == '#' || ch == '%' || ch == '&' || ch == '^' || ch == '*' || ch == '/' || ch == '\\':
			isSpecialChar = 1
		}
	}

	switch {
	case len(password) < 8:
		return "password must be at least 8 characters long"

	case isDigit == 0:
		return "password must contain at-least one numeric digit"

	case isLowercase == 0:
		return "password must contain at-least one lowercase alphabet"

	case isUppercase == 0:
		return "password must contain at-least one uppercase alphabet"

	case isSpecialChar == 0:
		return "password must contain at-least one special character"

	default:
		return "ok"
	}
}

func SendEmail(receiverEmail string, otp int64) {
	log.Printf("OTP for %s:- %d\n", receiverEmail, otp)

	senderEmail := os.Getenv("SENDER_EMAIL")
	senderPassword := os.Getenv("SENDER_PASSWORD")
	subject := "Subject: Verify your account\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	auth := smtp.PlainAuth("", senderEmail, senderPassword, SMTP_HOST)

	var t *template.Template
	var err error

	t, err = t.ParseFiles("template/template.html")
	if err != nil {
		log.Fatalln("HTML PARSING ERROR", err.Error())
	}

	buffer := new(bytes.Buffer)

	t.Execute(buffer, gin.H{
		"otp": otp,
	})

	msg := []byte(subject + mime + buffer.String())

	if err = smtp.SendMail(SMTP_HOST+":"+SMTP_PORT, auth, senderEmail, []string{receiverEmail}, msg); err != nil {
		log.Fatalln("SEND EMAIL ERROR", err.Error())
	}

	log.Printf("OTP SENT TO %s", receiverEmail)
}
