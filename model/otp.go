package model

import (
	"time"
)

type Otp struct {
	Email            string `gorm:"primary_key"`
	ResetPasswordOtp int64
	SignUpOtp        int64
	CreatedAt        time.Time
}
