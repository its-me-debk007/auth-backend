package model

import "time"

type Otp struct {
	Email            string `gorm:"primary_key"`
	ResetPasswordOtp int
	SignUpOtp        int
	CreatedAt        time.Time
}
