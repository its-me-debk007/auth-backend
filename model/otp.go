package model

import "time"

type Otp struct {
	Email     string `gorm:"primary_key"`
	Otp       int
	CreatedAt time.Time
}
