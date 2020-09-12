package model

import "gorm.io/gorm"

// User struct
type User struct {
	gorm.Model
	Email    string `gorm:"unique_index;not null" json:"email" form:"email"`
	Password string `gorm:"not null" json:"password" form: "password"`
	Names    string `json:"names"`
	Status   uint   `gorm:"not null;default:0" json:"status"`
	Token    string `json:"token"`
}

// Recording struct
type Recording struct {
	gorm.Model
	UserID   uint   `gorm:"not null" json:"user_id"`
	Title    string `gorm:"not null" json:"name"`
	Filename string `gorm:"not null" json:"file"`
	Language string `gorm:"not null" json:"language"`
	Status   uint   `gorm:"not null;default:0" json:"status"`
}

// Utterance struct
type Utterance struct {
	gorm.Model
	RecordingID uint    `gorm:"not null" json:"recording_id"`
	Start       float32 `gorm:"not null" json:"start"`
	End         float32 `gorm:"not null" json:"end"`
	Text        string  `json:"text"`
}
