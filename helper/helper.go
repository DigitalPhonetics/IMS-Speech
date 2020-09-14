package helper

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"simple-web-asr/model"
)

func GetConfig(key string) string {
	// load .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Print("Error loading .env file")
	}
	return os.Getenv(key)
}

var DB *gorm.DB

func ConnectDB() {
	var err error
	dsn := fmt.Sprintf("user=%s dbname=%s", GetConfig("DB_USER"), GetConfig("DB_NAME"))

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		fmt.Printf("%s\n", dsn)
		panic("failed to connect database")
	}

	fmt.Println("Connection Opened to Database")
	DB.AutoMigrate(&model.Recording{}, &model.Utterance{}, &model.User{})
	fmt.Println("Database Migrated")
}

func SendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "IMS-Speech <pavel.denisov@ims.uni-stuttgart.de>")
	m.SetHeader("Sender", "st153249@stud.uni-stuttgart.de")
	m.SetHeader("To", to)
	m.SetHeader("Subject", fmt.Sprintf("[IMS-Speech] %v", subject))
	m.SetBody("text/html", body)

	smtpPort, _ := strconv.ParseInt(GetConfig("SMTP_PORT"), 10, 32)

	d := gomail.NewDialer(GetConfig("SMTP_HOST"), int(smtpPort), GetConfig("SMTP_USER"), GetConfig("SMTP_PASSWORD"))

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

func RecordingFilename(recordingID uint) string {
	return fmt.Sprintf("%s/%07d.dat", GetConfig("DATA_DIR"), recordingID)
}
