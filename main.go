package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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

func getConfig(key string) string {
	// load .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Print("Error loading .env file")
	}
	return os.Getenv(key)
}

var db *gorm.DB

func connectDB() {
	var err error
	p := getConfig("DB_PORT")
	port, err := strconv.ParseUint(p, 10, 32)
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable", getConfig("DB_HOST"), port, getConfig("DB_USER"), getConfig("DB_NAME"))

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		fmt.Printf("%s\n", dsn)
		panic("failed to connect database")
	}

	fmt.Println("Connection Opened to Database")
	db.AutoMigrate(&Recording{}, &Utterance{}, &User{})
	fmt.Println("Database Migrated")
}

func showIndexPage(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")

	if userID != nil {
		recordings := getAllRecordingsByUserID(userID.(uint))
		render(c, gin.H{
			"payload": recordings}, "index.html")
	} else {
		showLoginPage(c)
	}
}

var store cookie.Store

func showRecordingUploadPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{}, "upload-recording.html")
}

func getRecording(c *gin.Context) {
	// Check if the recording ID is valid
	if recordingID, err := strconv.ParseUint(c.Param("recording_id"), 10, 32); err == nil {
		// Check if the recording exists
		if recording, err := getRecordingByID(uint(recordingID)); err == nil {
			render(c, gin.H{"payload": recording}, "recording.html")

		} else {
			// If the recording is not found, abort with an error
			c.AbortWithError(http.StatusNotFound, err)
		}

	} else {
		// If an invalid recording ID is specified in the URL, abort with an error
		c.AbortWithStatus(http.StatusNotFound)
	}
}

func uploadRecording(c *gin.Context) {
	// Obtain the POSTed title and language values
	title := c.PostForm("title")
	language := c.PostForm("language")

	file, err := c.FormFile("content")
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
	}

	filename := filepath.Base(file.Filename)
	if title == "" {
		title = filename
	}

	session := sessions.Default(c)
	userID := session.Get("user_id")

	r, err := createRecording(userID.(uint), title, filename, language)

	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
	}

	localFilename := fmt.Sprintf("%s/%07d.dat", getConfig("DATA_DIR"), r.ID)

	if err := c.SaveUploadedFile(file, localFilename); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
	}

	if err := updateRecordingStatus(r, 1); err == nil {
		render(c, gin.H{
			"payload": r}, "submission-successful.html")
	} else {
		c.AbortWithError(http.StatusBadRequest, err)
	}
}

func showLoginPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title": "Login",
	}, "login.html")
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func performLogin(c *gin.Context) {
	// Obtain the POSTed email and password values
	email := strings.ToLower(c.PostForm("email"))
	password := c.PostForm("password")
	user := findUser(email, password)

	// Check if the email/password combination is valid
	if user != nil {
		if user.Status > 0 {
			// If the email/password is valid, save the user to session
			session := sessions.Default(c)
			session.Set("user_id", user.ID)
			session.Save()

			// and mark this in context
			c.Set("is_logged_in", true)

			render(c, gin.H{
				"title": "Successful Login"}, "login-successful.html")
		} else {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{
				"ErrorTitle":   "Login Failed",
				"ErrorMessage": "Please check your mailbox and click the confirmation link"})
		}
	} else {
		// If the email/password combination is invalid,
		// show the error message on the login page
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"ErrorTitle":   "Login Failed",
			"ErrorMessage": "Invalid credentials provided"})
	}
}

func logout(c *gin.Context) {
	// Clear the cookie
	session := sessions.Default(c)
	session.Delete("user_id")
	session.Save()

	// Redirect to the home page
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

func showRegistrationPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title": "Register"}, "register.html")
}

func register(c *gin.Context) {
	// Obtain the POSTed email and password values
	email := strings.ToLower(c.PostForm("email"))
	password := c.PostForm("password")

	if _, err := registerNewUser(email, password); err == nil {
		render(c, gin.H{}, "register-successful.html")
	} else {
		// If the email/password combination is invalid,
		// show the error message on the login page
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"ErrorTitle":   "Registration Failed",
			"ErrorMessage": err.Error()})

	}
}

// Render one of HTML, JSON or CSV based on the 'Accept' header of the request
// If the header doesn't specify this, HTML is rendered, provided that
// the template name is present
func render(c *gin.Context, data gin.H, templateName string) {
	loggedInInterface, _ := c.Get("is_logged_in")
	data["is_logged_in"] = loggedInInterface.(bool)

	switch c.Request.Header.Get("Accept") {
	case "application/json":
		// Respond with JSON
		c.JSON(http.StatusOK, data["payload"])
	case "application/xml":
		// Respond with XML
		c.XML(http.StatusOK, data["payload"])
	default:
		// Respond with HTML
		c.HTML(http.StatusOK, templateName, data)
	}
}

// This middleware ensures that a request will be aborted with an error
// if the user is not logged in
func ensureLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if !loggedIn {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

// This middleware ensures that a request will be aborted with an error
// if the user is already logged in
func ensureNotLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's no error or if the token is not empty
		// the user is already logged in
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if loggedIn {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

// This middleware sets whether the user is logged in or not
func setUserStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if userID := session.Get("user_id"); userID != nil {
			c.Set("is_logged_in", true)
		} else {
			c.Set("is_logged_in", false)
		}
	}
}

// Return a list of all recordings
func getAllRecordingsByUserID(userID uint) []Recording {
	var recordings []Recording
	db.Where(&Recording{UserID: userID}).Not("status = 0").Find(&recordings)
	return recordings
}

// Fetch a recording based on the ID supplied
func getRecordingByID(id uint) (*Recording, error) {
	var recording Recording
	db.First(&recording, id)

	if recording.Title == "" {
		return nil, errors.New("Recording not found")
	} else {
		return &recording, nil
	}
}

// Create a new recording record
func createRecording(userID uint, title, filename, language string) (*Recording, error) {
	r := Recording{UserID: userID, Title: title, Filename: filename, Language: language}
	err := db.Create(&r).Error
	return &r, err
}

// Update status of the recording record
func updateRecordingStatus(r *Recording, status uint) error {
	var recording Recording

	db.First(&recording, r.ID)
	recording.Status = status
	err := db.Save(&recording).Error

	return err
}

// Check if the username and password combination is valid
func findUser(email, password string) *User {
	var user User
	db.Where(&User{Email: email}).First(&user)

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil
	} else {
		return &user
	}
}

// Register a new user with the given username and password
func registerNewUser(email, password string) (*User, error) {
	user := User{Email: email, Password: password}

	hash, err := hashPassword(user.Password)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Could not hash password: %v", err))
	}

	user.Password = hash
	if err := db.Create(&user).Error; err != nil {
		return nil, errors.New(fmt.Sprintf("Could not create user: %v", err))
	}

	if err := sendConfirmation(user.ID); err != nil {
		return nil, errors.New(fmt.Sprintf("Could not send confirmation link: %v", err))
	}

	return &user, nil
}

func sendConfirmation(userID uint) error {
	var user User

	token, err := uuid.NewRandom()

	if err != nil {
		return err
	}

	db.First(&user, userID)
	user.Token = token.String()
	err = db.Save(&user).Error

	if err != nil {
		return err
	}

	confirmationLink := fmt.Sprintf("%s/u/confirm/%s", getConfig("URL_BASE"), token)
	messageBody := fmt.Sprintf("To confirm this email address, go to:<br/>\n<a href=\"%s\">%s</a>", confirmationLink, confirmationLink)

	m := gomail.NewMessage()
	m.SetHeader("From", "IMS-Speech <pavel.denisov@ims.uni-stuttgart.de>")
	m.SetHeader("Sender", "st153249@stud.uni-stuttgart.de")
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "[IMS-Speech] Email Confirmation")
	m.SetBody("text/html", messageBody)

	smtpPort, _ := strconv.ParseInt(getConfig("SMTP_PORT"), 10, 32)

	d := gomail.NewDialer(getConfig("SMTP_HOST"), int(smtpPort), getConfig("SMTP_USER"), getConfig("SMTP_PASSWORD"))

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

func performConfirmation(c *gin.Context) {
	token := c.Param("token")

	if _, err := uuid.Parse(token); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	var user User
	db.Where(&User{Token: token}).First(&user)

	if user.Email == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("Invalid confirmation link"))
		return
	}

	user.Token = ""
	user.Status = 1
	if err := db.Save(&user).Error; err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	render(c, gin.H{}, "confirmation.html")
}

func initializeRoutes(app *gin.Engine) {

	// Use the setUserStatus middleware for every route to set a flag
	// indicating whether the request was from an authenticated user or not
	app.Use(setUserStatus())

	// Handle the index route
	app.GET("/", showIndexPage)

	// Group user related routes together
	userRoutes := app.Group("/u")
	{
		// Handle the GET requests at /u/login
		// Show the login page
		// Ensure that the user is not logged in by using the middleware
		userRoutes.GET("/login", ensureNotLoggedIn(), showLoginPage)

		// Handle POST requests at /u/login
		// Ensure that the user is not logged in by using the middleware
		userRoutes.POST("/login", ensureNotLoggedIn(), performLogin)

		// Handle GET requests at /u/logout
		// Ensure that the user is logged in by using the middleware
		userRoutes.GET("/logout", ensureLoggedIn(), logout)

		// Handle the GET requests at /u/register
		// Show the registration page
		// Ensure that the user is not logged in by using the middleware
		userRoutes.GET("/register", ensureNotLoggedIn(), showRegistrationPage)

		// Handle POST requests at /u/register
		// Ensure that the user is not logged in by using the middleware
		userRoutes.POST("/register", ensureNotLoggedIn(), register)

		// Handle GET requests at /u/confirm/some_token
		userRoutes.GET("/confirm/:token", ensureNotLoggedIn(), performConfirmation)
	}

	// Group recording related routes together
	recordingRoutes := app.Group("/recording")
	{
		// Handle GET requests at /recording/view/some_recording_id
		recordingRoutes.GET("/view/:recording_id", getRecording)

		// Handle the GET requests at /recording/upload
		// Show the recording upload page
		// Ensure that the user is logged in by using the middleware
		recordingRoutes.GET("/upload", ensureLoggedIn(), showRecordingUploadPage)

		// Handle POST requests at /recording/upload
		// Ensure that the user is logged in by using the middleware
		recordingRoutes.POST("/upload", ensureLoggedIn(), uploadRecording)
	}
}

func main() {
	// Set Gin to production mode
	gin.SetMode(gin.ReleaseMode)

	// Connect to the database
	connectDB()

	// Set the router as the default one provided by Gin
	app := gin.Default()

	// Process the templates at the start so that they don't have to be loaded
	// from the disk again. This makes serving HTML pages very fast.
	app.LoadHTMLGlob("templates/*")

	// Enable cookie session
	store = cookie.NewStore([]byte(getConfig("SESSION_KEY")))
	app.Use(sessions.Sessions("ims-speech-session", store))

	// Initialize the routes
	initializeRoutes(app)

	// Start serving the application
	app.Run()
}
