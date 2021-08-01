package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/asticode/go-astisub"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"simple-web-asr/internal/helper"
	"simple-web-asr/internal/model"
)

var db *gorm.DB

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

func formatDuration(secondsFloat float32) string {
	d := time.Duration(int(secondsFloat*1000)) * time.Millisecond
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func showRecordingUploadPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{}, "upload-recording.html")
}

func getRecording(c *gin.Context) (*model.Recording, []model.Utterance) {
	// Check if the recording ID is valid
	if recordingID, err := strconv.ParseUint(c.Param("recording_id"), 10, 32); err == nil {
		// Check if the recording exists
		if recording, err := getRecordingByID(uint(recordingID)); err == nil {
			session := sessions.Default(c)
			userID := session.Get("user_id")

			// Check if the recording is owned by the current user
			if userID.(uint) == recording.UserID {
				var utterances []model.Utterance

				if recording.Status == 3 {
					utterances = getAllUtterancesByRecordingID(recording.ID)
				}

				return recording, utterances
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
		} else {
			// If the recording is not found, abort with an error
			c.AbortWithError(http.StatusNotFound, err)
		}

	} else {
		// If an invalid recording ID is specified in the URL, abort with an error
		c.AbortWithStatus(http.StatusNotFound)
	}

	return nil, nil
}

func getRecordingHTML(c *gin.Context) {
	recording, utterances := getRecording(c)
	render(c, gin.H{"recording": recording, "utterances": utterances}, "recording.html")
}

func getRecordingSubtitles(c *gin.Context) (*astisub.Subtitles, string) {
	recording, utterances := getRecording(c)

	subtitles := astisub.NewSubtitles()

	for u := range utterances {
		item := &astisub.Item{}

		item.StartAt = time.Duration(int(utterances[u].Start*1000)) * time.Millisecond
		item.EndAt = time.Duration(int(utterances[u].End*1000)) * time.Millisecond
		item.Lines = append(item.Lines, astisub.Line{Items: []astisub.LineItem{{Text: utterances[u].Text}}})

		subtitles.Items = append(subtitles.Items, item)
	}

	return subtitles, recording.Filename
}

func getRecordingSRT(c *gin.Context) {
	subtitles, filename := getRecordingSubtitles(c)
	buf := &bytes.Buffer{}

	subtitles.WriteToSRT(buf)

	subtitlesFilename := strings.TrimSuffix(filename, filepath.Ext(filename)) + ".srt"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": subtitlesFilename}))
	c.Data(http.StatusOK, "text/srt", buf.Bytes())
}

func getRecordingTTML(c *gin.Context) {
	subtitles, filename := getRecordingSubtitles(c)
	buf := &bytes.Buffer{}

	subtitles.WriteToTTML(buf)

	subtitlesFilename := strings.TrimSuffix(filename, filepath.Ext(filename)) + ".ttml"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": subtitlesFilename}))
	c.Data(http.StatusOK, "text/xml", buf.Bytes())
}

func getRecordingWebVTT(c *gin.Context) {
	subtitles, filename := getRecordingSubtitles(c)
	buf := &bytes.Buffer{}

	subtitles.WriteToWebVTT(buf)

	subtitlesFilename := strings.TrimSuffix(filename, filepath.Ext(filename)) + ".vtt"

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": subtitlesFilename}))
	c.Data(http.StatusOK, "text/vtt", buf.Bytes())
}

func getRecordingOTR(c *gin.Context) {
	recording, utterances := getRecording(c)
	filename := recording.Filename
	otrFilename := strings.TrimSuffix(filename, filepath.Ext(filename)) + ".otr"

	var text string

	for u := range utterances {
		utt := utterances[u]

		text += "<p>"
		text += fmt.Sprintf("<span class=\"timestamp\" data-timestamp=\"%f\">%s</span>", utt.Start, formatDuration(utt.Start))
		text += " " + html.EscapeString(utt.Text) + " "
		text += fmt.Sprintf("<span class=\"timestamp\" data-timestamp=\"%f\">%s</span>", utt.End, formatDuration(utt.End))
		text += "<br /></p>"
	}

	otr := gin.H{}
	otr["media"] = recording.Filename
	otr["text"] = text

	bytes, _ := json.Marshal(otr)

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": otrFilename}))
	c.Data(http.StatusOK, "text/json", bytes)
}

func deleteRecording(c *gin.Context) {
	recording, utterances := getRecording(c)

	recordingFilename := helper.RecordingFilename(recording.ID)
	os.Remove(recordingFilename)
	os.Remove(recordingFilename + ".txt")

	db.Unscoped().Delete(utterances)
	db.Unscoped().Delete(recording)

	c.Redirect(http.StatusTemporaryRedirect, "/")
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

	localFilename := helper.RecordingFilename(r.ID)

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

func showDPSPage(c *gin.Context) {
	render(c, gin.H{
		"title": "Data protection statement",
	}, "dps.html")
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

			showIndexPage(c)
		} else {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{
				"url_base":     helper.GetConfig("URL_BASE"),
				"ErrorTitle":   "Login Failed",
				"ErrorMessage": "Please check your mailbox and click the confirmation link"})
		}
	} else {
		// If the email/password combination is invalid,
		// show the error message on the login page
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"url_base":     helper.GetConfig("URL_BASE"),
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
			"url_base":     helper.GetConfig("URL_BASE"),
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

	data["url_base"] = helper.GetConfig("URL_BASE")

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
			showLoginPage(c)
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
func getAllRecordingsByUserID(userID uint) []model.Recording {
	var recordings []model.Recording
	db.Where(&model.Recording{UserID: userID}).Not("status = 0").Find(&recordings)
	return recordings
}

// Return a list of all utterances
func getAllUtterancesByRecordingID(recordingID uint) []model.Utterance {
	var utterances []model.Utterance
	db.Where(&model.Utterance{RecordingID: recordingID}).Order("start asc").Find(&utterances)
	return utterances
}

// Fetch a recording based on the ID supplied
func getRecordingByID(id uint) (*model.Recording, error) {
	var recording model.Recording
	db.First(&recording, id)

	if recording.Title == "" {
		return nil, errors.New("Recording not found")
	} else {
		return &recording, nil
	}
}

// Create a new recording record
func createRecording(userID uint, title, filename, language string) (*model.Recording, error) {
	r := model.Recording{UserID: userID, Title: title, Filename: filename, Language: language}
	err := db.Create(&r).Error
	return &r, err
}

// Update status of the recording record
func updateRecordingStatus(r *model.Recording, status uint) error {
	var recording model.Recording

	db.First(&recording, r.ID)
	recording.Status = status
	err := db.Save(&recording).Error

	return err
}

// Check if the username and password combination is valid
func findUser(email, password string) *model.User {
	var user model.User
	db.Where(&model.User{Email: email}).First(&user)

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil
	} else {
		return &user
	}
}

// Register a new user with the given username and password
func registerNewUser(email, password string) (*model.User, error) {
	user := model.User{Email: email, Password: password}

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
	var user model.User

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

	confirmationLink := fmt.Sprintf("%s/u/confirm/%s", helper.GetConfig("URL_BASE"), token)
	messageBody := fmt.Sprintf("To confirm this email address, go to:<br/>\n<a href=\"%s\">%s</a>", confirmationLink, confirmationLink)
	if err := helper.SendEmail(user.Email, "Email Confirmation", messageBody); err != nil {
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

	var user model.User
	db.Where(&model.User{Token: token}).First(&user)

	if user.Email == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("Invalid confirmation link"))
		return
	}

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

	// Handle the Data protection statement
	app.GET("/dps", showDPSPage)

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
		recordingRoutes.GET("/view/:recording_id", ensureLoggedIn(), getRecordingHTML)

		// Handle the GET requests at /recording/upload
		// Show the recording upload page
		// Ensure that the user is logged in by using the middleware
		recordingRoutes.GET("/upload", ensureLoggedIn(), showRecordingUploadPage)

		// Handle POST requests at /recording/upload
		// Ensure that the user is logged in by using the middleware
		recordingRoutes.POST("/upload", ensureLoggedIn(), uploadRecording)

		// Handle GET requests at /recording/export/srt/some_recording_id
		recordingRoutes.GET("/export/srt/:recording_id", ensureLoggedIn(), getRecordingSRT)

		// Handle GET requests at /recording/export/ttml/some_recording_id
		recordingRoutes.GET("/export/ttml/:recording_id", ensureLoggedIn(), getRecordingTTML)

		// Handle GET requests at /recording/export/vtt/some_recording_id
		recordingRoutes.GET("/export/vtt/:recording_id", ensureLoggedIn(), getRecordingWebVTT)

		// Handle GET requests at /recording/export/otr/some_recording_id
		recordingRoutes.GET("/export/otr/:recording_id", ensureLoggedIn(), getRecordingOTR)

		// Handle GET requests at /recording/delete/some_recording_id
		recordingRoutes.GET("/delete/:recording_id", ensureLoggedIn(), deleteRecording)
	}
}

func main() {
	// Set Gin to production mode
	gin.SetMode(gin.ReleaseMode)

	// Connect to the database
	helper.ConnectDB()
	db = helper.DB

	// Set the router as the default one provided by Gin
	app := gin.Default()

	// Set custom function to format Start and End of utterance
	app.SetFuncMap(template.FuncMap{"formatDuration": formatDuration})

	// Process the templates at the start so that they don't have to be loaded
	// from the disk again. This makes serving HTML pages very fast.
	app.LoadHTMLGlob("cmd/web/templates/*.html")

	// Enable cookie session
	store = cookie.NewStore([]byte(helper.GetConfig("SESSION_KEY")))
	app.Use(sessions.Sessions("ims-speech-session", store))

	// Initialize the routes
	initializeRoutes(app)

	// Start serving the application
	app.Run()
}
