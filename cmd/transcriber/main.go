package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"simple-web-asr/internal/helper"
	"simple-web-asr/internal/model"
)

var db *gorm.DB

func loadTranscription(filename string, recordingID uint) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var line string
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			break
		}

		parts := strings.SplitN(line, " ", 2)
		times := strings.SplitN(parts[0], "-", 2)

		var timesParsed []float32

		for t := range times {
			timeParsed, errP := strconv.ParseFloat(times[t], 32)
			if errP != nil {
				return errP
			}
			timesParsed = append(timesParsed, float32(timeParsed)/100.0)
		}

		if parts[1] != "" {
			errD := db.Create(&model.Utterance{
				RecordingID: recordingID,
				Start:       timesParsed[0],
				End:         timesParsed[1],
				Text:        parts[1]}).Error
			if errD != nil {
				return errD
			}
		}

		if err != nil {
			break
		}
	}
	if err != io.EOF {
		return err
	}

	return nil
}

func transcribe(recording *model.Recording) {
	recordingName := fmt.Sprintf("\"%v\" (ID %d)", recording.Title, recording.ID)

	log.Println("Transcribing", recordingName)

	recording.Status = 2
	if err := db.Save(&recording).Error; err != nil {
		log.Println(fmt.Sprintf("Failed to update status for %s: %v", recordingName, err))
		return
	}

	recordingFilename := helper.RecordingFilename(recording.ID)

	cmd := exec.Command(helper.GetConfig("DECODE_CMD"), recordingFilename, recording.Language)

	if err := cmd.Run(); err != nil {
		log.Println(fmt.Sprintf("Failed to transcribe %s: %v", recordingName, err))
		recording.Status = 4
	} else {
		transcriptionFilename := recordingFilename + ".txt"

		if err = loadTranscription(transcriptionFilename, recording.ID); err != nil {
			log.Println(fmt.Sprintf("Failed to load %s: %v", transcriptionFilename, err))
			recording.Status = 4
		} else {
			recording.Status = 3
		}
	}

	if err := db.Save(&recording).Error; err != nil {
		log.Println(fmt.Sprintf("Failed to update status for %s: %v", recordingName, err))
	} else {
		log.Println("Done transcribing", recordingName)

		if recording.Status == 3 {
			var user model.User
			db.First(&user, recording.UserID)

			if user.Email != "" {
				link := fmt.Sprintf("%s/recording/view/%d", helper.GetConfig("URL_BASE"), recording.ID)
				body := fmt.Sprintf("To see the transcription, go to:<br/>\n<a href=\"%s\">%s</a>", link, link)
				if errM := helper.SendEmail(user.Email, "Transcription Notification", body); errM != nil {
					log.Println("Failed to send email", errM)
				} else {
					log.Println("Email sent to", user.Email)
				}
			}
		} else {
			helper.SendEmail("pavel.denisov@ims.uni-stuttgart.de", "Transcription Error", fmt.Sprintf("id: %d", recording.ID))
		}
	}
}

func main() {
	helper.ConnectDB()
	db = helper.DB

	for {
		var recordings []model.Recording
		db.Where(&model.Recording{Status: 1}).Limit(1).Find(&recordings)

		if len(recordings) == 0 {
			time.Sleep(10 * time.Second)
		} else {
			transcribe(&recordings[0])
		}
	}
}
