package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	// multi byte string will corrupted by "gopkg.in/toast.v1"
	"github.com/go-toast/toast"
	"github.com/gopxl/beep"
	"github.com/gopxl/beep/mp3"
	"github.com/gopxl/beep/speaker"
	"github.com/gopxl/beep/wav"
)

const (
	WatcherInterval = 60
)

func playSound(path string) {
	f, err := os.Open(path)
	if err != nil {
		logger.Error("PlaySound(open)", slog.Any("error", err.Error()))
		return
	}

	var streamer beep.StreamSeekCloser
	var format beep.Format
	switch strings.ToLower(filepath.Ext(path)) {
	case ".wav":
		streamer, format, err = wav.Decode(f)
	case ".mp3":
		streamer, format, err = mp3.Decode(f)
	default:
		streamer, format, err = mp3.Decode(f)
	}
	if err != nil {
		logger.Error("PlaySound(Decode)", slog.Any("error", err.Error()))
		return
	}
	defer streamer.Close()

	speaker.Init(format.SampleRate, format.SampleRate.N(time.Second/10))
	done := make(chan bool)
	speaker.Play(beep.Seq(streamer, beep.Callback(func() {
		done <- true
	})))
	<-done
}

func showNotification(user, url, at string) {
	notification := toast.Notification{
		AppID:    "Clip Generated Notification",
		Title:    "クリップが作成されました",
		Audio:    toast.Silent,
		Duration: toast.Long,
	}
	notification.Message = fmt.Sprintf(
		"作成者 : %v\n作成日 : %v\n", user, at,
	)
	notification.ActivationArguments = url
	err := notification.Push()
	if err != nil {
		logger.Error("Notification", slog.Any("error", err.Error()))
	}
}

func StartWatcher(cfg *Config, done chan struct{}) {
	go func() {
		ticker := time.NewTicker(time.Second * WatcherInterval)
		defer ticker.Stop()
		//byDate := time.Date(2024, 2, 1, 9, 0, 0, 0, time.Local)
		byDate := time.Now()
		for {
			select {
			case <-done:
				break
			case <-ticker.C:
				ret, raw := referUserClipsByDate(cfg, cfg.TargetUserId, false, &byDate)
				if len(ret) > 0 {
					playSound(cfg.NotifySoundFile)
					showNotification(raw.Data[0].CreatorName, raw.Data[0].Url, raw.Data[0].CreatedAt)
					statsLogger.Info("NewClip",
						slog.Any(LogFieldName_Type, "新規クリップ"),
						slog.Any("by", raw.Data[0].CreatorName),
						slog.Any("title", raw.Data[0].Title),
					)
				}
				byDate = time.Now()
			}
		}
	}()
}
