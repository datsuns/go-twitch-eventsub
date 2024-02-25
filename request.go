package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func issueEventSubRequest(cfg *Config, method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if *Debug {
		logger.Info("rest auth", "Auth", cfg.AuthCode, "ClientID", cfg.ClientId)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.AuthCode))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Client-Id", cfg.ClientId)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	byteArray, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if *Debug {
		logger.Info("request", "Status", resp.Status, "URL", url, "RawRet", string(byteArray))
	}
	switch resp.StatusCode {
	case 200:
	case 202:
	default:
		return nil, fmt.Errorf("error responce. status[%v] msg[%v]", resp.StatusCode, string(byteArray))
	}
	return byteArray, nil
}

func createEventSubscription(cfg *Config, r *Responce, event string, e *EventTableEntry) error {
	bin := e.Builder(cfg, r, event, e.Version)
	logger.Info("create EventSub", "SessionID", r.Payload.Session.Id, "User", cfg.TargetUserId, "Type", event, "Raw", string(bin))
	_, err := issueEventSubRequest(cfg, "POST", "https://api.twitch.tv/helix/eventsub/subscriptions", bytes.NewReader(bin))
	return err
}

func referTargetUserIdWith(cfg *Config, username string) string {
	url := fmt.Sprintf("https://api.twitch.tv/helix/users?login=%v", username)
	ret, err := issueEventSubRequest(cfg, "GET", url, nil)
	if err != nil {
		logger.Error("Eventsub Request", "ERROR", err.Error())
	}
	r := &GetUsersApiResponce{}
	err = json.Unmarshal(ret, &r)
	if err != nil {
		logger.Error("json.Unmarshal", "ERR", err.Error())
	}
	logger.Info("SubscribeTarget", "id", r.Data[0].Id, "name", r.Data[0].DisplayName)
	return r.Data[0].Id
}

func referTargetUserId(cfg *Config) string {
	return referTargetUserIdWith(cfg, cfg.TargetUser)
}

func referUserClips(cfg *Config, userId string) string {
	retString, _ := referUserClipsByDate(cfg, userId, true, nil)
	return retString
}

func referUserClipsByDate(cfg *Config, userId string, featured bool, date *time.Time) (string, *GetClipsApiResponce) {
	maxN := 5
	url := fmt.Sprintf("https://api.twitch.tv/helix/clips?broadcaster_id=%v&is_featured=%v&first=%v", userId, featured, maxN)
	if date != nil {
		url += fmt.Sprintf("&started_at=%v", date.UTC().Format(time.RFC3339))
	}
	raw, err := issueEventSubRequest(cfg, "GET", url, nil)
	if err != nil {
		logger.Error("Eventsub Request", "ERROR", err.Error())
		return "", nil
	}
	r := &GetClipsApiResponce{}
	err = json.Unmarshal(raw, &r)
	if err != nil {
		logger.Error("json.Unmarshal", "ERR", err.Error())
		return "", nil
	}
	ret := ""
	for _, v := range r.Data {
		//infoLogger.Info("UserClip", slog.Any("タイトル", v.Title), slog.Any("URL", v.Url), slog.Any("視聴回数", v.ViewCount))
		ret += fmt.Sprintf("   再生回数[%v] / タイトル[%v] / URL[ %v ]\n", v.ViewCount, v.Title, v.Url)
	}
	return ret, r
}
