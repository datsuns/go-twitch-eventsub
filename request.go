package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func createEventSubscription(cfg *Config, r *Responce, event string, e *SessionHandlerEntry) error {
	bin := e.Builder(cfg, r, event, e.Version)
	logger.Info("create EventSub", "SessionID", r.Payload.Session.Id, "User", cfg.TargetUserId, "Type", event, "Raw", string(bin))
	_, err := issueEventSubRequest(cfg, "POST", "https://api.twitch.tv/helix/eventsub/subscriptions", bytes.NewReader(bin))
	return err
}

func referTargetUserId(cfg *Config) string {
	url := fmt.Sprintf("https://api.twitch.tv/helix/users?login=%v", cfg.TargetUser)
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
