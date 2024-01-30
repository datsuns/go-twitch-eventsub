package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	slogmulti "github.com/samber/slog-multi"
)

type SessionHandler func(*Responce, []byte)
type SessionHandlerEntry struct {
	Version string
	Handler SessionHandler
}

const (
	LocalTestAddr   = "127.0.0.1:8080"
	LocalTestScheme = "ws"
)

var (
	Debug  = flag.Bool("debug", false, "debug mode")
	Test   = flag.Bool("test", false, "local test mode")
	logger *slog.Logger

	scheme = "wss"
	addr   = flag.String("addr", "eventsub.wss.twitch.tv", "http service address")

	path      = "/ws"
	query     = "keepalive_timeout_seconds=30"
	keepalive = flag.String("keepalive", "30", "keepalive timeout")

	// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/#subscription-types
	SubscribeHandlerList = map[string]SessionHandlerEntry{
		"channel.chat.message":         {"1", handleNotificationChannelChatMessage},         // user:read:chat
		"channel.follow":               {"2", handleNotificationDefault},                    // moderator:read:followers
		"channel.chat.notification":    {"1", handleNotificationChannelChatNotification},    // user:read:chat
		"channel.subscribe":            {"1", handleNotificationChannelSubscribe},           // channel:read:subscriptions
		"channel.subscription.gift":    {"1", handleNotificationDefault},                    // channel:read:subscriptions
		"channel.subscription.message": {"1", handleNotificationChannelSubscriptionMessage}, // channel:read:subscriptions
		"channel.cheer":                {"1", handleNotificationChannelCheer},               // bits:read
		"stream.online":                {"1", handleNotificationStreamOnline},
		"stream.offline":               {"1", handleNotificationStreamOffline},
		"channel.channel_points_custom_reward_redemption.add": {"1", handleNotificationChannelPointsCustomRewardRedemptionAdd}, // channel:read:redemptions
	}
)

// --- request

type SubscriptionCondition struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
	UserId            string `json:"user_id"`
	ModeratorUserId   string `json:"moderator_user_id"`
}

type SubscriptionTransport struct {
	Method    string `json:"method"`
	Callback  string `json:"callback"`
	Secret    string `json:"secret"`
	SessionId string `json:"session_id"`
	ConduitId string `json:"conduit_id"`
}

type CreateSubscriptionBody struct {
	Type      string                `json:"type"`
	Version   string                `json:"version"`
	Condition SubscriptionCondition `json:"condition"`
	Transport SubscriptionTransport `json:"transport"`
}

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
	if resp.StatusCode != 202 {
		return nil, fmt.Errorf("error responce. status[%v] msg[%v]", resp.StatusCode, string(byteArray))
	}
	return byteArray, nil
}

func buildQuery() string {
	return fmt.Sprintf("keepalive_timeout_seconds=%v", *keepalive)
}

func connect() (*websocket.Conn, error) {
	var u url.URL
	if *Test {
		u = url.URL{Scheme: LocalTestScheme, Host: LocalTestAddr, Path: path, RawQuery: buildQuery()}
	} else {
		u = url.URL{Scheme: scheme, Host: *addr, Path: path, RawQuery: buildQuery()}
	}
	logger.Info("connecting to " + u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		logger.Error("dial error" + err.Error())
		return nil, err
	}
	return c, nil
}

func receive(conn *websocket.Conn) (*Responce, []byte, error) {
	r := &Responce{}
	_, message, err := conn.ReadMessage()
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
		return nil, nil, err
	}
	if *Debug {
		logger.Info("receive", "raw", string(message))
	}
	err = json.Unmarshal(message, &r)
	if err != nil {
		logger.Error("json.Unmarshal", "ERR", err.Error())
		return nil, nil, err
	}
	return r, message, nil
}

// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/#subscription-types
func handleSessionWelcome(cfg *Config, r *Responce, raw []byte) {
	c := SubscriptionCondition{
		BroadcasterUserId: cfg.TargetUser,
		UserId:            cfg.TargetUser,
		ModeratorUserId:   cfg.TargetUser,
	}
	t := SubscriptionTransport{
		Method:    "websocket",
		SessionId: r.Payload.Session.Id,
	}
	for k, v := range SubscribeHandlerList {
		body := CreateSubscriptionBody{
			Type:      k,
			Version:   v.Version,
			Condition: c,
			Transport: t,
		}
		bin, _ := json.Marshal(&body)
		logger.Info("create EventSub", "SessionID", r.Payload.Session.Id, "User", cfg.TargetUser, "Type", k, "Raw", string(bin))
		_, err := issueEventSubRequest(cfg, "POST", "https://api.twitch.tv/helix/eventsub/subscriptions", bytes.NewReader(bin))
		if err != nil {
			logger.Error("Eventsub Request", "ERROR", err.Error())
		}
	}
}

func handleNotificationDefault(r *Responce, raw []byte) {
	logger.Info("event(no handler)", "Type", r.Payload.Subscription.Type)
}

func handleNotificationChannelChatMessage(r *Responce, raw []byte) {
	v := &ResponceChatMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	logger.Info("event(ChatMsg)", "user", e.ChatterUserLogin, "text", e.Message.Text)
}

func handleNotificationChannelChatNotification(r *Responce, raw []byte) {
	v := &ResponceChannelChatNotification{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	switch e.NoticeType {
	case "raid":
		logger.Info("event(Raid)", "from", e.RaId.UserName, "viewers", e.RaId.ViewerCount)
	case "sub":
	case "resub":
	case "sub_gift":
	case "community_sub_gift":
	case "gift_paid_upgrade":
	case "prime_paid_upgrade":
	case "unraid":
	case "pay_it_forward":
	case "announcement":
	case "bits_badge_tier":
	case "charity_donation":
	default:
		logger.Error("event(NotParsed)", "raw", string(raw))
	}
}

func handleNotificationChannelSubscribe(r *Responce, raw []byte) {
	v := &ResponceChannelSubscribe{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	if v.Payload.Event.IsGift {
		logger.Info("event(Subscribed<Gift>)", "user", e.UserName, "tear", e.Tier, "gift", e.IsGift)
	} else {
		logger.Info("event(Subscribed)", "user", e.UserName, "tear", e.Tier, "gift", e.IsGift)
	}
}

func handleNotificationChannelSubscriptionMessage(r *Responce, raw []byte) {
	v := &ResponceChannelSubscriptionMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	logger.Info("event(ReSubscribed)", "user", e.UserName, "tear", e.Tier,
		"duration", e.DurationMonths, "streak", e.StreakMonths, "cumlative", e.CumulativeMonths)
}

func handleNotificationChannelCheer(r *Responce, raw []byte) {
	v := &ResponceChannelCheer{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	logger.Info("event(Cheer)", "user", e.UserName, "anonymous", e.IsAnonymous, "bits", e.Bits, "msg", e.Message)
}

func handleNotificationStreamOnline(r *Responce, raw []byte) {
	v := &ResponceStreamOnline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	logger.Info("event(Online)", "user", e.BroadcasterUserName, "at", e.StartedAt)
}

func handleNotificationStreamOffline(r *Responce, raw []byte) {
	v := &ResponceStreamOffline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	logger.Info("event(Offline)", "user", e.BroadcasterUserName)
}

func handleNotificationChannelPointsCustomRewardRedemptionAdd(r *Responce, raw []byte) {
	v := &ResponceChannelPointsCustomRewardRedemptionAdd{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("ReadMessage " + err.Error())
	}
	e := &v.Payload.Event
	logger.Info("event(Channel Points)", "user", e.BroadcasterUserName, "title", e.Reward.Title)
}

func handleNotification(cfg *Config, r *Responce, raw []byte) {
	logger.Info("ReceiveNotification", "type", r.Payload.Subscription.Type)
	if e, exists := SubscribeHandlerList[r.Payload.Subscription.Type]; exists {
		e.Handler(r, raw)
	} else {
		logger.Error("UNKNOWN notification", "Type", r.Payload.Subscription.Type)
	}
}

func progress(done *chan struct{}, cfg *Config, conn *websocket.Conn) {
	for {
		r, raw, err := receive(conn)
		if err != nil {
			break
		}
		logger.Info("recv", "Type", r.Metadata.MessageType)
		switch r.Metadata.MessageType {
		case "session_welcome":
			logger.Info("event: connected")
			handleSessionWelcome(cfg, r, raw)
		case "session_keepalive":
			logger.Info("event: keepalive")
		case "session_reconnect":
			logger.Info("event: reconnect")
		case "notification":
			logger.Info("event: notification")
			handleNotification(cfg, r, raw)
		case "revocation":
			logger.Info("event: revocation")
		default:
			logger.Error("UNKNOWN Event", "Type", r.Metadata.MessageType)
		}
	}
}

func buildLogPath() string {
	n := time.Now()
	return fmt.Sprintf("%v.txt", n.Format("20060102_1504"))
}

func buildLogger(logPath string, debug bool) {
	log, _ := os.Create(logPath)
	if debug {
		logger = slog.New(
			slogmulti.Fanout(
				slog.NewTextHandler(os.Stdout, nil),
				slog.NewTextHandler(log, nil),
			),
		)
	} else {
		logger = slog.New(slog.NewTextHandler(log, nil))
	}
}

func main() {
	flag.Parse()
	path := buildLogPath()
	buildLogger(path, *Debug)
	cfg, err := loadConfig()
	if err != nil {
		panic(nil)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	c, _ := connect()
	defer c.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		progress(&done, cfg, c)
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			logger.Info("done")
			return
		//case t := <-ticker.C:
		//	err := c.WriteMessage(websocket.TextMessage, []byte(t.String()))
		//	log.Println("write:", t)
		//	if err != nil {
		//		log.Println("writeERR:", err)
		//		return
		//	}
		case <-interrupt:
			logger.Info("interrupt")

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				logger.Error("write close " + err.Error())
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}
