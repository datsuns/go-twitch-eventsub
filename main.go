package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	slogmulti "github.com/samber/slog-multi"
)

type RequestBuilder func(*Config, *Responce, string, string) []byte
type SessionHandler func(*Responce, []byte)
type EventSubHandlerEntry struct {
	Version string
	Builder RequestBuilder
	Handler SessionHandler
}

const (
	LocalTestAddr   = "127.0.0.1:8080"
	LocalTestScheme = "ws"
)

var (
	Debug      = flag.Bool("debug", false, "debug mode")
	Test       = flag.Bool("test", false, "local test mode")
	logger     *slog.Logger
	infoLogger *slog.Logger

	scheme = "wss"
	addr   = flag.String("addr", "eventsub.wss.twitch.tv", "http service address")

	path      = "/ws"
	query     = "keepalive_timeout_seconds=30"
	keepalive = flag.String("keepalive", "30", "keepalive timeout")

	// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/#subscription-types
	SubscribeHandlerList = map[string]EventSubHandlerEntry{
		"channel.subscribe":            {"1", buildRequest, handleNotificationChannelSubscribe}, // channel:read:subscriptions
		"channel.cheer":                {"1", buildRequest, handleNotificationChannelCheer},     // bits:read
		"stream.online":                {"1", buildRequest, handleNotificationStreamOnline},
		"stream.offline":               {"1", buildRequest, handleNotificationStreamOffline},
		"channel.subscription.gift":    {"1", buildRequest, handleNotificationDefault},                    // channel:read:subscriptions
		"channel.subscription.message": {"1", buildRequest, handleNotificationChannelSubscriptionMessage}, // channel:read:subscriptions
		"channel.channel_points_custom_reward_redemption.add": {"1", buildRequest, handleNotificationChannelPointsCustomRewardRedemptionAdd}, // channel:read:redemptions
		"channel.chat.notification":                           {"1", buildRequestWithUser, handleNotificationChannelChatNotification},        // user:read:chat
		"channel.chat.message":                                {"1", buildRequestWithUser, handleNotificationChannelChatMessage},             // user:read:chat
		"channel.follow":                                      {"2", buildRequestWithModerator, handleNotificationDefault},                   // moderator:read:followers
	}
)

// --- request

type RequestCondition struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
}

type RequestConditionWithModerator struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
	ModeratorUserId   string `json:"moderator_user_id"`
}

type RequestConditionWithUser struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
	UserId            string `json:"user_id"`
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
	Condition RequestCondition      `json:"condition"`
	Transport SubscriptionTransport `json:"transport"`
}

type CreateSubscriptionBodyWithModerator struct {
	Type      string                        `json:"type"`
	Version   string                        `json:"version"`
	Condition RequestConditionWithModerator `json:"condition"`
	Transport SubscriptionTransport         `json:"transport"`
}

type CreateSubscriptionBodyWithUser struct {
	Type      string                   `json:"type"`
	Version   string                   `json:"version"`
	Condition RequestConditionWithUser `json:"condition"`
	Transport SubscriptionTransport    `json:"transport"`
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
func buildRequestWithModerator(cfg *Config, r *Responce, subscType, version string) []byte {
	c := RequestConditionWithModerator{
		BroadcasterUserId: cfg.TargetUserId,
		ModeratorUserId:   cfg.TargetUserId,
	}
	t := SubscriptionTransport{
		Method:    "websocket",
		SessionId: r.Payload.Session.Id,
	}
	body := CreateSubscriptionBodyWithModerator{
		Type:      subscType,
		Version:   version,
		Condition: c,
		Transport: t,
	}
	bin, _ := json.Marshal(&body)
	return bin
}

func buildRequest(cfg *Config, r *Responce, subscType, version string) []byte {
	c := RequestCondition{
		BroadcasterUserId: cfg.TargetUserId,
	}
	t := SubscriptionTransport{
		Method:    "websocket",
		SessionId: r.Payload.Session.Id,
	}
	body := CreateSubscriptionBody{
		Type:      subscType,
		Version:   version,
		Condition: c,
		Transport: t,
	}
	bin, _ := json.Marshal(&body)
	return bin
}

func buildRequestWithUser(cfg *Config, r *Responce, subscType, version string) []byte {
	c := RequestConditionWithUser{
		BroadcasterUserId: cfg.TargetUserId,
		UserId:            cfg.TargetUserId,
	}
	t := SubscriptionTransport{
		Method:    "websocket",
		SessionId: r.Payload.Session.Id,
	}
	body := CreateSubscriptionBodyWithUser{
		Type:      subscType,
		Version:   version,
		Condition: c,
		Transport: t,
	}
	bin, _ := json.Marshal(&body)
	return bin
}

// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/#subscription-types
func handleSessionWelcome(cfg *Config, r *Responce, raw []byte) {
	if *Test {
		return
	}
	for k, v := range SubscribeHandlerList {
		err := createEventSubscription(cfg, r, k, &v)
		if err != nil {
			logger.Error("Eventsub Request", "ERROR", err.Error())
		}
	}
}

func handleNotificationDefault(r *Responce, raw []byte) {
	infoLogger.Info("event(no handler)",
		slog.Any("type", r.Payload.Subscription.Type),
	)
}

func handleNotificationChannelChatMessage(r *Responce, raw []byte) {
	v := &ResponceChatMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(ChatMsg)",
		slog.Any("type", r.Payload.Subscription.Type),
		slog.Any("user", e.ChatterUserLogin),
		slog.Any("name", e.ChatterUserName),
		slog.Any("text", e.Message.Text),
	)
}

func handleNotificationChannelChatNotification(r *Responce, raw []byte) {
	v := &ResponceChannelChatNotification{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	switch e.NoticeType {
	case "raid":
		infoLogger.Info("event(Raid)",
			slog.Any("type", r.Payload.Subscription.Type),
			slog.Any("from", e.RaId.UserName),
			slog.Any("viewers", e.RaId.ViewerCount),
		)
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
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	if v.Payload.Event.IsGift {
		infoLogger.Info("event(Subscribed<Gift>)",
			slog.Any("type", r.Payload.Subscription.Type),
			slog.Any("user", e.UserName),
			slog.Any("tear", e.Tier),
			slog.Any("gift", e.IsGift),
		)
	} else {
		infoLogger.Info("event(Subscribed)",
			slog.Any("type", r.Payload.Subscription.Type),
			slog.Any("user", e.UserName),
			slog.Any("tear", e.Tier),
			slog.Any("gift", e.IsGift),
		)
	}
}

func handleNotificationChannelSubscriptionMessage(r *Responce, raw []byte) {
	v := &ResponceChannelSubscriptionMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(ReSubscribed)",
		slog.Any("type", r.Payload.Subscription.Type),
		slog.Any("user", e.UserName),
		slog.Any("tear", e.Tier),
		slog.Any("duration", e.DurationMonths),
		slog.Any("streak", e.StreakMonths),
		slog.Any("cumlative", e.CumulativeMonths),
	)
}

func handleNotificationChannelCheer(r *Responce, raw []byte) {
	v := &ResponceChannelCheer{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Cheer)",
		slog.Any("type", r.Payload.Subscription.Type),
		slog.Any("user", e.UserName),
		slog.Any("anonymous", e.IsAnonymous),
		slog.Any("bits", e.Bits),
		slog.Any("msg", e.Message),
	)
}

func handleNotificationStreamOnline(r *Responce, raw []byte) {
	path := buildLogPath()
	_, infoLogger = buildLogger(path, *Debug)

	v := &ResponceStreamOnline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Online)",
		slog.Any("type", r.Payload.Subscription.Type),
		slog.Any("user", e.BroadcasterUserName),
		slog.Any("at", e.StartedAt),
	)
}

func handleNotificationStreamOffline(r *Responce, raw []byte) {
	v := &ResponceStreamOffline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Offline)",
		slog.Any("type", r.Payload.Subscription.Type),
		slog.Any("user", e.BroadcasterUserName),
	)
}

func handleNotificationChannelPointsCustomRewardRedemptionAdd(r *Responce, raw []byte) {
	v := &ResponceChannelPointsCustomRewardRedemptionAdd{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Channel Points)",
		slog.Any("type", r.Payload.Subscription.Type),
		slog.Any("user", e.UserLogin),
		slog.Any("name", e.UserName),
		slog.Any("title", e.Reward.Title),
	)
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
			//logger.Info("event: keepalive")
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
	if *Test {
		return "local.test.txt"
	}
	n := time.Now()
	return fmt.Sprintf("%v.txt", n.Format("20060102"))
}

func buildLogger(logPath string, debug bool) (*slog.Logger, *slog.Logger) {
	log, _ := os.OpenFile(logPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0666)
	runlog, _ := os.OpenFile("debug.txt", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0666)
	return slog.New(
		slogmulti.Fanout(
			slog.NewTextHandler(os.Stdout, nil),
			slog.NewTextHandler(runlog, nil),
			NewTwitchInfoLogger(os.Stdout),
		),
	), slog.New(NewTwitchInfoLogger(log))

}

func main() {
	flag.Parse()
	path := buildLogPath()
	logger, infoLogger = buildLogger(path, *Debug)
	cfg, err := loadConfig()
	if err != nil {
		panic(nil)
	}
	cfg.TargetUserId = referTargetUserId(cfg)

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
