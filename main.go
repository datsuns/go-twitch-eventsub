package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

type SessionHandler func(*Responce, []byte)
type SessionHandlerEntry struct {
	Version string
	Handler SessionHandler
}

const (
	LocalTestAddr          = "127.0.0.1:8080"
	LocalTestScheme        = "ws"
	DEFAULT_SUBSCRIBE_USER = "DEFAULT_SUBSCRIBE_USER"
	MY_TWITCH_AUTH_CODE    = "MY_TWITCH_AUTH_CODE"
	MY_TWITCH_CLIENT_ID    = "MY_TWITCH_CLIENT_ID"
)

var (
	logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	Debug  = flag.Bool("debug", false, "debug mode")
	Test   = flag.Bool("test", false, "local test mode")

	scheme = "wss"
	addr   = flag.String("addr", "eventsub.wss.twitch.tv", "http service address")
	user   = flag.String("user", os.Getenv(DEFAULT_SUBSCRIBE_USER), "subscription target user")

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

func issueEventSubRequest(method, url string, body io.Reader) ([]byte, error) {
	authCode := os.Getenv(MY_TWITCH_AUTH_CODE)
	clientId := os.Getenv(MY_TWITCH_CLIENT_ID)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if *Debug {
		logger.Info(fmt.Sprintf("  auth[%v] client[%v]", authCode, clientId))
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authCode))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Client-Id", clientId)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	byteArray, _ := io.ReadAll(resp.Body)
	if *Debug {
		logger.Info("request[" + url + "]")
		logger.Info("ret[" + string(byteArray) + "]")
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
		log.Fatal("dial:", err)
		return nil, err
	}
	return c, nil
}

func receive(conn *websocket.Conn) (*Responce, []byte, error) {
	r := &Responce{}
	_, message, err := conn.ReadMessage()
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
		return nil, nil, err
	}
	if *Debug {
		logger.Info(fmt.Sprintln("raw data:   ", string(message)))
	}
	err = json.Unmarshal(message, &r)
	if err != nil {
		log.Fatalln(err)
		return nil, nil, err
	}
	return r, message, nil
}

// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/#subscription-types
func handleSessionWelcome(r *Responce, raw []byte) {
	logger.Info(fmt.Sprintln("session ID is", r.Payload.Session.Id, "target user [", *user, "]"))
	c := SubscriptionCondition{
		BroadcasterUserId: *user,
		UserId:            *user,
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
		logger.Info(fmt.Sprintf("create EventSub [%v]", k))
		_, err := issueEventSubRequest("POST", "https://api.twitch.tv/helix/eventsub/subscriptions", bytes.NewReader(bin))
		if err != nil {
			logger.Info(fmt.Sprintln("ERR(Eventsub Request): ", err))
		}
	}
}

func handleNotificationDefault(r *Responce, raw []byte) {
	logger.Info(fmt.Sprintf(">event(no handler): [%v]", r.Payload.Subscription.Type))
}

func handleNotificationChannelChatMessage(r *Responce, raw []byte) {
	v := &ResponceChatMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	logger.Info(fmt.Sprintf(">event: chat msg [user:%v] [text:%v]", v.Payload.Event.ChatterUserLogin, v.Payload.Event.Message.Text))
}

func handleNotificationChannelChatNotification(r *Responce, raw []byte) {
	v := &ResponceChannelChatNotification{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	switch v.Payload.Event.NoticeType {
	case "raid":
		logger.Info(fmt.Sprintf(">event: raid from[%v] w/ [%v] viewers", v.Payload.Event.RaId.UserName, v.Payload.Event.RaId.ViewerCount))
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
		logger.Info(fmt.Sprintf(">event: not-parsed[%v]", string(raw)))
	}
}

func handleNotificationChannelSubscribe(r *Responce, raw []byte) {
	v := &ResponceChannelSubscribe{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	if v.Payload.Event.IsGift {
		logger.Info(fmt.Sprintf(">event : Subscribed(Gift) [user:%v] [tear:%v] [gift:%v]", v.Payload.Event.UserName, v.Payload.Event.Tier, v.Payload.Event.IsGift))
	} else {
		logger.Info(fmt.Sprintf(">event : Subscribed [user:%v] [tear:%v] [gift:%v]", v.Payload.Event.UserName, v.Payload.Event.Tier, v.Payload.Event.IsGift))
	}
}

func handleNotificationChannelSubscriptionMessage(r *Responce, raw []byte) {
	v := &ResponceChannelSubscriptionMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	logger.Info(fmt.Sprintf(">event: ReSubscribed [user:%v] [tear:%v] [get %v month subscription] [continous:%v month] [total:%v month]",
		v.Payload.Event.UserName, v.Payload.Event.Tier, v.Payload.Event.DurationMonths, v.Payload.Event.StreakMonths, v.Payload.Event.CumulativeMonths))
}

func handleNotificationChannelCheer(r *Responce, raw []byte) {
	v := &ResponceChannelCheer{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	logger.Info(fmt.Sprintf(">event: Cheer [user:%v] [anonymous:%v] [bits %v] [msg:%v]",
		v.Payload.Event.UserName, v.Payload.Event.IsAnonymous, v.Payload.Event.Bits, v.Payload.Event.Message))
}

func handleNotificationStreamOnline(r *Responce, raw []byte) {
	v := &ResponceStreamOnline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	logger.Info(fmt.Sprintf(">event: Online [user:%v] [at:%v]",
		v.Payload.Event.BroadcasterUserName, v.Payload.Event.StartedAt))
}

func handleNotificationStreamOffline(r *Responce, raw []byte) {
	v := &ResponceStreamOffline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	logger.Info(fmt.Sprintf(">event: Offline [user:%v]",
		v.Payload.Event.BroadcasterUserName))
}

func handleNotificationChannelPointsCustomRewardRedemptionAdd(r *Responce, raw []byte) {
	v := &ResponceChannelPointsCustomRewardRedemptionAdd{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Info(fmt.Sprintln("ERR(ReadMessage): ", err))
	}
	logger.Info(fmt.Sprintf(">event: Channel Points [user:%v] [title:%v]",
		v.Payload.Event.BroadcasterUserName, v.Payload.Event.Reward.Title))
}

func handleNotification(r *Responce, raw []byte) {
	log.Println("type ", r.Payload.Subscription.Type)
	if e, exists := SubscribeHandlerList[r.Payload.Subscription.Type]; exists {
		e.Handler(r, raw)
	} else {
		logger.Info("UNKNOWN notification " + r.Payload.Subscription.Type)
	}
}

func progress(done *chan struct{}, conn *websocket.Conn) {
	for {
		r, raw, err := receive(conn)
		if err != nil {
			break
		}
		log.Printf("recv: type[%v]", r.Metadata.MessageType)
		switch r.Metadata.MessageType {
		case "session_welcome":
			log.Println("event: connected")
			handleSessionWelcome(r, raw)
		case "session_keepalive":
			log.Println("event: keepalive")
		case "session_reconnect":
			log.Println("event: reconnect")
		case "notification":
			log.Println("event: notification")
			handleNotification(r, raw)
		case "revocation":
			log.Println("event: revocation")
		default:
			log.Println("event: UNKNOWN", r.Metadata.MessageType)
		}
	}
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	c, _ := connect()
	defer c.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		progress(&done, c)
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
				logger.Info("write close:" + err.Error())
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
