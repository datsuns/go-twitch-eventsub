package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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
	LocalTestAddr   = "127.0.0.1:8080"
	LocalTestScheme = "ws"
)

var (
	Debug = flag.Bool("debug", false, "debug mode")
	Test  = flag.Bool("test", false, "local test mode")

	scheme = "wss"
	addr   = flag.String("addr", "eventsub.wss.twitch.tv", "http service address")
	user   = flag.String("user", os.Getenv("DEFAULT_SUBSCRIBE_USER"), "subscription target user")

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
	authCode := os.Getenv("MY_TWITCH_AUTH_CODE")
	clientId := os.Getenv("MY_TWITCH_CLIENT_ID")
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if *Debug {
		log.Printf("  auth[%v] client[%v]\n", authCode, clientId)
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
		log.Printf("request[%s]\n   ret[%s]\n", url, string(byteArray))
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
	log.Printf("connecting to %s", u.String())

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
		log.Println("ERR(ReadMessage): ", err)
		return nil, nil, err
	}
	if *Debug {
		fmt.Println("raw data:   ", string(message))
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
	fmt.Println("session ID is", r.Payload.Session.Id, "target user [", *user, "]")
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
		log.Printf("create EventSub [%v]\n", k)
		_, err := issueEventSubRequest("POST", "https://api.twitch.tv/helix/eventsub/subscriptions", bytes.NewReader(bin))
		if err != nil {
			log.Println("ERR(Eventsub Request): ", err)
		}
	}
}

func handleNotificationDefault(r *Responce, raw []byte) {
	fmt.Printf(">event(no handler): [%v]\n", r.Payload.Subscription.Type)
}

func handleNotificationChannelChatMessage(r *Responce, raw []byte) {
	v := &ResponceChatMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	fmt.Printf(">event: chat msg [user:%v] [text:%v]\n", v.Payload.Event.ChatterUserLogin, v.Payload.Event.Message.Text)
}

func handleNotificationChannelChatNotification(r *Responce, raw []byte) {
	v := &ResponceChannelChatNotification{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	switch v.Payload.Event.NoticeType {
	case "raid":
		fmt.Printf(">event: raid from[%v] w/ [%v] viewers\n", v.Payload.Event.RaId.UserName, v.Payload.Event.RaId.ViewerCount)
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
		fmt.Printf(">event: not-parsed[%v]\n", string(raw))
	}
}

func handleNotificationChannelSubscribe(r *Responce, raw []byte) {
	v := &ResponceChannelSubscribe{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	if v.Payload.Event.IsGift {
		fmt.Printf(">event : Subscribed(Gift) [user:%v] [tear:%v] [gift:%v]\n", v.Payload.Event.UserName, v.Payload.Event.Tier, v.Payload.Event.IsGift)
	} else {
		fmt.Printf(">event : Subscribed [user:%v] [tear:%v] [gift:%v]\n", v.Payload.Event.UserName, v.Payload.Event.Tier, v.Payload.Event.IsGift)
	}
}

func handleNotificationChannelSubscriptionMessage(r *Responce, raw []byte) {
	v := &ResponceChannelSubscriptionMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	fmt.Printf(">event: ReSubscribed [user:%v] [tear:%v] [get %v month subscription] [continous:%v month] [total:%v month]\n",
		v.Payload.Event.UserName, v.Payload.Event.Tier, v.Payload.Event.DurationMonths, v.Payload.Event.StreakMonths, v.Payload.Event.CumulativeMonths)
}

func handleNotificationChannelCheer(r *Responce, raw []byte) {
	v := &ResponceChannelCheer{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	fmt.Printf(">event: Cheer [user:%v] [anonymous:%v] [bits %v] [msg:%v]\n",
		v.Payload.Event.UserName, v.Payload.Event.IsAnonymous, v.Payload.Event.Bits, v.Payload.Event.Message)
}

func handleNotificationStreamOnline(r *Responce, raw []byte) {
	v := &ResponceStreamOnline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	fmt.Printf(">event: Online [user:%v] [at:%v]\n",
		v.Payload.Event.BroadcasterUserName, v.Payload.Event.StartedAt)
}

func handleNotificationStreamOffline(r *Responce, raw []byte) {
	v := &ResponceStreamOffline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	fmt.Printf(">event: Offline [user:%v]\n",
		v.Payload.Event.BroadcasterUserName)
}

func handleNotificationChannelPointsCustomRewardRedemptionAdd(r *Responce, raw []byte) {
	v := &ResponceChannelPointsCustomRewardRedemptionAdd{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		log.Println("ERR(ReadMessage): ", err)
	}
	fmt.Printf(">event: Channel Points [user:%v] [title:%v]\n",
		v.Payload.Event.BroadcasterUserName, v.Payload.Event.Reward.Title)
}

func handleNotification(r *Responce, raw []byte) {
	fmt.Println("type ", r.Payload.Subscription.Type)
	if e, exists := SubscribeHandlerList[r.Payload.Subscription.Type]; exists {
		e.Handler(r, raw)
	} else {
		fmt.Println("UNKNOWN notification", r.Payload.Subscription.Type)
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
			fmt.Println("event: connected")
			handleSessionWelcome(r, raw)
		case "session_keepalive":
			fmt.Println("event: keepalive")
		case "session_reconnect":
			fmt.Println("event: reconnect")
		case "notification":
			fmt.Println("event: notification")
			handleNotification(r, raw)
		case "revocation":
			fmt.Println("event: revocation")
		default:
			fmt.Println("event: UNKNOWN", r.Metadata.MessageType)
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
			fmt.Println("done")
			return
		//case t := <-ticker.C:
		//	err := c.WriteMessage(websocket.TextMessage, []byte(t.String()))
		//	log.Println("write:", t)
		//	if err != nil {
		//		log.Println("writeERR:", err)
		//		return
		//	}
		case <-interrupt:
			log.Println("interrupt")

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
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
