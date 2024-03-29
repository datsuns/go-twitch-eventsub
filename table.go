package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"
)

type CreateRequestBuilder func(*Config, *Responce, string, string) []byte
type NotificationHandler func(*Config, *Responce, []byte, *TwitchStats)

type EventTableEntry struct {
	LogTitle string
	Version  string
	Builder  CreateRequestBuilder
	Handler  NotificationHandler
}

var (
	// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/#subscription-types
	TwitchEventTable = map[string]EventTableEntry{
		"channel.subscribe":            {"サブスク", "1", buildRequest, handleNotificationChannelSubscribe}, // channel:read:subscriptions
		"channel.cheer":                {"cheer", "1", buildRequest, handleNotificationChannelCheer},    // bits:read
		"stream.online":                {"配信開始", "1", buildRequest, handleNotificationStreamOnline},
		"stream.offline":               {"配信終了", "1", buildRequest, handleNotificationStreamOffline},
		"channel.subscription.gift":    {"サブギフ", "1", buildRequest, handleNotificationChannelSubscriptionGift},       // channel:read:subscriptions
		"channel.subscription.message": {"再サブスク", "1", buildRequest, handleNotificationChannelSubscriptionMessage},   // channel:read:subscriptionsg",
		"channel.chat.notification":    {"通知", "1", buildRequestWithUser, handleNotificationChannelChatNotification}, // user:read:chat
		"channel.chat.message":         {"チャット", "1", buildRequestWithUser, handleNotificationChannelChatMessage},    // user:read:chat
		"channel.raid":                 {"レイド開始", "1", buildRequestWithWithFromUser, handleNotificationRaidStarted},  // none
		"channel.follow":               {"フォロー", "2", buildRequestWithModerator, handleNotificationChannelFollow},    // moderator:read:followers
		"channel.channel_points_custom_reward_redemption.add": {"チャネポ", "1", buildRequest, handleNotificationChannelPointsCustomRewardRedemptionAdd}, // channel:read:redemptions
	}
)

func typeToLogTitle(t string) string {
	if s, exists := TwitchEventTable[t]; exists {
		return s.LogTitle + logSplit
	} else {
		return fmt.Sprintf("%v%v", t, logSplit)
	}
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

func buildRequestWithWithFromUser(cfg *Config, r *Responce, subscType, version string) []byte {
	c := RequestConditionWithFromUser{
		FromBroadcasterUserId: cfg.TargetUserId,
	}
	t := SubscriptionTransport{
		Method:    "websocket",
		SessionId: r.Payload.Session.Id,
	}
	body := CreateSubscriptionBodyWithFromUser{
		Type:      subscType,
		Version:   version,
		Condition: c,
		Transport: t,
	}
	bin, _ := json.Marshal(&body)
	return bin
}

func handleNotificationDefault(_ *Config, r *Responce, raw []byte, _ *TwitchStats) {
	statsLogger.Info("event(no handler)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
	)
}

func handleNotificationChannelSubscribe(_ *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelSubscribe{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	if v.Payload.Event.IsGift {
		// ギフトを受け取った人の分は無理に出さなくてよい
		//infoLogger.Info("event(Subscribed<Gift>)",
		//	slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		//	slog.Any(LogFieldName_UserName, e.UserName),
		//	slog.Any("tear", e.Tier),
		//	slog.Any("gift", e.IsGift),
		//)
	} else {
		statsLogger.Info("event(Subscribed)",
			slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
			slog.Any(LogFieldName_UserName, e.UserName),
			slog.Any("tear", e.Tier),
			slog.Any("gift", e.IsGift),
		)
		s.SubScribe(UserName(e.UserName), e.Tier)
	}
}

func handleNotificationChannelCheer(_ *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelCheer{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(Cheer)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("anonymous", e.IsAnonymous),
		slog.Any("bits", e.Bits),
		slog.Any("msg", e.Message),
	)
	s.Cheer(UserName(e.UserName), e.Bits)
}

func handleNotificationStreamOnline(cfg *Config, r *Responce, raw []byte, s *TwitchStats) {
	path := buildLogPath()
	_, statsLogger, infoLogger = buildLogger(cfg, path, *Debug)

	v := &ResponceStreamOnline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	s.StreamStarted()
	e := &v.Payload.Event
	statsLogger.Info("event(Online)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.BroadcasterUserName),
		slog.Any("at", e.StartedAt),
	)
	os.Remove(cfg.RaidLogPath)
}

func handleNotificationStreamOffline(cfg *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceStreamOffline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(Offline)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.BroadcasterUserName),
	)
	s.StreamFinished()
	log, _ := os.OpenFile(cfg.StatsLogPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0666)
	defer log.Close()
	fmt.Fprintf(log, s.String())
}

// サブギフした
func handleNotificationChannelSubscriptionGift(_ *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelSubscriptionGift{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(Gift)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("tear", e.Tier),
		slog.Any("num", e.Total),
		slog.Any("cumulative", e.CumulativeTotal),
		slog.Any("anonymous", e.IsAnonymous),
	)

	s.SubGift(UserName(e.UserName), e.Total)
}

// 継続サブスクをチャットでシェアした
func handleNotificationChannelSubscriptionMessage(_ *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelSubscriptionMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(ReSubscribed)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("tear", e.Tier),
		slog.Any("duration", e.DurationMonths),
		slog.Any("streak", e.StreakMonths),
		slog.Any("cumlative", e.CumulativeMonths),
	)
	s.SubScribe(UserName(e.UserName), e.Tier)
}

func handleNotificationChannelPointsCustomRewardRedemptionAdd(_ *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelPointsCustomRewardRedemptionAdd{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(Channel Points)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("login", e.UserLogin),
		slog.Any("title", e.Reward.Title),
	)
	s.ChannelPoint(UserName(e.UserName), ChannelPointTitle(e.Reward.Title))
}

func handleNotificationChannelChatNotificationSubGifted(_ *Config, r *Responce, e *EventFormatChannelChatNotification, s *TwitchStats) {
	statsLogger.Info("event(SubGiftReceived)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any("category", "サブギフ受信"),
		slog.Any("from", e.ChatterUserName),
		slog.Any("to", e.SubGift.RecipientUserName),
	)
	s.SubGifted(UserName(e.SubGift.RecipientUserName), e.SubGift.Sub_Tier)
}

func handleNotificationChannelChatNotificationRaid(cfg *Config, r *Responce, e *EventFormatChannelChatNotification, s *TwitchStats) {
	statsLogger.Info("event(Raid)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any("category", "レイド"),
		slog.Any("from", e.RaId.UserName),
		slog.Any("viewers", e.RaId.ViewerCount),
	)
	s.Raid(UserName(e.RaId.UserName), e.RaId.ViewerCount)
	clips := referUserClips(cfg, e.RaId.UserId)
	log, _ := os.OpenFile(cfg.RaidLogPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0666)
	defer log.Close()
	fmt.Fprintf(log, fmt.Sprintf("-- %v さんのクリップ -- \n", e.RaId.UserName))
	fmt.Fprintf(log, clips)
}

func handleNotificationChannelChatNotification(cfg *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelChatNotification{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}

	e := &v.Payload.Event
	switch e.NoticeType {
	case "sub":
	case "resub":
		// サブスク継続をチャットで宣言したイベント
		// channel.subscription.message も来るはずなのでそっちでハンドリングする
	case "sub_gift":
		handleNotificationChannelChatNotificationSubGifted(cfg, r, e, s)
	case "community_sub_gift":
	case "gift_paid_upgrade":
	case "prime_paid_upgrade":
	case "raid":
		handleNotificationChannelChatNotificationRaid(cfg, r, e, s)
	case "unraid":
	case "pay_it_forward":
	case "announcement":
	case "bits_badge_tier":
	case "charity_donation":
	default:
		logger.Error("event(NotParsed)", "raw", string(raw))
	}
}

func handleNotificationChannelChatMessage(_ *Config, r *Responce, raw []byte, _ *TwitchStats) {
	v := &ResponceChatMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(ChatMsg)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.ChatterUserName),
		slog.Any(LogFieldName_LoginName, e.ChatterUserLogin),
		slog.Any("text", e.Message.Text),
	)
}

func handleNotificationChannelFollow(_ *Config, r *Responce, raw []byte, s *TwitchStats) {
	v := &ResponceChannelFollow{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	statsLogger.Info("event(Channel Follow)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any(LogFieldName_LoginName, e.UserLogin),
	)
	s.Follow(UserName(e.UserName))
}

func handleNotificationRaidStarted(cfg *Config, r *Responce, raw []byte, _ *TwitchStats) {
	statsLogger.Info("event(Raid Started)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
	)
	go func() {
		logger.Info("StopStream Start")
		ticker := time.NewTicker(time.Minute * time.Duration(cfg.DelayMinutesFromRaidToStop))
		<-ticker.C
		StopObsStream(cfg)
		logger.Info("StopStream End")
		return
	}()
}
