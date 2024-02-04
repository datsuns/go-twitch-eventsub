package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

type CreateRequestBuilder func(*Config, *Responce, string, string) []byte
type NotificationHandler func(*Config, *Responce, []byte)

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
		"channel.subscription.gift":    {"サブギフ", "1", buildRequest, handleNotificationDefault},                       // channel:read:subscriptions
		"channel.subscription.message": {"サブスクms", "1", buildRequest, handleNotificationChannelSubscriptionMessage},  // channel:read:subscriptionsg",
		"channel.chat.notification":    {"通知", "1", buildRequestWithUser, handleNotificationChannelChatNotification}, // user:read:chat
		"channel.chat.message":         {"チャット", "1", buildRequestWithUser, handleNotificationChannelChatMessage},    // user:read:chat
		"channel.follow":               {"フォロー", "2", buildRequestWithModerator, handleNotificationDefault},          // moderator:read:followers
		"channel.channel_points_custom_reward_redemption.add": {"チャネポ", "1", buildRequest, handleNotificationChannelPointsCustomRewardRedemptionAdd}, // channel:read:redemptions
	}
)

func typeToChatTitle(t string) string {
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

func handleNotificationDefault(_ *Config, r *Responce, raw []byte) {
	infoLogger.Info("event(no handler)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
	)
}

func handleNotificationChannelSubscribe(_ *Config, r *Responce, raw []byte) {
	v := &ResponceChannelSubscribe{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	if v.Payload.Event.IsGift {
		infoLogger.Info("event(Subscribed<Gift>)",
			slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
			slog.Any(LogFieldName_UserName, e.UserName),
			slog.Any("tear", e.Tier),
			slog.Any("gift", e.IsGift),
		)
	} else {
		infoLogger.Info("event(Subscribed)",
			slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
			slog.Any(LogFieldName_UserName, e.UserName),
			slog.Any("tear", e.Tier),
			slog.Any("gift", e.IsGift),
		)
	}
}

func handleNotificationChannelCheer(_ *Config, r *Responce, raw []byte) {
	v := &ResponceChannelCheer{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Cheer)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("anonymous", e.IsAnonymous),
		slog.Any("bits", e.Bits),
		slog.Any("msg", e.Message),
	)
}

func handleNotificationStreamOnline(cfg *Config, r *Responce, raw []byte) {
	path := buildLogPath()
	_, infoLogger = buildLogger(cfg, path, *Debug)

	v := &ResponceStreamOnline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Online)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.BroadcasterUserName),
		slog.Any("at", e.StartedAt),
	)
}

func handleNotificationStreamOffline(_ *Config, r *Responce, raw []byte) {
	v := &ResponceStreamOffline{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Offline)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.BroadcasterUserName),
	)
}

func handleNotificationChannelSubscriptionMessage(_ *Config, r *Responce, raw []byte) {
	v := &ResponceChannelSubscriptionMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(ReSubscribed)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("tear", e.Tier),
		slog.Any("duration", e.DurationMonths),
		slog.Any("streak", e.StreakMonths),
		slog.Any("cumlative", e.CumulativeMonths),
	)
}

func handleNotificationChannelPointsCustomRewardRedemptionAdd(_ *Config, r *Responce, raw []byte) {
	v := &ResponceChannelPointsCustomRewardRedemptionAdd{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(Channel Points)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.UserName),
		slog.Any("login", e.UserLogin),
		slog.Any("title", e.Reward.Title),
	)
}

func handleNotificationChannelChatNotification(_ *Config, r *Responce, raw []byte) {
	v := &ResponceChannelChatNotification{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	switch e.NoticeType {
	case "raid":
		infoLogger.Info("event(Raid)",
			slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
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

func handleNotificationChannelChatMessage(_ *Config, r *Responce, raw []byte) {
	v := &ResponceChatMessage{}
	err := json.Unmarshal(raw, &v)
	if err != nil {
		logger.Error("Unmarshal", "error", err, "raw", string(raw))
	}
	e := &v.Payload.Event
	infoLogger.Info("event(ChatMsg)",
		slog.Any(LogFieldName_Type, r.Payload.Subscription.Type),
		slog.Any(LogFieldName_UserName, e.ChatterUserName),
		slog.Any("login", e.ChatterUserLogin),
		slog.Any("text", e.Message.Text),
	)
}
