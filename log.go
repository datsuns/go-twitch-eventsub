package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

var (
	TypeToTitle = map[string]string{
		"channel.subscribe":            "サブスク",
		"channel.cheer":                "cheer",
		"stream.online":                "配信開始",
		"stream.offline":               "配信終了",
		"channel.subscription.gift":    "サブギフ",
		"channel.subscription.message": "サブスクmsg",
		"channel.channel_points_custom_reward_redemption.add": "チャネポ",
		"channel.chat.notification":                           "通知",
		"channel.chat.message":                                "チャット",
		"channel.follow":                                      "フォロー",
	}
)

type TwitchInfoLogger struct {
	slog.Handler
	w io.Writer
}

func NewTwitchInfoLogger(w io.Writer) *TwitchInfoLogger {
	return &TwitchInfoLogger{
		Handler: slog.NewTextHandler(w, nil),
		w:       w,
	}
}

func addLogFields(fields map[string]any, a slog.Attr) {
	value := a.Value.Any()
	if _, ok := value.([]slog.Attr); !ok {
		fields[a.Key] = value
		return
	}

	attrs := value.([]slog.Attr)
	// ネストしている場合、再起的にフィールドを探索する。
	innerFields := make(map[string]any, len(attrs))
	for _, attr := range attrs {
		addLogFields(innerFields, attr)
	}
	fields[a.Key] = innerFields
}

func (t *TwitchInfoLogger) Handle(_ context.Context, r slog.Record) error {
	split := "   "
	fields := make(map[string]any, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		addLogFields(fields, a)
		return true
	})
	log := r.Time.Format("2006/01/02 15:04:05 ")
	pattern := fmt.Sprintf("%v", fields["type"])
	if s, exists := TypeToTitle[pattern]; exists {
		log += s + split
	} else {
		log += fmt.Sprintf("%v%v", pattern, split)
	}
	for k, v := range fields {
		if k == "type" {
			continue
		}
		log += fmt.Sprintf("%v:%v%v", k, v, split)
	}
	log += "\n"
	t.w.Write([]byte(log))

	return nil
}
