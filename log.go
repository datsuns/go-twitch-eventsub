package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

type TwitchInfoLogger struct {
	slog.Handler
	w io.Writer
	c *Config
}

func NewTwitchInfoLogger(c *Config, w io.Writer) *TwitchInfoLogger {
	return &TwitchInfoLogger{
		Handler: slog.NewTextHandler(w, nil),
		w:       w,
		c:       c,
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

func loggable(cfg *Config, fields *map[string]any) bool {
	// いったんチャットフィルタはなくした
	return true
	//t := fmt.Sprintf("%v", (*fields)[LogFieldName_Type])
	//if t == "channel.chat.message" {
	//	u := fmt.Sprintf("%v", (*fields)[LogFieldName_LoginName])
	//	return slices.Contains(cfg.ChatTargets, u)
	//}
	//return true
}

func (t *TwitchInfoLogger) Handle(c context.Context, r slog.Record) error {
	fields := make(map[string]any, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		addLogFields(fields, a)
		return true
	})
	typeField := fields[LogFieldName_Type]

	if typeField == nil {
		t.w.Write([]byte(fmt.Sprintf("%v\n", fields)))
		return nil
	}

	if loggable(t.c, &fields) == false {
		return nil
	}
	log := r.Time.Format("2006/01/02 15:04:05 ")
	pattern := fmt.Sprintf("%v", typeField)
	log += typeToLogTitle(pattern)
	for k, v := range fields {
		if k == LogFieldName_Type {
			continue
		}
		log += fmt.Sprintf("%v:%v%v", k, v, logSplit)
	}
	log += "\n"
	t.w.Write([]byte(log))

	return nil
}
