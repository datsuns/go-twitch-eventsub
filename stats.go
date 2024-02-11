package main

import (
	"io"
	"time"
)

type UserName string
type ChannelPointTitle string

type PeriodStats struct {
	Started  time.Time
	Finished time.Time
}

type ViewerStats struct {
	Time  time.Time
	Total int
}

type ChatEntry struct {
	Time time.Time
	User UserName
	Text string
}

type ChatStats struct {
	Total   int
	History []ChatEntry
}

type CheerRecord struct {
	Bits  int
	Times int
}

type CheerStats struct {
	TotalBits int
	History   map[UserName]CheerRecord
}

type ChannelPointStats struct {
	TotalTimes int
	Record     map[ChannelPointTitle]int
}

type TwitchStats struct {
	InStreaming    bool
	LastPeriod     PeriodStats
	ChatStats      ChatStats
	CheerStats     CheerStats
	ViewersHistory []ViewerStats
	ChannelPoinsts ChannelPointStats
}

func NewTwitchStats() *TwitchStats {
	ret := &TwitchStats{}
	ret.Clear()
	return ret
}

func (t *TwitchStats) Clear() {
	t.InStreaming = false
	t.ChatStats = ChatStats{
		Total: 0,
	}
	t.CheerStats = CheerStats{
		TotalBits: 0,
		History:   map[UserName]CheerRecord{},
	}
	t.ViewersHistory = []ViewerStats{}
	t.ChannelPoinsts = ChannelPointStats{
		TotalTimes: 0,
		Record:     map[ChannelPointTitle]int{},
	}
}

func (t *TwitchStats) String() string {
	return ""
}

func (t *TwitchStats) Dump(w io.Writer) {
}

func (t *TwitchStats) StreamStarted() {
	t.Clear()
	t.InStreaming = true
	t.LastPeriod.Started = time.Now()
}

func (t *TwitchStats) StreamFinished() {
	t.LastPeriod.Finished = time.Now()
	t.InStreaming = false
}

func (t *TwitchStats) Chat(user UserName, text string) {
	if t.InStreaming == false {
		return
	}
	t.ChatStats.Total += 1
	t.ChatStats.History = append(t.ChatStats.History, ChatEntry{Time: time.Now(), User: user, Text: text})
}

func (t *TwitchStats) ChannelPoint(user UserName, title ChannelPointTitle) {
	if t.InStreaming == false {
		return
	}
	t.ChannelPoinsts.TotalTimes += 1
	if _, exists := t.ChannelPoinsts.Record[title]; exists {
		t.ChannelPoinsts.Record[title] += 1
	} else {
		t.ChannelPoinsts.Record[title] = 1
	}
}

func (t *TwitchStats) Cheer(user UserName, n int) {
	t.CheerStats.TotalBits += n
	if v, exists := t.CheerStats.History[user]; exists {
		v.Bits += n
		v.Times += 1
		t.CheerStats.History[user] = v
	} else {
		t.CheerStats.History[user] = CheerRecord{Bits: n, Times: 1}
	}
}

// --- loader

func (t *TwitchStats) LoadPeriod() time.Duration {
	return t.LastPeriod.Finished.Sub(t.LastPeriod.Started)
}

func (t *TwitchStats) LoadNChats() int {
	return t.ChatStats.Total
}

func (t *TwitchStats) LoadChatHistory() []ChatEntry {
	return t.ChatStats.History
}

func (t *TwitchStats) LoadCheerTotal() int {
	return t.CheerStats.TotalBits
}

func (t *TwitchStats) LoadCheerHistory() map[UserName]CheerRecord {
	return t.CheerStats.History
}

func (t *TwitchStats) LoadChannelPointTotal() int {
	return t.ChannelPoinsts.TotalTimes
}

func (t *TwitchStats) LoadChannelPointTimes(title ChannelPointTitle) int {
	if _, exists := t.ChannelPoinsts.Record[title]; exists {
		return t.ChannelPoinsts.Record[title]
	} else {
		return 0
	}
}
