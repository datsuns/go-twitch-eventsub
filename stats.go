package main

import (
	"fmt"
	"io"
	"time"
)

type UserName string
type ChannelPointTitle string

type PeriodStats struct {
	Started  time.Time
	Finished time.Time
}

type FollowStats struct {
	Users []UserName
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

type BitsRecord struct {
	Bits  int
	Times int
}

type CheerStats struct {
	TotalBits int
	History   map[UserName]BitsRecord
}

type SubGiftStats struct {
	TotalBits int
	History   map[UserName]BitsRecord
}

type SubScriptionEntry struct {
	Tier string
}

type SubScriptionStats struct {
	Entry map[UserName]SubScriptionEntry
}

type ChannelPointStats struct {
	TotalTimes int
	Record     map[UserName]int
}

type RaidEntry struct {
	From    UserName
	Viewers int
}

type RaidStats struct {
	History []RaidEntry
}

type TwitchStats struct {
	InStreaming       bool
	LastPeriod        PeriodStats
	FollowStats       FollowStats
	ChatStats         ChatStats
	CheerStats        CheerStats
	SubScriptionStats SubScriptionStats
	SubGiftStats      SubGiftStats
	ViewersHistory    []ViewerStats
	ChannelPoinsts    ChannelPointStats
	RaidStats         RaidStats
}

func NewTwitchStats() *TwitchStats {
	ret := &TwitchStats{}
	ret.Clear()
	return ret
}

func (t *TwitchStats) Clear() {
	t.InStreaming = false
	t.FollowStats.Users = []UserName{}
	t.ChatStats = ChatStats{
		Total: 0,
	}
	t.CheerStats = CheerStats{
		TotalBits: 0,
		History:   map[UserName]BitsRecord{},
	}
	t.SubScriptionStats = SubScriptionStats{
		Entry: map[UserName]SubScriptionEntry{},
	}
	t.SubGiftStats = SubGiftStats{
		TotalBits: 0,
		History:   map[UserName]BitsRecord{},
	}
	t.ViewersHistory = []ViewerStats{}
	t.ChannelPoinsts = ChannelPointStats{
		TotalTimes: 0,
		Record:     map[UserName]int{},
	}
	t.RaidStats = RaidStats{
		History: []RaidEntry{},
	}
}

func (t *TwitchStats) String() string {
	raidTimes, raidTotal := t.LoadRaidResult()
	started := t.LastPeriod.Started.Format("2006/01/02 15:04:05")
	finished := t.LastPeriod.Finished.Format("2006/01/02 15:04:05")
	return fmt.Sprintf(
		"------\n"+
			"  配信時間: %v ~ %v\n"+
			"  新規フォロー: %v人\n"+
			"  チャネポ回数: %v\n"+
			"  新規サブスク: %v人\n"+
			"  ビッツ: %v\n"+
			"  レイド: %v回 (視聴者数:%v人)\n",
		started, finished,
		len(t.FollowStats.Users),
		t.LoadChannelPointTotal(),
		len(t.LoadSubScribed()),
		t.LoadCheerTotal(),
		raidTimes, raidTotal,
	)
}

func (t *TwitchStats) Dump(w io.Writer) {
	w.Write([]byte(t.String() + "\n"))
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

func (t *TwitchStats) Follow(user UserName) {
	if t.InStreaming == false {
		return
	}
	t.FollowStats.Users = append(t.FollowStats.Users, user)
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
	if _, exists := t.ChannelPoinsts.Record[user]; exists {
		t.ChannelPoinsts.Record[user] += 1
	} else {
		t.ChannelPoinsts.Record[user] = 1
	}
}

func (t *TwitchStats) Cheer(user UserName, n int) {
	t.CheerStats.TotalBits += n
	if v, exists := t.CheerStats.History[user]; exists {
		v.Bits += n
		v.Times += 1
		t.CheerStats.History[user] = v
	} else {
		t.CheerStats.History[user] = BitsRecord{Bits: n, Times: 1}
	}
}

func (t *TwitchStats) SubGift(user UserName, n int) {
	t.SubGiftStats.TotalBits += n
	if v, exists := t.SubGiftStats.History[user]; exists {
		v.Bits += n
		v.Times += 1
		t.SubGiftStats.History[user] = v
	} else {
		t.SubGiftStats.History[user] = BitsRecord{Bits: n, Times: 1}
	}
}

func (t *TwitchStats) SubScribe(user UserName, tier string) {
	if v, exists := t.SubScriptionStats.Entry[user]; exists {
		v.Tier = tier
		t.SubScriptionStats.Entry[user] = v
	} else {
		t.SubScriptionStats.Entry[user] = SubScriptionEntry{Tier: tier}
	}
}

func (t *TwitchStats) Raid(from UserName, viewers int) {
	t.RaidStats.History = append(
		t.RaidStats.History,
		RaidEntry{From: from, Viewers: viewers},
	)
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

func (t *TwitchStats) LoadCheerHistory() map[UserName]BitsRecord {
	return t.CheerStats.History
}

func (t *TwitchStats) LoadSubGiftTotal() int {
	return t.SubGiftStats.TotalBits
}

func (t *TwitchStats) LoadSubGiftHistory() map[UserName]BitsRecord {
	return t.SubGiftStats.History
}

func (t *TwitchStats) LoadSubScribed() map[UserName]SubScriptionEntry {
	return t.SubScriptionStats.Entry
}

func (t *TwitchStats) LoadChannelPointTotal() int {
	return t.ChannelPoinsts.TotalTimes
}

func (t *TwitchStats) LoadChannelPointTimes(user UserName) int {
	if _, exists := t.ChannelPoinsts.Record[user]; exists {
		return t.ChannelPoinsts.Record[user]
	} else {
		return 0
	}
}

func (t *TwitchStats) LoadRaidResult() (int, int) {
	times := len(t.RaidStats.History)
	total := 0
	for _, e := range t.RaidStats.History {
		total += e.Viewers
	}
	return times, total
}
