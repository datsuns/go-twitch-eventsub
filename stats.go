package main

import (
	"io"
	"time"
)

type PeriodStats struct {
	Started  *time.Time
	Finished *time.Time
}

type ViewerStats struct {
	Time  time.Time
	Total int
}

type ChannelPointStats struct {
	TotalTimes int
	Entry      []struct {
		Name  string
		Times int
	}
}

type TwitchStats struct {
	Period         PeriodStats
	NumOfChats     int
	ViewersHistory []ViewerStats
	ChannelPoinsts []ChannelPointStats
}

func NewTwitchStats() *TwitchStats {
	ret := &TwitchStats{}
	ret.Clear()
	return ret
}

func (t *TwitchStats) Clear() {
	t.NumOfChats = 0
	t.ViewersHistory = []ViewerStats{}
	t.ChannelPoinsts = []ChannelPointStats{}
}

func (t *TwitchStats) Dump(w io.Writer) {
}

func (t *TwitchStats) StreamStarted() {
	t.Clear()
}
