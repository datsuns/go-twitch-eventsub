package main

import "time"

type TwitchViewer struct {
	Time *time.Time
	Name string
}

type TwitchChannelPoint struct {
	TotalTimes int
	Entry      []struct {
		Name  string
		Times int
	}
}

type TwitchStats struct {
	NumOfChats     int
	ViewersHistory []TwitchViewer
	ChannelPoinsts []TwitchChannelPoint
}

func NewTwitchStats() *TwitchStats {
	return &TwitchStats{
		NumOfChats:     0,
		ViewersHistory: []TwitchViewer{},
		ChannelPoinsts: []TwitchChannelPoint{},
	}
}
