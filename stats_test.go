package main

import (
	"testing"
	"time"
)

func TestTwitchStats(t *testing.T) {
	sut := NewTwitchStats()
	if sut.NumOfChats != 0 {
		t.Errorf("invalid initializing [n:%v]", sut.NumOfChats)
	}

	sut.ViewersHistory = append(sut.ViewersHistory, ViewerStats{Time: time.Now(), Total: 10})
	if len(sut.ViewersHistory) == 0 {
		t.Errorf("invalid initializing [n:%v]", sut.NumOfChats)
	}

	sut.Clear()
	if len(sut.ViewersHistory) != 0 {
		t.Errorf("invalid Clear [n:%v]", len(sut.ViewersHistory))
	}
}
