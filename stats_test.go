package main

import "testing"

func TestTwitchStats(t *testing.T) {
	sut := NewTwitchStats()
	if sut.NumOfChats != 0 {
		t.Errorf("invalid initializing [n:%v]", sut.NumOfChats)
	}
}
