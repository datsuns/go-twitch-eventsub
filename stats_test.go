package main

import (
	"testing"
	"time"
)

func TestTwitchStats_Clear(t *testing.T) {
	sut := NewTwitchStats()
	if sut.ChatStats.Total != 0 {
		t.Errorf("invalid initializing [n:%v]", sut.ChatStats.Total)
	}

	sut.ViewersHistory = append(sut.ViewersHistory, ViewerStats{Time: time.Now(), Total: 10})
	if len(sut.ViewersHistory) == 0 {
		t.Errorf("invalid initializing [n:%v]", sut.ChatStats.Total)
	}

	sut.Clear()
	if len(sut.ViewersHistory) != 0 {
		t.Errorf("invalid Clear [n:%v]", len(sut.ViewersHistory))
	}
}

func TestTwitchStats_StartFinish(t *testing.T) {
	sut := NewTwitchStats()
	sut.StreamStarted()
	time.Sleep(1 * time.Millisecond)
	sut.StreamFinished()
	if sut.LoadPeriod() == 0 {
		t.Errorf("invalid period [n:%v]", sut.LoadPeriod())
	}
}

func TestTwitchStats_Chatting(t *testing.T) {
	sut := NewTwitchStats()
	sut.StreamStarted()
	sut.Chat("bob", "hi hello")
	if sut.LoadNChats() != 1 {
		t.Errorf("invalid chat total [n:%v]", sut.LoadNChats())
	}
	sut.Chat("Tom", "morning")
	if sut.LoadNChats() != 2 {
		t.Errorf("invalid chat total [n:%v]", sut.LoadNChats())
	}
	sut.StreamFinished()
}

func TestTwitchStats_ChannelPoint(t *testing.T) {
	sut := NewTwitchStats()
	sut.StreamStarted()

	user1 := UserName("user1")
	user2 := UserName("user2")
	title := ChannelPointTitle("にほんごのタイトル")
	title2 := ChannelPointTitle("べつのタイトル")

	sut.ChannelPoint(user1, title)
	if sut.LoadChannelPointTotal() != 1 {
		t.Errorf("invalid channel points total [n:%v]", sut.LoadChannelPointTotal())
	}
	if sut.LoadChannelPointTimes(user1) != 1 {
		t.Errorf("invalid channel points times [n:%v]", sut.LoadChannelPointTimes(user1))
	}
	if sut.LoadChannelPointTimes(user2) != 0 {
		t.Errorf("invalid channel points times(2) [n:%v]", sut.LoadChannelPointTimes(user2))
	}

	sut.ChannelPoint(user2, title2)
	if sut.LoadChannelPointTotal() != 2 {
		t.Errorf("invalid channel points total [n:%v]", sut.LoadChannelPointTotal())
	}
	if sut.LoadChannelPointTimes(user1) != 1 {
		t.Errorf("invalid channel points times [n:%v]", sut.LoadChannelPointTimes(user1))
	}
	if sut.LoadChannelPointTimes(user2) != 1 {
		t.Errorf("invalid channel points times(2) [n:%v]", sut.LoadChannelPointTimes(user2))
	}

	sut.ChannelPoint(user2, title2)
	if sut.LoadChannelPointTotal() != 3 {
		t.Errorf("invalid channel points total [n:%v]", sut.LoadChannelPointTotal())
	}
	if sut.LoadChannelPointTimes(user1) != 1 {
		t.Errorf("invalid channel points times [n:%v]", sut.LoadChannelPointTimes(user1))
	}
	if sut.LoadChannelPointTimes(user2) != 2 {
		t.Errorf("invalid channel points times(2) [n:%v]", sut.LoadChannelPointTimes(user2))
	}

	sut.StreamFinished()
}

func TestTwitchStats_ChannelCheer(t *testing.T) {
	var h map[UserName]CheerRecord
	sut := NewTwitchStats()
	sut.StreamStarted()

	user1 := UserName("user1")
	user2 := UserName("user2")

	if sut.LoadCheerTotal() != 0 {
		t.Errorf("invalid cheer total [n:%v]", sut.LoadCheerTotal())
	}

	sut.Cheer(user1, 10)
	h = sut.LoadCheerHistory()
	if sut.LoadCheerTotal() != 10 {
		t.Errorf("invalid cheer total [n:%v]", sut.LoadCheerTotal())
	}
	if h[user1].Bits != 10 {
		t.Errorf("invalid user1 cheer [n:%v]", h[user1].Bits)
	}
	if h[user1].Times != 1 {
		t.Errorf("invalid user1 times [n:%v]", h[user1].Times)
	}

	sut.Cheer(user2, 100)
	h = sut.LoadCheerHistory()
	if sut.LoadCheerTotal() != 110 {
		t.Errorf("invalid cheer total [n:%v]", sut.LoadCheerTotal())
	}
	if h[user1].Bits != 10 {
		t.Errorf("invalid user1 cheer [n:%v]", h[user1].Bits)
	}
	if h[user1].Times != 1 {
		t.Errorf("invalid user1 times [n:%v]", h[user1].Times)
	}
	if h[user2].Bits != 100 {
		t.Errorf("invalid user1 cheer [n:%v]", h[user2].Bits)
	}
	if h[user2].Times != 1 {
		t.Errorf("invalid user1 times [n:%v]", h[user2].Times)
	}

	sut.Cheer(user1, 1000)
	h = sut.LoadCheerHistory()
	if sut.LoadCheerTotal() != 1110 {
		t.Errorf("invalid cheer total [n:%v]", sut.LoadCheerTotal())
	}
	if h[user1].Bits != 1010 {
		t.Errorf("invalid user1 cheer [n:%v]", h[user1].Bits)
	}
	if h[user1].Times != 2 {
		t.Errorf("invalid user1 times [n:%v]", h[user1].Times)
	}
	if h[user2].Bits != 100 {
		t.Errorf("invalid user1 cheer [n:%v]", h[user2].Bits)
	}
	if h[user2].Times != 1 {
		t.Errorf("invalid user1 times [n:%v]", h[user2].Times)
	}

	sut.StreamFinished()
}
