package main

import "testing"

func TestConfigLoad(t *testing.T) {
	raw := []byte(`SUBSCRIBE_USER: user1
CHART_TARGETS:
  - user2
  - user3
AUTH_CODE: auth
CLIENT_ID: client
`)
	if c, e := loadConfigFrom(raw); e != nil {
		t.Errorf("load error [%v]", e.Error())
	} else {
		if c.TargetUser != "user1" {
			t.Errorf("load error user1 != %v", c.TargetUser)
		}
		if len(c.ChatTargets) != 2 {
			t.Errorf("load error 2 != %v", len(c.ChatTargets))
		}
		if c.ChatTargets[0] != "user2" {
			t.Errorf("load error user2 != %v", c.ChatTargets[0])
		}
		if c.ChatTargets[1] != "user3" {
			t.Errorf("load error user3 != %v", c.ChatTargets[1])
		}
	}

}
