package main

// --- request

type RequestCondition struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
}

type RequestConditionWithModerator struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
	ModeratorUserId   string `json:"moderator_user_id"`
}

type RequestConditionWithUser struct {
	BroadcasterUserId string `json:"broadcaster_user_id"`
	UserId            string `json:"user_id"`
}

type SubscriptionTransport struct {
	Method    string `json:"method"`
	Callback  string `json:"callback"`
	Secret    string `json:"secret"`
	SessionId string `json:"session_id"`
	ConduitId string `json:"conduit_id"`
}
type CreateSubscriptionBody struct {
	Type      string                `json:"type"`
	Version   string                `json:"version"`
	Condition RequestCondition      `json:"condition"`
	Transport SubscriptionTransport `json:"transport"`
}

type CreateSubscriptionBodyWithModerator struct {
	Type      string                        `json:"type"`
	Version   string                        `json:"version"`
	Condition RequestConditionWithModerator `json:"condition"`
	Transport SubscriptionTransport         `json:"transport"`
}

type CreateSubscriptionBodyWithUser struct {
	Type      string                   `json:"type"`
	Version   string                   `json:"version"`
	Condition RequestConditionWithUser `json:"condition"`
	Transport SubscriptionTransport    `json:"transport"`
}

// --- responce

type GetUsersApiResponce struct {
	Data []struct {
		Id          string `json:"id"`
		Login       string `json:"login"`
		DisplayName string `json:"display_name"`
	} `json:"data"`
}

type GetClipsApiResponce struct {
	Data []struct {
		Id              string  `json:"id"`
		Url             string  `json:"url"`
		EmbedUrl        string  `json:"embed_url"`
		BroadcasterId   string  `json:"broadcaster_id"`
		BroadcasterName string  `json:"broadcaster_name"`
		CreatorId       string  `json:"creator_id"`
		CreatorName     string  `json:"creator_name"`
		VideoId         string  `json:"video_id"`
		GameId          string  `json:"game_id"`
		Language        string  `json:"language"`
		Title           string  `json:"title"`
		ViewCount       int     `json:"view_count"`
		CreatedAt       string  `json:"created_at"`
		ThumbnailUrl    string  `json:"thumbnail_url"`
		Duration        float32 `json:"duration"`
		VodOffset       int     `json:"vod_offset"`
		IsFeatured      bool    `json:"is_featured"`
	} `json:"data"`
}

// --- EventSub notification

type MetadataFormat struct {
	MessageId           string `json:"message_id"`
	MessageType         string `json:"message_type"`
	MessageTimestamp    string `json:"message_timestamp"`
	SubscriptionType    string `json:"subscription_type"`
	SubscriptionVersion string `json:"subscription_version"`
}

type SessionFormat struct {
	Id        string `json:"id"`
	Status    string `json:"status"`
	At        string `json:"connected_at"`
	KeepAlive int    `json:"keepalive_timeout_seconds"`
	ReconnUrl string `json:"reconnect_url"`
}

type SubscriptionFormat struct {
	Id        string `json:"id"`
	Status    string `json:"status"`
	Type      string `json:"type"`
	Version   string `json:"version"`
	Cost      int    `json:"cost"`
	Condition struct {
		BroadcasterUserId string `json:"broadcaster_user_id"`
	} `json:"condition"`
	Transport struct {
		Method    string `json:"method"`
		SessionId string `json:"session_id"`
	} `json:"transport"`
	CreatedAt string `json:"created_at"`
}

// https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types/
type EventFormatCommon struct {
	UserId               string `json:"user_id"`
	UserLogin            string `json:"user_login"`
	UserName             string `json:"user_name"`
	BroadcasterUserId    string `json:"broadcaster_user_id"`
	BroadcasterUserLogin string `json:"broadcaster_user_login"`
	BroadcasterUserName  string `json:"broadcaster_user_name"`
}

type PayloadFormatCommon struct {
	Session      SessionFormat      `json:"session"`
	Subscription SubscriptionFormat `json:"subscription"`
	Event        EventFormatCommon  `json:"event"`
}

type Responce struct {
	Metadata MetadataFormat      `json:"metadata"`
	Payload  PayloadFormatCommon `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChatMessage struct {
	BroadcasterUserId    string `json:"broadcaster_user_id"`
	BroadcasterUserLogin string `json:"broadcaster_user_login"`
	BroadcasterUserName  string `json:"broadcaster_user_name"`
	ChatterUserId        string `json:"chatter_user_id"`
	ChatterUserLogin     string `json:"chatter_user_login"`
	ChatterUserName      string `json:"chatter_user_name"`
	MessageId            string `json:"message_id"`
	Message              struct {
		Text      string `json:"text"`
		Fragments []struct {
			Type      string `json:"type"`
			Text      string `json:"text"`
			Cheermote struct {
				Prefix string `json:"prefix"`
				Bits   int    `json:"bits"`
				Tier   int    `json:"tier"`
			} `json:"cheermote"`
			Emote struct {
				Id         string   `json:"id"`
				EmoteSetId string   `json:"emote_set_id"`
				OwnerId    string   `json:"owner_id"`
				Format     []string `json:"format"`
			} `json:"emote"`
			Mention struct {
				UserId    string `json:"user_id"`
				UserName  string `json:"user_name"`
				UserLogin string `json:"user_login"`
			} `json:"mention"`
		} `json:"fragments"`
	} `json:"message"`
	Color  string `json:"color"`
	Badges []struct {
		SetId string `json:"set_id"`
		Id    string `json:"id"`
		Info  string `json:"info"`
	} `json:"badges"`
	MessageType string `json:"message_type"`
	Cheer       struct {
		Bits  int    `json:"bits"`
		Color string `json:"color"`
	} `json:"cheer"`
	Reply struct {
		ParentMessageId   string `json:"parent_message_id"`
		ParentMessageBody string `json:"parent_message_body"`
		ParentUserId      string `json:"parent_user_id"`
		ParentUserName    string `json:"parent_user_name"`
		ParentUserLogin   string `json:"parent_user_login"`
		ThreadMessageId   string `json:"thread_message_id"`
		ThreadUserId      string `json:"thread_user_id"`
		ThreadUserName    string `json:"thread_user_name"`
		ThreadUserLogin   string `json:"thread_user_login"`
	} `json:"reply"`
	ChannelPointsCustomRewardId string `json:"channel_points_custom_reward_id"`
}

type PayloadFormatChatMessage struct {
	Session      SessionFormat          `json:"session"`
	Subscription SubscriptionFormat     `json:"subscription"`
	Event        EventFormatChatMessage `json:"event"`
}

type ResponceChatMessage struct {
	Metadata MetadataFormat           `json:"metadata"`
	Payload  PayloadFormatChatMessage `json:"payload"`
}

// --------------------------------------------------------
// https://dev.twitch.tv/docs/eventsub/eventsub-reference/#channel-chat-notification-event
type EventFormatChannelChatNotification struct {
	BroadcasterUserId    string `json:"broadcaster_user_id"`
	BroadcasterUserLogin string `json:"broadcaster_user_login"`
	BroadcasterUserName  string `json:"broadcaster_user_name"`
	ChatterUserId        string `json:"chatter_user_id"`
	ChatterUserLogin     string `json:"chatter_user_login"`
	ChatterUserName      string `json:"chatter_user_name"`
	ChatterIsAnonymous   bool   `json:"chatter_is_anonymous"`
	Color                string `json:"color"`
	Badges               []struct {
		SetId string `json:"set_id"`
		Id    string `json:"id"`
		Info  string `json:"info"`
	} `json:"badges"`
	SystemMessage string `json:"system_message"`
	MessageId     string `json:"message_id"`
	Message       struct {
		Text      string `json:"text"`
		Fragments []struct {
			Type      string `json:"type"`
			Text      string `json:"text"`
			Cheermote struct {
				Prefix string `json:"prefix"`
				Bits   int    `json:"bits"`
				Tier   int    `json:"tier"`
			} `json:"cheermote"`
			Emote struct {
				Id         string   `json:"id"`
				EmoteSetId string   `json:"emote_set_id"`
				OwnerId    string   `json:"owner_id"`
				Format     []string `json:"format"`
			} `json:"emote"`
			Mention struct {
				UserId    string `json:"user_id"`
				UserName  string `json:"user_name"`
				UserLogin string `json:"user_login"`
			} `json:"mention"`
		} `json:"fragments"`
	} `json:"message"`
	NoticeType string `json:"notice_type"`
	Sub        struct {
		SubTier        string `json:"sub_tier"`
		IsPrime        bool   `json:"is_prime"`
		DurationMonths int    `json:"duration_months"`
	} `json:"sub"`
	Resub struct {
		CumulativeMonths  int    `json:"cumulative_months"`
		DurationMonths    int    `json:"duration_months"`
		StreakMonths      int    `json:"streak_months"`
		SubTier           string `json:"sub_tier"`
		IsPrime           bool   `json:"is_prime"`
		IsGift            bool   `json:"is_gift"`
		GifterIsAnonymous bool   `json:"gifter_is_anonymous"`
		GifterUserId      string `json:"gifter_user_id"`
		GifterUserName    string `json:"gifter_user_name"`
		GifterUserLogin   string `json:"gifter_user_login"`
	} `json:"resub"`
	SubGift struct {
		DurationMonths     int    `json:"duration_months"`
		CumulativeTotal    int    `json:"cumulative_total"`
		RecipientUserId    string `json:"recipient_user_id"`
		RecipientUserName  string `json:"recipient_user_name"`
		RecipientUserLogin string `json:"recipient_user_login"`
		Sub_Tier           string `json:"sub_tier"`
		CommunityGiftId    string `json:"community_gift_id"`
	} `json:"sub_gift"`
	CommunitySubGift struct {
		Id              string `json:"id"`
		Total           int    `json:"total"`
		SubTier         string `json:"sub_tier"`
		CumulativeTotal int    `json:"cumulative_total"`
	} `json:"community_sub_gift"`
	GiftPaidUpgrade struct {
		GifterIsAnonymous bool   `json:"gifter_is_anonymous"`
		GifterUserId      string `json:"gifter_user_id"`
		GifterUserName    string `json:"gifter_user_name"`
		GifterUserLogin   string `json:"gifter_user_login"`
	} `json:"gift_paid_upgrade"`
	PrimePaidUpgrade struct {
		SubTier string `json:"sub_tier"`
	} `json:"prime_paid_upgrade"`
	RaId struct {
		UserId          string `json:"user_id"`
		UserName        string `json:"user_name"`
		UserLogin       string `json:"user_login"`
		ViewerCount     int    `json:"viewer_count"`
		ProfileImageUrl string `json:"profile_image_url"`
	} `json:"raid"`
	Unraid       struct{} `json:"unraid"`
	PayItForward struct {
		GifterIsAnonymous bool   `json:"gifter_is_anonymous"`
		GifterUserId      string `json:"gifter_user_id"`
		GifterUserName    string `json:"gifter_user_name"`
		GifterUserLogin   string `json:"gifter_user_login"`
	} `json:"pay_it_forward"`
	Announcement struct {
		Color string `json:"color"`
	} `json:"announcement"`
	BitsBadgeTier struct {
		Tier int `json:"tier"`
	} `json:"bits_badge_tier"`
	CharityDonation struct {
		Charity_name string `json:"charity_name"`
		Amount       struct {
			Value         int    `json:"value"`
			DecimalPlaces int    `json:"decimal_places"`
			Currency      string `json:"currency"`
		} `json:"amount"`
	} `json:"charity_donation"`
}

type PayloadFormatChannelChatNotification struct {
	Session      SessionFormat                      `json:"session"`
	Subscription SubscriptionFormat                 `json:"subscription"`
	Event        EventFormatChannelChatNotification `json:"event"`
}

type ResponceChannelChatNotification struct {
	Metadata MetadataFormat                       `json:"metadata"`
	Payload  PayloadFormatChannelChatNotification `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChannelSubscribe struct {
	*EventFormatCommon
	IsGift bool   `json:"is_gift"`
	Tier   string `json:"tier"`
}

type PayloadFormatChannelSubscribe struct {
	Session      SessionFormat               `json:"session"`
	Subscription SubscriptionFormat          `json:"subscription"`
	Event        EventFormatChannelSubscribe `json:"event"`
}

type ResponceChannelSubscribe struct {
	Metadata MetadataFormat                `json:"metadata"`
	Payload  PayloadFormatChannelSubscribe `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChannelSubscriptionGift struct {
	*EventFormatCommon
	Total           int    `json:"total"`
	Tier            string `json:"tier"`
	CumulativeTotal int    `json:"cumulative_total"`
	IsAnonymous     bool   `json:"is_anonymous"`
}

type PayloadFormatChannelSubscriptionGift struct {
	Session      SessionFormat                      `json:"session"`
	Subscription SubscriptionFormat                 `json:"subscription"`
	Event        EventFormatChannelSubscriptionGift `json:"event"`
}

type ResponceChannelSubscriptionGift struct {
	Metadata MetadataFormat                       `json:"metadata"`
	Payload  PayloadFormatChannelSubscriptionGift `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChannelSubscriptionMessage struct {
	*EventFormatCommon
	Tier    string `json:"tier"`
	Message struct {
		Text   string `json:"text"`
		Emotes []struct {
			Begin int    `json:"begin"`
			End   int    `json:"end"`
			Id    string `json:"id"`
		} `json:"emotes"`
	} `json:"message"`
	CumulativeMonths int `json:"cumulative_months"` // 累計何か月サブスクしてくれたか？
	StreakMonths     int `json:"streak_months"`     // サブスクの継続月数
	DurationMonths   int `json:"duration_months"`   // 何か月のサブスクか？
}

type PayloadFormatChannelSubscriptionMessage struct {
	Session      SessionFormat                         `json:"session"`
	Subscription SubscriptionFormat                    `json:"subscription"`
	Event        EventFormatChannelSubscriptionMessage `json:"event"`
}

type ResponceChannelSubscriptionMessage struct {
	Metadata MetadataFormat                          `json:"metadata"`
	Payload  PayloadFormatChannelSubscriptionMessage `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChannelCheer struct {
	*EventFormatCommon
	IsAnonymous bool   `json:"is_anonymous"`
	Message     string `json:"message"`
	Bits        int    `json:"bits"`
}

type PayloadFormatChannelCheer struct {
	Session      SessionFormat           `json:"session"`
	Subscription SubscriptionFormat      `json:"subscription"`
	Event        EventFormatChannelCheer `json:"event"`
}

type ResponceChannelCheer struct {
	Metadata MetadataFormat            `json:"metadata"`
	Payload  PayloadFormatChannelCheer `json:"payload"`
}

// --------------------------------------------------------
type EventFormatStreamOnline struct {
	Id                   string `json:"id"`
	BroadcasterUserId    string `json:"broadcaster_user_id"`
	BroadcasterUserLogin string `json:"broadcaster_user_login"`
	BroadcasterUserName  string `json:"broadcaster_user_name"`
	Type                 string `json:"type"`
	StartedAt            string `json:"started_at"`
}

type PayloadFormatStreamOnline struct {
	Session      SessionFormat           `json:"session"`
	Subscription SubscriptionFormat      `json:"subscription"`
	Event        EventFormatStreamOnline `json:"event"`
}

type ResponceStreamOnline struct {
	Metadata MetadataFormat            `json:"metadata"`
	Payload  PayloadFormatStreamOnline `json:"payload"`
}

// --------------------------------------------------------
type EventFormatStreamOffline struct {
	BroadcasterUserId    string `json:"broadcaster_user_id"`
	BroadcasterUserLogin string `json:"broadcaster_user_login"`
	BroadcasterUserName  string `json:"broadcaster_user_name"`
}

type PayloadFormatStreamOffline struct {
	Session      SessionFormat            `json:"session"`
	Subscription SubscriptionFormat       `json:"subscription"`
	Event        EventFormatStreamOffline `json:"event"`
}

type ResponceStreamOffline struct {
	Metadata MetadataFormat             `json:"metadata"`
	Payload  PayloadFormatStreamOffline `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChannelPointsCustomRewardRedemptionAdd struct {
	Id string `json:"id"`
	*EventFormatCommon
	UserInput string `json:"user_input"`
	Status    string `json:"status"`
	Reward    struct {
		Id     string `json:"id"`
		Title  string `json:"title"`
		Cost   int    `json:"cost"`
		Prompt string `json:"prompt"`
	} `json:"reward"`
	RedeemedAt string `json:"redeemed_at"`
}

type PayloadFormatChannelPointsCustomRewardRedemptionAdd struct {
	Session      SessionFormat                                     `json:"session"`
	Subscription SubscriptionFormat                                `json:"subscription"`
	Event        EventFormatChannelPointsCustomRewardRedemptionAdd `json:"event"`
}

type ResponceChannelPointsCustomRewardRedemptionAdd struct {
	Metadata MetadataFormat                                      `json:"metadata"`
	Payload  PayloadFormatChannelPointsCustomRewardRedemptionAdd `json:"payload"`
}

// --------------------------------------------------------
type EventFormatChannelFollow struct {
	*EventFormatCommon
	FollowedAt string `json:"followed_at"`
}

type PayloadFormatChannelFollow struct {
	Session      SessionFormat            `json:"session"`
	Subscription SubscriptionFormat       `json:"subscription"`
	Event        EventFormatChannelFollow `json:"event"`
}

type ResponceChannelFollow struct {
	Metadata MetadataFormat             `json:"metadata"`
	Payload  PayloadFormatChannelFollow `json:"payload"`
}
