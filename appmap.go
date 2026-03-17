package forti2versa

// FGAppCategoryToVersa maps FortiGate application category IDs to Versa
// predefined application-filter names.
// Source: FortiGuard application categories, Versa predefined application filters.
var FGAppCategoryToVersa = map[int]string{
	2:  "P2P",
	3:  "VOIP",
	5:  "Audio-Video-Streaming",
	6:  "High-Risk-Applications", // Proxy
	7:  "High-Risk-Applications", // Remote.Access
	8:  "Gaming",
	12: "Non-Business-Traffic",   // General.Interest
	15: "Business-Traffic",       // Network.Service
	17: "Software-Updates",       // Update
	19: "High-Risk-Applications", // Botnet
	21: "Business-Traffic",       // Email
	22: "File-Transfer",          // Storage.Backup
	23: "Non-Business-Traffic",   // Social.Media
	24: "File-Transfer",          // File.Sharing
	25: "Web-Browsing",           // Web.Others / Web.Client
	26: "IOT",                    // Industrial
	28: "SaaS-Applications",      // Collaboration
	29: "Business-Traffic",       // Business
	30: "SaaS-Applications",      // Cloud.IT
	31: "Mobile-Traffic",         // Mobile
}

// FGAppIDToVersa maps well-known FortiGate application signature IDs to Versa
// predefined-application names. This covers common apps found in FortiGate configs.
// Versa application names are UPPER_CASE with underscores.
var FGAppIDToVersa = map[int]string{
	// P2P / File sharing
	15832: "BITTORRENT",
	15834: "EDONKEY",
	16276: "ARES",
	16554: "GNUTELLA",
	15841: "KAZAA",
	35498: "UTORRENT",

	// Social media
	33:    "HTTP",
	15895: "FACEBOOK",
	32880: "TWITTER",
	31322: "INSTAGRAM",
	15888: "LINKEDIN",
	40463: "TIKTOK",
	40568: "SNAPCHAT",

	// Messaging / VoIP
	15847: "SKYPE",
	46498: "WHATSAPP",
	48756: "TELEGRAM",
	36498: "VIBER",
	31077: "LINE",
	45430: "DISCORD",
	37182: "ZOOM",
	34577: "WEBEX",

	// Streaming
	15891: "YOUTUBE",
	15897: "NETFLIX",
	15836: "SPOTIFY",
	40579: "DISNEY_PLUS",
	15842: "HULU",
	45903: "AMAZON_VIDEO",

	// Cloud / SaaS
	15893: "GOOGLE",
	16198: "DROPBOX",
	35181: "BOX_NET",
	42182: "ONEDRIVE",
	15894: "AMAZON",
	39174: "SALESFORCE",
	15906: "GITHUB",
	41468: "SLACK",
	35381: "ASANA",
	38195: "TRELLO",

	// Gaming
	33622: "STEAM",
	41495: "FORTNITE",
	48372: "ROBLOX",
	15843: "WOW",
	34741: "LOL_GAME",
	47682: "MINECRAFT",

	// Remote access
	15907: "TEAMVIEWER",
	33181: "LOGMEIN",
	15905: "SSH",
	15904: "RDP",
	30988: "ANYDESK",

	// Email
	15896: "GMAIL",
	15853: "OUTLOOK",

	// VPN / Proxy
	44198: "OPENVPN",
	40650: "WIREGUARD",
	16068: "TOR",
	15900: "ULTRASURF",
}
