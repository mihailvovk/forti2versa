package forti2versa

// FGCategoryToVersa maps FortiGate/FortiGuard category IDs to Versa predefined URL category slugs.
// Source: FortiGuard https://www.fortiguard.com/webfilter/categories
// Versa: https://docs.versa-networks.com/Secure_SD-WAN/01_Configuration_from_Director/Security_Configuration/Configure_URL_Filtering
var FGCategoryToVersa = map[int]string{
	// --- Potentially Liable ---
	1:  "abused_drugs",
	3:  "hacking",
	4:  "illegal",
	5:  "hate_and_racism",
	6:  "violence",
	12: "hate_and_racism", // Extremist Groups
	59: "proxy_avoid_and_anonymizers",
	62: "cheating",  // Plagiarism
	83: "illegal",   // Child Sexual Abuse
	96: "illegal",   // Terrorism
	98: "spyware_and_adware",  // Crypto Mining
	99: "spyware_and_adware",  // Potentially Unwanted Program

	// --- Adult / Mature Content ---
	2:  "religion",            // Alternative Beliefs
	7:  "abortion",
	8:  "adult_and_pornography", // Other Adult Materials
	9:  "philosophy_and_political_advocacy", // Advocacy Organizations
	11: "gambling",
	13: "nudity",
	14: "adult_and_pornography", // Pornography
	15: "dating",
	16: "weapons",
	57: "marijuana",
	63: "sex_education",
	64: "alcohol_and_tobacco",
	65: "alcohol_and_tobacco",
	66: "swimsuits_and_intimate_apparel",
	67: "hunting_and_fishing", // Sports Hunting and War Games

	// --- Bandwidth Consuming ---
	19: "shareware_and_freeware",
	24: "personal_storage",
	25: "streaming_media",
	72: "peer_to_peer",
	75: "streaming_media",          // Internet Radio and TV
	76: "internet_communications",  // Internet Telephony

	// --- Security Risk ---
	26: "malware_sites",
	61: "phishing_and_other_frauds",
	86: "spam_urls",
	88: "dynamic_comment",             // Dynamic DNS
	90: "unconfirmed_spam_sources",    // Newly Observed Domain
	91: "unconfirmed_spam_sources",    // Newly Registered Domain

	// --- General Interest - Personal ---
	17: "web_advertisements",
	18: "stock_advice_and_tools",
	20: "games",
	23: "web_based_email",
	28: "entertainment_and_arts",
	29: "entertainment_and_arts",
	30: "educational_institutions",
	33: "health_and_medicine",
	34: "job_search",
	35: "health_and_medicine",
	36: "news_and_media",
	37: "social_network",
	38: "philosophy_and_political_advocacy",
	39: "reference_and_research",
	40: "religion",
	42: "shopping",
	44: "society",
	46: "sports",
	47: "travel",
	48: "motor_vehicles",
	54: "dynamic_comment",
	55: "dead_sites",
	58: "society",           // Folklore
	68: "internet_communications",
	69: "internet_communications",
	70: "internet_communications",
	71: "online_greeting_cards",
	77: "kids",
	78: "real_estate",
	79: "food_and_dining",
	80: "personal_sites_and_blogs",
	85: "parked_domains",
	87: "proxy_avoid_and_anonymizers", // Personal Privacy
	89: "auctions",

	// --- General Interest - Business ---
	41:  "search_engines",
	43:  "business_and_economy",
	49:  "business_and_economy",
	50:  "computer_and_internet_security",
	51:  "government",
	52:  "computer_and_internet_info",
	53:  "military",
	56:  "web_hosting_sites",
	81:  "computer_and_internet_security",
	82:  "cdns",
	84:  "computer_and_internet_info",
	92:  "society",           // Charitable Organizations
	93:  "proxy_avoid_and_anonymizers", // Remote Access
	94:  "web_advertisements", // Web Analytics
	95:  "internet_communications", // Online Meeting
	97:  "dynamic_comment",   // URL Shortening
	100: "generative_ai",
	101: "financial_services", // Cryptocurrency

	// --- Special ---
	0: "uncategorized",
}
