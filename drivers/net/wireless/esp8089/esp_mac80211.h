/* Copyright (c) 2008 -2014 Espressif System.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *
 *     MAC80211 support module
 */
#ifndef _ESP_MAC80211_H_
#define _ESP_MAC80211_H_
#include <linux/ieee80211.h>

/*MGMT --------------------------------------------------------- */
struct esp_80211_deauth {
	struct ieee80211_hdr_3addr hdr;
	u16 reason_code;
};

/*CONTROL --------------------------------------------------------- */

/*DATA --------------------------------------------------------- */
struct esp_80211_nulldata {
	struct ieee80211_hdr_3addr hdr;
};

enum esp_80211_phy_type {
	PHY_TYPE_CCK,
	PHY_TYPE_OFDM,
};

/*IE --------------------------------------------------------- */
struct esp_80211_wmm_ac_param {
	u8 aci_aifsn; 		/* AIFSN, ACM, ACI */
	u8 cw; 		/* ECWmin, ECWmax (CW = 2^ECW - 1) */
	u16 txop_limit;
};

struct esp_80211_wmm_param_element {
	/* Element ID： 221 (0xdd); length: 24 */
	/* required fields for WMM version 1 */
	u8 oui[3]; 		/* 00:50:f2 */
	u8 oui_type; 		/* 2 */
	u8 oui_subtype; 	/* 1 */
	u8 version; 		/* 1 for WMM version 1.0 */
	u8 qos_info; 		/* AP/STA specif QoS info */
	u8 reserved; 		/* 0 */
	struct esp_80211_wmm_ac_param ac[4]; /* AC_BE, AC_BK, AC_VI, AC_VO */
};

#endif /* _ESP_MAC80211_H_ */
