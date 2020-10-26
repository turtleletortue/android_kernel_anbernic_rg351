/* Copyright (c) 2008 -2014 Espressif System.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef _ESP_WL_H_
#define _ESP_WL_H_

//#define MAX_PROBED_SSID_INDEX 9

enum {
        CONF_HW_BIT_RATE_1MBPS   = BIT(0),
        CONF_HW_BIT_RATE_2MBPS   = BIT(1),
        CONF_HW_BIT_RATE_5_5MBPS = BIT(2),
        CONF_HW_BIT_RATE_11MBPS  = BIT(3),
        CONF_HW_BIT_RATE_6MBPS   = BIT(4),
        CONF_HW_BIT_RATE_9MBPS   = BIT(5),
        CONF_HW_BIT_RATE_12MBPS  = BIT(6),
        CONF_HW_BIT_RATE_18MBPS  = BIT(7),
        CONF_HW_BIT_RATE_22MBPS  = BIT(8),
        CONF_HW_BIT_RATE_24MBPS  = BIT(9),
        CONF_HW_BIT_RATE_36MBPS  = BIT(10),
        CONF_HW_BIT_RATE_48MBPS  = BIT(11),
        CONF_HW_BIT_RATE_54MBPS  = BIT(12),
	CONF_HW_BIT_RATE_11B_MASK = (CONF_HW_BIT_RATE_1MBPS | CONF_HW_BIT_RATE_2MBPS | CONF_HW_BIT_RATE_5_5MBPS | CONF_HW_BIT_RATE_11MBPS),
};


#endif /* _ESP_WL_H_ */
