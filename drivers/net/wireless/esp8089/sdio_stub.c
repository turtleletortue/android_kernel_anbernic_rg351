/* Copyright (c) 2008 -2014 Espressif System.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *
 *  sdio stub code for RK
 */

#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/moduleparam.h>


/* reset GPIO parameter defaults to GPIO 0 (ID_SD) on the Raspberry Pi */
/* default reset port of OGA hw rev 1.1 : GPIO3_B1 (105) */
static int esp_reset_gpio = 105;
module_param(esp_reset_gpio, int, 0);
MODULE_PARM_DESC(esp_reset_gpio, "ESP8089 CH_PD reset GPIO number");

#define ESP8089_DRV_VERSION "2.25"

extern int rk29sdk_wifi_power(int on);
extern int rk29sdk_wifi_set_carddetect(int val);

void sif_platform_rescan_card(unsigned insert)
{
}

void sif_platform_reset_target(void)
{
	/* set output high by default */
	printk("ESP8089 reset via GPIO %d\n", esp_reset_gpio);
	gpio_request(esp_reset_gpio,"esp_reset");
	gpio_direction_output(esp_reset_gpio, 1);
	gpio_free(esp_reset_gpio);
}

void sif_platform_target_poweroff(void)
{
	/* reset ESP before unload so that the esp can be probed on
	 * warm reboot */
	sif_platform_reset_target();
}

void sif_platform_target_poweron(void)
{
	sif_platform_reset_target();
}

void sif_platform_target_speed(int high_speed)
{
}

void sif_platform_check_r1_ready(struct esp_pub *epub)
{
}


#ifdef ESP_ACK_INTERRUPT
extern void sdmmc_ack_interrupt(struct mmc_host *mmc);

void sif_platform_ack_interrupt(struct esp_pub *epub)
{
        struct esp_sdio_ctrl *sctrl = NULL;
        struct sdio_func *func = NULL;

        ASSERT(epub != NULL);
        sctrl = (struct esp_sdio_ctrl *)epub->sif;
        func = sctrl->func;
        ASSERT(func != NULL);

        sdmmc_ack_interrupt(func->card->host);
}
#endif //ESP_ACK_INTERRUPT

late_initcall(esp_sdio_init);
module_exit(esp_sdio_exit);
