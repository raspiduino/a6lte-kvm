/*
 * s2mu005.h - Driver for the s2mu005
 *
 *  Copyright (C) 2015 Samsung Electrnoics
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * This driver is based on max8997.h
 *
 * s2mu005 has Flash LED, SVC LED, Haptic, MUIC devices.
 * The devices share the same I2C bus and included in
 * this mfd driver.
 */

#ifndef __S2MU005_H__
#define __S2MU005_H__
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/notifier.h>

#ifdef CONFIG_BATTERY_SAMSUNG_V2 
#include "../../../../drivers/battery_v2/include/sec_charging_common.h"
#else
#include <linux/battery/sec_charging_common.h> 
#endif

//#include <linux/battery/charger/s2mu005_charger.h>
//#include <linux/battery/fuelgauge/s2mu005_fuelgauge.h>

#define MFD_DEV_NAME "s2mu005"
#define M2SH(m) ((m) & 0x0F ? ((m) & 0x03 ? ((m) & 0x01 ? 0 : 1) : ((m) & 0x04 ? 2 : 3)) : \
		((m) & 0x30 ? ((m) & 0x10 ? 4 : 5) : ((m) & 0x40 ? 6 : 7)))

struct s2mu005_haptic_platform_data {
	u16 max_timeout;
	u16 duty;
	u16 period;
	u16 reg2;
	char *regulator_name;
	unsigned int pwm_id;

	void (*init_hw) (void);
	void (*motor_en) (bool);
};
extern int s2m_acok_notify_call_chain(void);

struct s2mu005_regulator_data {
	int id;
	struct regulator_init_data *initdata;
	struct device_node *reg_node;
};

typedef struct s2mu005_charger_platform_data {
	sec_charging_current_t *charging_current;
	int chg_float_voltage;
	char *charger_name;
	bool chg_eoc_dualpath;
	uint32_t is_1MHz_switching:1;
	bool always_enable;
	/* 2nd full check */
	 sec_battery_full_charged_t full_check_type_2nd;
} s2mu005_charger_platform_data_t;

struct s2mu005_platform_data {
	/* IRQ */
	int irq_base;
	int irq_gpio;
	bool wakeup;
#if defined(CONFIG_CHARGER_S2MU005)
	s2mu005_charger_platform_data_t *pdata;
#endif

	int num_regulators;
	struct s2mu005_regulator_data *regulators;
	/* haptic motor data */
	struct s2mu005_haptic_platform_data *haptic_data;
	struct mfd_cell *sub_devices;
	int num_subdevs;
};

struct s2mu005
{
	struct regmap *regmap;
};

#endif /* __S2MU005_H__ */

