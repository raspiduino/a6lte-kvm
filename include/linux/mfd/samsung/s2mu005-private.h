/*
 * s2mu005-private.h - Voltage regulator driver for the s2mu005
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
 */

#ifndef __LINUX_MFD_S2MU005_PRIV_H
#define __LINUX_MFD_S2MU005_PRIV_H

#include <linux/i2c.h>

//#include <linux/battery/charger/s2mu005_charger.h>
//#include <linux/battery/fuelgauge/s2mu005_fuelgauge.h>

#define S2MU005_I2C_ADDR		(0x7A)
#define S2MU005_REG_INVALID		(0xff)

enum s2mu005_reg {
	/* Slave addr = 0x7A */
	S2MU005_REG_SC_INT,
	S2MU005_REG_SC_INT_MASK,
	S2MU005_REG_FLED_INT,
	S2MU005_REG_FLED_INT_MASK,
	S2MU005_REG_MUIC_INT1,
	S2MU005_REG_MUIC_INT2,
	S2MU005_REG_MUIC_INT1_MASK,
	S2MU005_REG_MUIC_INT2_MASK,

	S2MU005_REG_SC_STATUS0,
	S2MU005_REG_SC_STATUS1,
	S2MU005_REG_SC_STATUS2,
	S2MU005_REG_SC_STATUS3,
	S2MU005_REG_SC_STATUS4,
	S2MU005_REG_SC_STATUS5,
	S2MU005_REG_SC_CTRL0,
	S2MU005_REG_SC_CTRL1,
	S2MU005_REG_SC_CTRL2,
	S2MU005_REG_SC_CTRL3,
	S2MU005_REG_SC_CTRL4,
	S2MU005_REG_SC_CTRL5,
	S2MU005_REG_SC_CTRL6,
	S2MU005_REG_SC_CTRL7,
	S2MU005_REG_SC_CTRL8,
	S2MU005_REG_SC_CTRL9,
	S2MU005_REG_SC_CTRL10,
	S2MU005_REG_SC_CTRL11,
	S2MU005_REG_SC_CTRL12,
	S2MU005_REG_SC_CTRL13,
	S2MU005_REG_SC_CTRL14,
	S2MU005_REG_SC_CTRL15,
	S2MU005_REG_SC_CTRL16,
	S2MU005_REG_SC_CTRL17,
	S2MU005_REG_SC_CTRL18,
	S2MU005_REG_SC_RSVD21,
	S2MU005_REG_SC_TEST0,
	S2MU005_REG_SC_TEST1,
	S2MU005_REG_SC_TEST2,
	S2MU005_REG_SC_TEST3,
	S2MU005_REG_SC_TEST4,
	S2MU005_REG_SC_TEST5,
	S2MU005_REG_SC_TEST6,
	S2MU005_REG_SC_TEST7,
	S2MU005_REG_SC_TEST8,
	S2MU005_REG_SC_RSVD2B,
	S2MU005_REG_SC_TEST10,

	S2MU005_REG_FLED_STATUS,
	S2MU005_REG_FLED_CH1_CTRL0,
	S2MU005_REG_FLED_CH1_CTRL1,
	S2MU005_REG_FLED_CH1_CTRL2,
	S2MU005_REG_FLED_CH1_CTRL3,
	S2MU005_REG_FLED_CH2_CTRL0,
	S2MU005_REG_FLED_CH2_CTRL1,
	S2MU005_REG_FLED_CH2_CTRL2,
	S2MU005_REG_FLED_CH2_CTRL3,
	S2MU005_REG_FLED_CTRL0,
	S2MU005_REG_FLED_CTRL1,
	S2MU005_REG_FLED_CTRL2,
	S2MU005_REG_FLED_CTRL3,
	S2MU005_REG_FLED_CTRL4,
	S2MU005_REG_FLED_TEST0,
	S2MU005_REG_FLED_RSVD,
	S2MU005_REG_LED_EN,
	S2MU005_REG_LED1_CURRENT,
	S2MU005_REG_LED2_CURRENT,
	S2MU005_REG_LED3_CURRENT,
	S2MU005_REG_LED1_RAMP,
	S2MU005_REG_LED1_DUR,
	S2MU005_REG_LED2_RAMP,
	S2MU005_REG_LED2_DUR,
	S2MU005_REG_LED3_RAMP,
	S2MU005_REG_LED3_DUR,
	S2MU005_REG_LED_TEST0,
	S2MU005_REG_LED_CTRL0,

	S2MU005_REG_MUIC_ADC,
	S2MU005_REG_MUIC_DEVICE_TYPE1,
	S2MU005_REG_MUIC_DEVICE_TYPE2,
	S2MU005_REG_MUIC_DEVICE_TYPE3,
	S2MU005_REG_MUIC_BUTTON1,
	S2MU005_REG_MUIC_BUTTON2,
	S2MU005_REG_MUIC_RESET,
	S2MU005_REG_MUIC_CHG_TYPE,
	S2MU005_REG_MUIC_DEVICE_APPLE,
	S2MU005_REG_MUIC_BCD_RESCAN,
	S2MU005_REG_MUIC_TEST1,
	S2MU005_REG_MUIC_TEST2,
	S2MU005_REG_MUIC_TEST3,
	S2MU005_REG_MUIC_RSVD56,

	S2MU005_REG_COMMON_CFG1,
	S2MU005_REG_COMMON_CFG2,
	S2MU005_REG_MRSTB,
	S2MU005_REG_PWRSEL_CTRL0,
	S2MU005_REG_RSVD5B,
	S2MU005_REG_RSVD5C,
	S2MU005_REG_RSVD5D,
	S2MU005_REG_SELFDIS_CFG1,
	S2MU005_REG_SELFDIS_CFG2,
	S2MU005_REG_SELFDIS_CFG3,
	S2MU005_REG_RSVD61,

	S2MU005_REG_REV_ID = 0x73,

	S2MU005_REG_MUIC_CTRL1 = 0xB2,
	S2MU005_REG_MUIC_TIMER_SET1,
	S2MU005_REG_MUIC_TIMER_SET2,
	S2MU005_REG_MUIC_SW_CTRL,
	S2MU005_REG_MUIC_TIMER_SET3,
	S2MU005_REG_MUIC_CTRL2,
	S2MU005_REG_MUIC_CTRL3,

	S2MU005_REG_MUIC_LDOADC_VSETL = 0xBF,
	S2MU005_REG_MUIC_LDOADC_VSETH = 0xC0,

	S2MU005_REG_END,
};

enum s2mu005_irq_source {
	CHG_INT = 0,
	FLED_INT,
	MUIC_INT1,
	MUIC_INT2,

	S2MU005_IRQ_GROUP_NR,
};

#define MUIC_MAX_INT			MUIC_INT2
#define S2MU005_NUM_IRQ_MUIC_REGS	(MUIC_MAX_INT - MUIC_INT1 + 1)

enum s2mu005_irq {

	S2MU005_CHG_IRQ_DET_BAT,
	S2MU005_CHG_IRQ_BAT,
	S2MU005_CHG_IRQ_IVR,
	S2MU005_CHG_IRQ_EVENT,
	S2MU005_CHG_IRQ_CHG,
	S2MU005_CHG_IRQ_VMID,
	S2MU005_CHG_IRQ_WCIN,
	S2MU005_CHG_IRQ_VBUS,

	S2MU005_FLED_IRQ_LBPROT,
	S2MU005_FLED_IRQ_OPEN_CH2,
	S2MU005_FLED_IRQ_OPEN_CH1,
	S2MU005_FLED_IRQ_SHORT_CH2,
	S2MU005_FLED_IRQ_SHORT_CH1,

	S2MU005_MUIC_IRQ1_ATTATCH,
	S2MU005_MUIC_IRQ1_DETACH,
	S2MU005_MUIC_IRQ1_KP,
	S2MU005_MUIC_IRQ1_LKP,
	S2MU005_MUIC_IRQ1_LKR,
	S2MU005_MUIC_IRQ1_RID_CHG,

	S2MU005_MUIC_IRQ2_VBUS_ON,
	S2MU005_MUIC_IRQ2_RSVD_ATTACH,
	S2MU005_MUIC_IRQ2_ADC_CHANGE,
	S2MU005_MUIC_IRQ2_STUCK,
	S2MU005_MUIC_IRQ2_STUCKRCV,
	S2MU005_MUIC_IRQ2_MHDL,
	S2MU005_MUIC_IRQ2_AV_CHARGE,
	S2MU005_MUIC_IRQ2_VBUS_OFF,

	S2MU005_IRQ_NR,
};

struct s2mu005_dev {
	struct device *dev;
	struct i2c_client *i2c; /* Slave addr = 0x7A */
	struct mutex i2c_lock;

	int type;

	int irq;
	int irq_base;
	int irq_gpio;
	bool wakeup;
	struct mutex irqlock;
	int irq_masks_cur[S2MU005_IRQ_GROUP_NR];
	int irq_masks_cache[S2MU005_IRQ_GROUP_NR];

#ifdef CONFIG_HIBERNATION
	/* For hibernation */
	u8 reg_pmic_dump[S2MU005_PMIC_REG_END];
	u8 reg_muic_dump[S2MU005_MUIC_REG_END];
	u8 reg_led_dump[S2MU005_LED_REG_END];
#endif

	/* pmic VER/REV register */
	u8 pmic_rev;	/* pmic Rev */
	u8 pmic_ver;	/* pmic version */

	struct s2mu005_platform_data *pdata;
};

enum s2mu005_types {
	TYPE_S2MU005,
};

extern int s2mu005_irq_init(struct s2mu005_dev *s2mu005);
extern void s2mu005_irq_exit(struct s2mu005_dev *s2mu005);

/* s2mu005 shared i2c API function */
extern int s2mu005_read_reg(struct i2c_client *i2c, u8 reg, u8 *dest);
extern int s2mu005_bulk_read(struct i2c_client *i2c, u8 reg, int count,
				u8 *buf);
extern int s2mu005_write_reg(struct i2c_client *i2c, u8 reg, u8 value);
extern int s2mu005_bulk_write(struct i2c_client *i2c, u8 reg, int count,
				u8 *buf);
extern int s2mu005_write_word(struct i2c_client *i2c, u8 reg, u16 value);
extern int s2mu005_read_word(struct i2c_client *i2c, u8 reg);

extern int s2mu005_update_reg(struct i2c_client *i2c, u8 reg, u8 val, u8 mask);

/* s2mu005 check muic path fucntion */
extern bool is_muic_usb_path_ap_usb(void);
extern bool is_muic_usb_path_cp_usb(void);

/* s2mu005 Debug. ft */
extern void s2mu005_muic_read_register(struct i2c_client *i2c);

/* for charger api */
extern void s2mu005_hv_muic_charger_init(void);

#endif /* __LINUX_MFD_S2MU005_PRIV_H */

