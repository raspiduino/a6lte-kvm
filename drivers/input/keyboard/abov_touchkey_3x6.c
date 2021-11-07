/* abov_touchkey.c -- Linux driver for abov chip as touchkey
 *
 * Copyright (C) 2013 Samsung Electronics Co.Ltd
 * Author: Junkyeong Kim <jk0430.kim@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <asm/unaligned.h>
#include <linux/regulator/consumer.h>
#include <linux/pinctrl/consumer.h>
#include <linux/wakelock.h>
#include <linux/sec_sysfs.h>

#if 0
#include <linux/sec_class.h>
#else
extern struct class *sec_class;
#endif

#ifdef CONFIG_OF
#include <linux/of_gpio.h>
#endif

#ifdef CONFIG_VBUS_NOTIFIER
#include <linux/muic/muic.h>
#include <linux/muic/muic_notifier.h>
#include <linux/vbus_notifier.h>
#endif

bool ta_connected;

#define ABOV_TK_NAME "abov-touchkey-3x6"

/* registers */
#define ABOV_LED_CONTROL	0x00
#define ABOV_FW_VER		0x01
#define ABOV_THRESHOLD		0x02
#define ABOV_BTNSTATUS		0x07
#define ABOV_DIFFDATA		0x0A
#define ABOV_RAWDATA		0x0E
#define ABOV_VENDORID		0x12
#define ABOV_GLOVE		0x13
#define ABOV_TSPTA			0x13
#define ABOV_MODEL_NO		0x14
#define CMD_SAR_TOTALCAP	0x16
#define CMD_SAR_MODE		0x17
#define CMD_SAR_TOTALCAP_READ	0x18
#define ABOV_SW_RESET		0x1A
#define CMD_SAR_ENABLE		0x24
#define CMD_SAR_SENSING		0x25
#define CMD_SAR_NOISE_THRESHOLD	0x26
#define CMD_SAR_BASELINE	0x28
#define CMD_SAR_DIFFDATA	0x2A
#define CMD_SAR_RAWDATA		0x2E
#define CMD_SAR_THRESHOLD	0x32

#define CMD_DATA_UPDATE		0x40
#define CMD_MODE_CHECK		0x41
#define CMD_LED_CTRL_ON		0x60
#define CMD_LED_CTRL_OFF	0x70
#define CMD_STOP_MODE		0x80

/* command */
#define CMD_LED_ON		0x10
#define CMD_LED_OFF		0x20
#define CMD_ON			0x20
#define CMD_OFF			0x10
#define CMD_SW_RESET		0x10

#define ABOV_BOOT_DELAY		45
#define ABOV_RESET_DELAY	150
#define ABOV_FLASH_MODE		0x18

#define USE_OPEN_CLSOE
static struct device *sec_touchkey;

/* Force FW update if module# is different */
#undef FORCE_FW_UPDATE_DIFF_MODULE

/* Touchkey LED twinkle during booting in factory sw (in LCD detached status) */
#ifdef CONFIG_SEC_FACTORY
/* Jade project don't use KEY_LED, if use KEY LED, let's define*/
#undef LED_TWINKLE_BOOTING
#endif

#define USE_OPEN_CLOSE

#define TK_FW_PATH_SDCARD "/sdcard/Firmware/TOUCHKEY/abov_fw.bin"

#ifdef LED_TWINKLE_BOOTING
static void led_twinkle_work(struct work_struct *work);
#endif

#define I2C_M_WR 0		/* for i2c */

enum {
	BUILT_IN = 0,
	SDCARD,
};

#ifdef CONFIG_SAMSUNG_LPM_MODE
extern int poweroff_charging;
#endif
extern unsigned int system_rev;
extern unsigned int lcdtype;
static int touchkey_keycode[] = { 0,
	KEY_RECENT, KEY_BACK,
#ifdef CONFIG_TOUCHKEY_GRIP
	KEY_CP_GRIP,
#endif
};

struct abov_tk_info {
	struct i2c_client *client;
	struct input_dev *input_dev;
	struct abov_touchkey_devicetree_data *dtdata;
	struct mutex lock;
	struct pinctrl *pinctrl;

	const struct firmware *firm_data_bin;
	const u8 *firm_data_ums;
	char phys[32];
	long firm_size;
	int irq;
	u16 menu_s;
	u16 back_s;
	u16 menu_raw;
	u16 back_raw;
#ifdef CONFIG_TOUCHKEY_GRIP
	struct wake_lock touchkey_wake_lock;

	u16 grip_p_thd;
	u16 grip_r_thd;
	u16 grip_n_thd;
	u16 grip_s1;
	u16 grip_s2;
	u16 grip_baseline;
	u16 grip_raw1;
	u16 grip_raw2;
	u16 grip_event;
	bool sar_mode;
	bool sar_enable;
	bool sar_enable_off;
	int irq_count;
	int abnormal_mode;
	s16 diff;
	s16 max_diff;
#endif
	int (*power)(bool on);
	int touchkey_count;
	u8 fw_update_state;
	u8 fw_ver;
	u8 md_ver;
	u8 checksum_h;
	u8 checksum_l;
	u8 fw_ver_bin;
	u8 md_ver_bin;
	u8 checksum_h_bin;
	u8 checksum_l_bin;
	bool enabled;
#ifdef GLOVE_MODE
	bool glovemode;
#endif
	bool probe_done;
#ifdef LED_TWINKLE_BOOTING
	struct delayed_work led_twinkle_work;
	bool led_twinkle_check;
#endif
#ifdef CONFIG_VBUS_NOTIFIER
	struct notifier_block vbus_nb;
#endif
	bool flip_mode;
	struct completion resume_done;
	bool is_lpm_suspend;
};

struct abov_touchkey_devicetree_data {
	unsigned long irq_flag;
	int gpio_en;
	int gpio_int;
	int gpio_sda;
	int gpio_scl;
	int gpio_rst;
	int vdd_io_alwayson;
	struct regulator *vdd_io_vreg;
	struct regulator *avdd_vreg;
	struct regulator *vdd_led;
	const char *fw_name;
	int bringup;
	int firmup_cmd;
	bool ta_notifier;
	bool not_support_key;
	int (*power)(struct abov_tk_info *info, bool on);
	int (*keyled)(bool on);
};

#ifdef USE_OPEN_CLOSE
static int abov_tk_input_open(struct input_dev *dev);
static void abov_tk_input_close(struct input_dev *dev);
#endif

static int abov_tk_i2c_read_checksum(struct abov_tk_info *info);
static void abov_set_ta_status(struct abov_tk_info *info);

static int abov_touchkey_led_status;
static int abov_touchled_cmd_reserved;

#if defined(GLOVE_MODE) || defined(CONFIG_TOUCHKEY_GRIP)
static int abov_mode_enable(struct i2c_client *client,u8 cmd_reg, u8 cmd)
{
	return i2c_smbus_write_byte_data(client, cmd_reg, cmd);
}
#endif

static int abov_tk_i2c_read(struct i2c_client *client,
		u8 reg, u8 *val, unsigned int len)
{
	struct abov_tk_info *info = i2c_get_clientdata(client);
	struct i2c_msg msg;
	int ret;
	int retry = 3;

	mutex_lock(&info->lock);
	msg.addr = client->addr;
	msg.flags = I2C_M_WR;
	msg.len = 1;
	msg.buf = &reg;
	while (retry--) {
		ret = i2c_transfer(client->adapter, &msg, 1);
		if (ret >= 0)
			break;

		input_err(true, &client->dev, "%s fail(address set)(%d)\n",
			__func__, retry);
		usleep_range(10 * 1000, 10 * 1000);
	}
	if (ret < 0) {
		mutex_unlock(&info->lock);
		return ret;
	}
	retry = 3;
	msg.flags = 1;/*I2C_M_RD*/
	msg.len = len;
	msg.buf = val;
	while (retry--) {
		ret = i2c_transfer(client->adapter, &msg, 1);
		if (ret >= 0) {
			mutex_unlock(&info->lock);
			return 0;
		}
		input_err(true, &client->dev, "%s fail(data read)(%d)\n",
			__func__, retry);
		usleep_range(10 * 1000, 10 * 1000);
	}
	mutex_unlock(&info->lock);
	return ret;
}

static int abov_tk_i2c_read_data(struct i2c_client *client, u8 *val, unsigned int len)
{
	struct abov_tk_info *info = i2c_get_clientdata(client);
	struct i2c_msg msg;
	int ret;
	int retry = 3;

	mutex_lock(&info->lock);
	msg.addr = client->addr;
	msg.flags = 1;/*I2C_M_RD*/
	msg.len = len;
	msg.buf = val;
	while (retry--) {
		ret = i2c_transfer(client->adapter, &msg, 1);
		if (ret >= 0) {
			mutex_unlock(&info->lock);
			return 0;
		}
		input_err(true, &client->dev, "%s fail(data read)(%d)\n",
			__func__, retry);
		usleep_range(10 * 1000, 10 * 1000);
	}
	mutex_unlock(&info->lock);
	return ret;
}

static int abov_tk_i2c_write(struct i2c_client *client,
		u8 reg, u8 *val, unsigned int len)
{
	struct abov_tk_info *info = i2c_get_clientdata(client);
	struct i2c_msg msg[1];
	unsigned char data[2];
	int ret;
	int retry = 3;

	mutex_lock(&info->lock);
	data[0] = reg;
	data[1] = *val;
	msg->addr = client->addr;
	msg->flags = I2C_M_WR;
	msg->len = 2;
	msg->buf = data;

	while (retry--) {
		ret = i2c_transfer(client->adapter, msg, 1);
		if (ret >= 0) {
			mutex_unlock(&info->lock);
			return 0;
		}
		input_err(true, &client->dev, "%s fail(%d)\n",
			__func__, retry);
		usleep_range(10 * 1000, 10 * 1000);
	}
	mutex_unlock(&info->lock);
	return ret;
}

#ifdef CONFIG_TOUCHKEY_GRIP
static void abov_sar_only_mode(struct abov_tk_info *info, int on)
{
	struct i2c_client *client = info->client;
	int retry =3;
	int ret;
	u8 cmd;
	u8 r_buf;
	int mode_retry = 1;

	if (info->sar_mode == on) {
		input_info(true, &client->dev, "[TK] %s : skip already %s\n",
				__func__, (on == 1) ? "sar only mode" : "normal mode");
		return;
	}

	if (on == 1)
		cmd = CMD_ON;
	else
		cmd = CMD_OFF;

	input_info(true, &client->dev, "[TK] %s : %s, cmd=%x\n",
		__func__, (on == 1) ? "sar only mode" : "normal mode", cmd);

sar_mode:
	while (retry > 0) {
		ret = abov_mode_enable(client, CMD_SAR_MODE, cmd);
		if (ret < 0) {
			input_err(true, &info->client->dev,
					"%s fail(%d), retry %d\n", __func__, ret, retry);
			retry--;
			msleep(20);
			continue;
		}
		break;
	}

	msleep(40);

	ret = abov_tk_i2c_read(info->client, CMD_SAR_MODE, &r_buf, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
	}

	input_info(true, &client->dev, "%s read reg = %x\n", __func__, r_buf);

	if ((r_buf != cmd) && (mode_retry == 1)) {
		input_err(true, &info->client->dev, "%s change fail retry\n", __func__);
		mode_retry = 0;
		goto sar_mode;
	}

	if (r_buf == CMD_ON)
		info->sar_mode = 1;
	else
		info->sar_mode = 0;
}

static void touchkey_sar_sensing(struct abov_tk_info *info, int on)
{
	struct i2c_client *client = info->client;
	int ret;
	u8 cmd;

	if (on == 0)
		cmd = CMD_ON;
	else
		cmd = CMD_OFF;		//EarJack inserted

	input_info(true, &client->dev, "[TK] %s : %d\n", __func__, !on);

	ret = abov_tk_i2c_write(info->client, CMD_SAR_SENSING, &cmd, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
	}
}

/* abov_grip_sw_reset
  * grip baseline calibration (only grip)
  */
static void abov_grip_sw_reset(struct abov_tk_info *info)
{
	int ret;
	u8 cmd = CMD_SW_RESET;

	input_info(true, &info->client->dev, "[TK] %s\n", __func__);

	ret = abov_tk_i2c_write(info->client, ABOV_SW_RESET, &cmd, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev,
				"%s sw_reset fail(%d)\n", __func__, ret);
	}
}
#endif

static void release_all_fingers(struct abov_tk_info *info)
{
	struct i2c_client *client = info->client;
	int i;

	input_info(true, &client->dev, "[TK] %s tc=%d\n", __func__, info->touchkey_count);

	for (i = 1; i < info->touchkey_count; i++) {
		input_report_key(info->input_dev,
			touchkey_keycode[i], 0);
	}
	input_sync(info->input_dev);
}

static int abov_tk_reset_for_bootmode(struct abov_tk_info *info)
{
	if (gpio_get_value(info->dtdata->gpio_en)) {
		gpio_direction_output(info->dtdata->gpio_en, 0);
		usleep_range(10 * 1000, 12 * 1000);
	}

	gpio_direction_output(info->dtdata->gpio_en, 1);

	return 0;
}

static void abov_tk_reset(struct abov_tk_info *info)
{
	struct i2c_client *client = info->client;

	if (info->enabled == false)
		return;

	input_info(true, &client->dev, "%s++\n", __func__);
	disable_irq_nosync(info->irq);

	info->enabled = false;

	release_all_fingers(info);

	abov_tk_reset_for_bootmode(info);
	msleep(ABOV_RESET_DELAY);

#ifdef GLOVE_MODE
	if (info->glovemode)
		abov_mode_enable(client, ABOV_GLOVE, CMD_ON);
#endif

#ifdef CONFIG_TOUCHKEY_GRIP
	if (info->sar_enable)
		abov_mode_enable(client, CMD_SAR_ENABLE, CMD_ON);
#endif
	info->enabled = true;
	
	if (info->dtdata->ta_notifier && ta_connected) {
		abov_set_ta_status(info);
	}

	enable_irq(info->irq);
	input_info(true, &client->dev, "%s--\n", __func__);
}

static irqreturn_t abov_tk_interrupt(int irq, void *dev_id)
{
	struct abov_tk_info *info = dev_id;
	struct i2c_client *client = info->client;
	int ret, retry;
	u8 buf;
#ifdef CONFIG_TOUCHKEY_GRIP
#ifdef CONFIG_SEC_FACTORY
	u8 r_buf[2];
#endif
#endif
	bool press;
	int menu_data;
	int back_data;
	u8 menu_press;
	u8 back_press;
#ifdef CONFIG_TOUCHKEY_GRIP
	int grip_data;
	u8 grip_press = 0;
	wake_lock(&info->touchkey_wake_lock);

#endif

	ret = abov_tk_i2c_read(client, ABOV_BTNSTATUS, &buf, 1);
	if (ret < 0) {
		retry = 3;
		while (retry--) {
			input_err(true, &client->dev, "%s read fail(%d)\n",
				__func__, retry);
			ret = abov_tk_i2c_read(client, ABOV_BTNSTATUS, &buf, 1);
			if (ret == 0)
				break;

			usleep_range(10 * 1000, 10 * 1000);
		}
		if (retry == 0) {
			abov_tk_reset(info);
#ifdef CONFIG_TOUCHKEY_GRIP
			wake_unlock(&info->touchkey_wake_lock);
#endif

			return IRQ_HANDLED;
		}
	}

	/* added dual key mode concept for screen pinning(google) */

	menu_data = buf & 0x03;
	back_data = (buf >> 2) & 0x03;
	menu_press = !(menu_data % 2);
	back_press = !(back_data % 2);
#ifdef CONFIG_TOUCHKEY_GRIP
	grip_data = (buf >> 4) & 0x03;
	grip_press = !(grip_data % 2);
#endif

	press = (menu_data ? menu_press : 0) || (back_data ? back_press : 0);

	if (menu_data)
		input_report_key(info->input_dev,
			touchkey_keycode[1], menu_press);
	if (back_data)
		input_report_key(info->input_dev,
			touchkey_keycode[2], back_press);
#ifdef CONFIG_TOUCHKEY_GRIP
	if (grip_data) {
		input_report_key(info->input_dev,
				touchkey_keycode[3], grip_press);
		info->grip_event =  grip_press;
	}
#ifdef CONFIG_SEC_FACTORY
	ret = abov_tk_i2c_read(info->client, CMD_SAR_DIFFDATA, r_buf, 2);
	if (ret < 0) {
		retry = 3;
		while (retry--) {
			input_err(true, &client->dev, "%s read fail(%d)\n",
				__func__, retry);
			ret = abov_tk_i2c_read(info->client, CMD_SAR_DIFFDATA, r_buf, 2);
			if (ret == 0)
				break;

			usleep_range(10 * 1000, 10 * 1000);
		}
	}
	
	info->diff = (r_buf[0] << 8) | r_buf[1];
	if (info->abnormal_mode) {
		if (info->grip_event) {
			if (info->max_diff < info->diff)
				info->max_diff = info->diff;
			info->irq_count++;
		}
	}
#endif
#endif

	input_sync(info->input_dev);

#ifdef CONFIG_SAMSUNG_PRODUCT_SHIP
	input_info(true, &client->dev,
		"key %s%s ver0x%02x\n",
		menu_data ? (menu_press ? "P" : "R") : "",
		back_data ? (back_press ? "P" : "R") : "",
		info->fw_ver);
#else
	input_info(true, &client->dev,
		"%s%s%x ver0x%02x\n",
		menu_data ? (menu_press ? "menu P " : "menu R ") : "",
		back_data ? (back_press ? "back P " : "back R ") : "",
		buf, info->fw_ver);
#endif

#ifdef CONFIG_TOUCHKEY_GRIP
	if (grip_data) {
		input_info(true, &client->dev, "grip %s %x, TA %d\n",
			grip_press ? "P " : "R ", buf, ta_connected);
	}
	wake_unlock(&info->touchkey_wake_lock);
#endif

	return IRQ_HANDLED;
}

static int touchkey_led_set(struct abov_tk_info *info, int data)
{
	u8 cmd;
	int ret;

	if (data == 1)
		cmd = CMD_LED_ON;
	else
		cmd = CMD_LED_OFF;

	if (!info->enabled)
		goto out;

	ret = abov_tk_i2c_write(info->client, ABOV_LED_CONTROL, &cmd, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		goto out;
	}

	return 0;
out:
	abov_touchled_cmd_reserved = 1;
	abov_touchkey_led_status = cmd;
	return 1;
}

static ssize_t touchkey_led_control(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int data;
	int ret;

	ret = sscanf(buf, "%d", &data);
	if (ret != 1) {
		input_err(true, &client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(data == 0 || data == 1)) {
		input_err(true, &client->dev, "%s: wrong command(%d)\n",
			__func__, data);
		return count;
	}

#ifdef LED_TWINKLE_BOOTING
	if (info->led_twinkle_check == 1) {
		info->led_twinkle_check = 0;
		cancel_delayed_work(&info->led_twinkle_work);
	}
#endif

	if (touchkey_led_set(info, data))
		return count;

	msleep(20);

	abov_touchled_cmd_reserved = 0;
	input_info(true, &client->dev, "%s data(%d)\n", __func__,data);

	return count;
}

static ssize_t touchkey_threshold_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	u8 r_buf;
	int ret;

	ret = abov_tk_i2c_read(client, ABOV_THRESHOLD, &r_buf, 1);
	if (ret < 0) {
		input_err(true, &client->dev, "%s fail(%d)\n", __func__, ret);
		r_buf = 0;
	}
	return snprintf(buf, PAGE_SIZE, "%d\n", r_buf);
}

static void get_diff_data(struct abov_tk_info *info)
{
	struct i2c_client *client = info->client;
	u8 r_buf[4];
	int ret;

	ret = abov_tk_i2c_read(client, ABOV_DIFFDATA, r_buf, 4);
	if (ret < 0) {
		input_err(true, &client->dev, "%s fail(%d)\n", __func__, ret);
		info->menu_s = 0;
		info->back_s = 0;
		return;
	}

	info->menu_s = (r_buf[0] << 8) | r_buf[1];
	info->back_s = (r_buf[2] << 8) | r_buf[3];
}

static ssize_t touchkey_menu_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	get_diff_data(info);

	return sprintf(buf, "%d\n", info->menu_s);
}

static ssize_t touchkey_back_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	get_diff_data(info);

	return sprintf(buf, "%d\n", info->back_s);
}

static void get_raw_data(struct abov_tk_info *info)
{
	struct i2c_client *client = info->client;
	u8 r_buf[4];
	int ret;

	ret = abov_tk_i2c_read(client, ABOV_RAWDATA, r_buf, 4);
	if (ret < 0) {
		input_err(true, &client->dev, "%s fail(%d)\n", __func__, ret);
		info->menu_raw = 0;
		info->back_raw = 0;
		return;
	}

	info->menu_raw = (r_buf[0] << 8) | r_buf[1];
	info->back_raw = (r_buf[2] << 8) | r_buf[3];
}

static ssize_t touchkey_menu_raw_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	get_raw_data(info);

	return snprintf(buf, PAGE_SIZE, "%d\n", info->menu_raw);
}

static ssize_t touchkey_back_raw_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	get_raw_data(info);

	return snprintf(buf, PAGE_SIZE, "%d\n", info->back_raw);
}

#ifdef CONFIG_TOUCHKEY_GRIP
static ssize_t touchkey_sar_enable(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int data;
	int ret;
	u8 cmd;

	ret = sscanf(buf, "%d", &data);
	if (ret != 1) {
		input_err(true, &client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(data >= 0 && data <= 3)) {
		input_err(true, &client->dev, "%s: wrong command(%d)\n",
				__func__, data);
		return count;
	}

	/*	sar enable param
	  *	0	off
	  *	1	on
	  *	2	force off
	  *	3	force off -> on
	  */

	if (data == 3) {
		info->sar_enable_off = 0;
		input_info(true, &info->client->dev,
				"%s : Power back off _ force off -> on (%d)\n",
				__func__, info->sar_enable);
		if (info->sar_enable)
			data = 1;
		else
			return count;
	}

	if (info->sar_enable_off) {
		if (data == 1)
			info->sar_enable = true;
		else
			info->sar_enable = false;
		input_info(true, &info->client->dev,
				"%s skip, Power back off _ force off mode (%d)\n",
				__func__, info->sar_enable);
		return count;
	}

	if (data == 1) {
		cmd = 0x20;
	} else if (data == 2) {
		cmd = 0x10;
		info->sar_enable_off = 1;
	} else {
		cmd = 0x10;
	}

	input_info(true, &info->client->dev, "%s data(%d)\n",__func__,data);

	ret = abov_mode_enable(client, CMD_SAR_ENABLE, cmd);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		return count;
	}


	if (data == 1) {
		info->sar_enable = true;
	} else {
		input_report_key(info->input_dev, touchkey_keycode[3], 0);
		info->grip_event = 0;
		info->sar_enable = false;
	}

	input_info(true, &client->dev, "%s data(%d)\n",__func__,data);

	return count;
}

static ssize_t touchkey_grip_threshold_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	u8 r_buf[4];
	int ret;

	ret = abov_tk_i2c_read(info->client, CMD_SAR_THRESHOLD, r_buf, 4);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		info->grip_p_thd = 0;
		info->grip_r_thd = 0;
		return sprintf(buf, "%d\n", 0);
	}
	info->grip_p_thd = (r_buf[0] << 8) | r_buf[1];
	info->grip_r_thd = (r_buf[2] << 8) | r_buf[3];

	ret = abov_tk_i2c_read(info->client, CMD_SAR_NOISE_THRESHOLD, r_buf, 2);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		info->grip_n_thd = 0;
		return sprintf(buf, "%d\n", 0);
	}
	info->grip_n_thd = (r_buf[0] << 8) | r_buf[1];

	return sprintf(buf, "%d,%d,%d\n",
			info->grip_p_thd, info->grip_r_thd, info->grip_n_thd );
}

static ssize_t touchkey_total_cap_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	u8 r_buf[2];
	u8 cmd;
	int ret;
	int value;

	cmd = CMD_ON;
	ret = abov_tk_i2c_write(info->client, CMD_SAR_TOTALCAP, &cmd, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s write fail(%d)\n", __func__, ret);
	}

	usleep_range(10, 10);

	ret = abov_tk_i2c_read(info->client, CMD_SAR_TOTALCAP_READ, r_buf, 2);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		return sprintf(buf, "%d\n", 0);
	}
	value = (r_buf[0] << 8) | r_buf[1];

	return sprintf(buf, "%d\n", value / 100);
}

static ssize_t touchkey_grip_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	u8 r_buf[4];
	int ret;

	ret = abov_tk_i2c_read(info->client, CMD_SAR_DIFFDATA, r_buf, 4);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		info->grip_s1 = 0;
		info->grip_s2 = 0;
		return sprintf(buf, "%d\n", 0);
	}
	info->grip_s1 = (r_buf[0] << 8) | r_buf[1];
	info->grip_s2 = (r_buf[2] << 8) | r_buf[3];


	return sprintf(buf, "%d,%d\n", info->grip_s1, info->grip_s2);
}

static ssize_t touchkey_grip_baseline_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	u8 r_buf[2];
	int ret;

	ret = abov_tk_i2c_read(info->client, CMD_SAR_BASELINE, r_buf, 2);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		info->grip_baseline = 0;
		return sprintf(buf, "%d\n", 0);
	}
	info->grip_baseline = (r_buf[0] << 8) | r_buf[1];

	return sprintf(buf, "%d\n", info->grip_baseline);

}

static ssize_t touchkey_grip_raw_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	u8 r_buf[4];
	int ret;

	ret = abov_tk_i2c_read(info->client, CMD_SAR_RAWDATA, r_buf, 4);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
		info->grip_raw1 = 0;
		info->grip_raw2 = 0;
		return sprintf(buf, "%d\n", 0);
	}
	info->grip_raw1 = (r_buf[0] << 8) | r_buf[1];
	info->grip_raw2 = 0;

	return sprintf(buf, "%d,%d\n", info->grip_raw1, info->grip_raw2);
}

static ssize_t touchkey_grip_gain_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d,%d,%d,%d\n", 0, 0, 0, 0);
}

static ssize_t touchkey_grip_check_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	input_info(true, &info->client->dev, "%s event:%d\n", __func__, info->grip_event);

	return sprintf(buf, "%d\n", info->grip_event);
}

static ssize_t touchkey_grip_sw_reset(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int data;
	int ret;

	ret = sscanf(buf, "%d", &data);
	if (ret != 1) {
		input_err(true, &client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(data == 1)) {
		input_err(true, &client->dev, "%s: wrong command(%d)\n",
			__func__, data);
		return count;
	}

	info->grip_event = 0;

	input_info(true, &info->client->dev, "%s data(%d)\n",__func__,data);

	abov_grip_sw_reset(info);

	return count;
}

static ssize_t touchkey_sensing_change(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int ret, data;

	ret = sscanf(buf, "%d", &data);
	if (ret != 1) {
		input_err(true, &client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(data == 0 || data == 1)) {
		input_err(true, &client->dev, "%s: wrong command(%d)\n",
				__func__, data);
		return count;
	}

	touchkey_sar_sensing(info, data);

	input_info(true, &info->client->dev, "%s earjack (%d)\n", __func__, data);

	return count;
}

#ifndef CONFIG_SAMSUNG_PRODUCT_SHIP
static ssize_t touchkey_sar_press_threshold_store(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	int ret;
	int threshold;
	u8 cmd[2];

	ret = sscanf(buf, "%d", &threshold);
	if (ret != 1) {
		input_err(true, &info->client->dev,
				"%s: failed to read thresold, buf is %s\n",
				__func__,buf);
		return count;
	}

	if (threshold > 0xff) {
		cmd[0] = (threshold >> 8) & 0xff;
		cmd[1] = 0xff & threshold;
	} else if(threshold < 0) {
		cmd[0] = 0x0;
		cmd[1] = 0x0;
	} else {
		cmd[0] = 0x0;
		cmd[1] = (u8)threshold;
	}

	input_info(true, &info->client->dev, "%s buf : %d, threshold : %d\n",
			__func__, threshold,(cmd[0]<<8 )| cmd[1]);

	ret = abov_tk_i2c_write(info->client, CMD_SAR_THRESHOLD, &cmd[0], 1);
	if (ret) {
		input_err(true, &info->client->dev,
				"%s failed to write press_threhold data1", __func__);
		goto press_threshold_out;
	}

	ret = abov_tk_i2c_write(info->client, CMD_SAR_THRESHOLD + 0x01, &cmd[1], 1);
	if (ret) {
		input_err(true, &info->client->dev,
				"%s failed to write press_threhold data2", __func__);
		goto press_threshold_out;
	}

press_threshold_out:
	return count;
}

static ssize_t touchkey_sar_release_threshold_store(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	int ret;
	int threshold;
	u8 cmd[2];

	ret = sscanf(buf, "%d", &threshold);
	if (ret != 1) {
		input_err(true, &info->client->dev,
				"%s: failed to read thresold, buf is %s\n",
				__func__, buf);
		return count;
	}

	if (threshold > 0xff) {
		cmd[0] = (threshold >> 8) & 0xff;
		cmd[1] = 0xff & threshold;
	} else if (threshold < 0) {
		cmd[0] = 0x0;
		cmd[1] = 0x0;
	} else {
		cmd[0] = 0x0;
		cmd[1] = (u8)threshold;
	}

	input_info(true, &info->client->dev, "%s buf : %d, threshold : %d\n",
			__func__, threshold,(cmd[0] << 8) | cmd[1]);

	ret = abov_tk_i2c_write(info->client, CMD_SAR_THRESHOLD + 0x02, &cmd[0], 1);
	input_info(true, &info->client->dev, "%s ret : %d\n", __func__, ret);
	if (ret) {
		input_err(true, &info->client->dev,
				"%s failed to write release_threshold_data1", __func__);
		goto release_threshold_out;
	}

	ret = abov_tk_i2c_write(info->client, CMD_SAR_THRESHOLD + 0x03, &cmd[1], 1);
	input_info(true, &info->client->dev, "%s ret : %d\n", __func__, ret);
	if (ret) {
		input_err(true, &info->client->dev,
				"%s failed to write release_threshold_data2", __func__);
		goto release_threshold_out;
	}

release_threshold_out:
	return count;
}

static ssize_t touchkey_mode_change(struct device *dev,
		 struct device_attribute *attr, const char *buf,
		 size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int ret, data;

	ret = sscanf(buf, "%d", &data);
	if (ret != 1) {
		input_err(true, &client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(data == 0 || data == 1)) {
		input_err(true, &client->dev, "%s: wrong command(%d)\n", __func__, data);
		return count;
	}

	input_info(true, &info->client->dev, "%s data(%d)\n", __func__, data);

	abov_sar_only_mode(info, data);

	return count;
}
#endif

static ssize_t touchkey_grip_irq_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	int result = 0;

	if (info->irq_count)
		result = -1;

	input_info(true, &info->client->dev, "%s - called\n", __func__);

	return snprintf(buf, PAGE_SIZE, "%d,%d,%d\n",
		result, info->irq_count, info->max_diff);
}

static ssize_t touchkey_grip_irq_count_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	u8 onoff;
	int ret;

	ret = kstrtou8(buf, 10, &onoff);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s - kstrtou8 failed.(%d)\n", __func__, ret);
		return count;
	}

	mutex_lock(&info->lock);

	if (onoff == 0) {
		info->abnormal_mode = 0;
	} else if (onoff == 1) {
		info->abnormal_mode = 1;
		info->irq_count = 0;
		info->max_diff = 0;
	} else {
		input_err(true, &info->client->dev, "%s - unknown value %d\n", __func__, onoff);
	}

	mutex_unlock(&info->lock);

	input_info(true, &info->client->dev, "%s - %d\n", __func__, onoff);
	
	return count;
}
#endif

static ssize_t touchkey_chip_name(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;

	input_info(true, &client->dev, "%s\n", __func__);

	return sprintf(buf, "A96T3X6\n");
}

static ssize_t bin_fw_ver(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;

	input_info(true, &client->dev, "fw version bin : 0x%x\n", info->fw_ver_bin);

	return snprintf(buf, PAGE_SIZE, "0x%02x\n", info->fw_ver_bin);
}

int get_tk_fw_version(struct abov_tk_info *info, bool bootmode)
{
	struct i2c_client *client = info->client;
	u8 buf;
	int ret;
	int retry = 3;

	ret = abov_tk_i2c_read(client, ABOV_FW_VER, &buf, 1);
	if (ret < 0) {
		while (retry--) {
			input_err(true, &client->dev, "%s read fail(%d)\n",
				__func__, retry);
			if (!bootmode)
				abov_tk_reset(info);
			else
				return -1;
			ret = abov_tk_i2c_read(client, ABOV_FW_VER, &buf, 1);
			if (ret == 0)
				break;
		}
		if (retry == 0)
			return -1;
	}

	info->fw_ver = buf;

	retry = 3;
	ret = abov_tk_i2c_read(client, ABOV_MODEL_NO, &buf, 1);
	if (ret < 0) {
		while (retry--) {
			input_err(true, &client->dev, "%s read fail(%d)\n",
				__func__, retry);
			if (!bootmode)
				abov_tk_reset(info);
			else
				return -1;
			ret = abov_tk_i2c_read(client, ABOV_MODEL_NO, &buf, 1);
			if (ret == 0)
				break;
		}
		if (retry == 0)
			return -1;
	}

	info->md_ver = buf;
	input_info(true, &client->dev, "%s : fw = 0x%x, md = 0x%x\n",
		__func__, info->fw_ver, info->md_ver);
	return 0;
}

static ssize_t read_fw_ver(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int ret;

	ret = get_tk_fw_version(info, false);
	if (ret < 0) {
		input_err(true, &client->dev, "%s read fail\n", __func__);
		info->fw_ver = 0;
	}

	return snprintf(buf, PAGE_SIZE, "0x%02x\n", info->fw_ver);
}

static int abov_load_fw_kernel(struct abov_tk_info *info)
{
	struct i2c_client *client = info->client;
	int ret = 0;

	ret = request_firmware(&info->firm_data_bin,
		info->dtdata->fw_name, &client->dev);
	if (ret) {
		input_err(true, &client->dev,
			"%s request_firmware fail.\n", __func__);
		return ret;
	}
	info->firm_size = info->firm_data_bin->size;
	info->fw_ver_bin = info->firm_data_bin->data[5];
	info->md_ver_bin = info->firm_data_bin->data[1];
	input_info(true, &client->dev, "%s : fw = 0x%x, md = 0x%x\n",
		__func__, info->fw_ver_bin, info->md_ver_bin);

	info->checksum_h_bin = info->firm_data_bin->data[8];
	info->checksum_l_bin = info->firm_data_bin->data[9];

	input_info(true, &client->dev, "%s : crc 0x%x 0x%x\n",
		__func__, info->checksum_h_bin, info->checksum_l_bin);

	return ret;
}

static int abov_load_fw(struct abov_tk_info *info, u8 cmd)
{
	struct i2c_client *client = info->client;
	struct file *fp;
	mm_segment_t old_fs;
	long fsize, nread;
	int ret = 0;

	switch (cmd) {
	case BUILT_IN:
		break;

	case SDCARD:
		old_fs = get_fs();
		set_fs(get_ds());
		fp = filp_open(TK_FW_PATH_SDCARD, O_RDONLY, S_IRUSR);
		if (IS_ERR(fp)) {
			input_err(true, &client->dev,
				"%s %s open error\n", __func__, TK_FW_PATH_SDCARD);
			ret = -ENOENT;
			goto fail_sdcard_open;
		}

		fsize = fp->f_path.dentry->d_inode->i_size;
		info->firm_data_ums = kzalloc((size_t)fsize, GFP_KERNEL);
		if (!info->firm_data_ums) {
			input_err(true, &client->dev,
				"%s fail to kzalloc for fw\n", __func__);
			ret = -ENOMEM;
			goto fail_sdcard_kzalloc;
		}

		nread = vfs_read(fp,
			(char __user *)info->firm_data_ums, fsize, &fp->f_pos);
		if (nread != fsize) {
			input_err(true, &client->dev,
				"%s fail to vfs_read file\n", __func__);
			ret = -EINVAL;
			goto fail_sdcard_size;
		}
		filp_close(fp, current->files);
		set_fs(old_fs);
		info->firm_size = nread;
		break;

	default:
		ret = -1;
		break;
	}
	input_info(true, &client->dev, "fw_size : %lu\n", info->firm_size);
	input_info(true, &client->dev, "%s success\n", __func__);
	return ret;

fail_sdcard_size:
	kfree(&info->firm_data_ums);
fail_sdcard_kzalloc:
	filp_close(fp, current->files);
fail_sdcard_open:
	set_fs(old_fs);
	return ret;
}

static int abov_tk_check_busy(struct abov_tk_info *info)
{
	int ret, count = 0;
	unsigned char val = 0x00;

	do {
		ret = i2c_master_recv(info->client, &val, sizeof(val));

		if (val)
			count++;
		else
			break;

		if (count > 1000)
			break;
	} while (1);

	if (count > 1000)
		input_err(true, &info->client->dev, "%s: busy %d\n", __func__, count);
	return ret;
}

static int abov_tk_i2c_read_checksum(struct abov_tk_info *info)
{
	unsigned char data[6] = {0xAC, 0x9E, 0x10, 0x00, 0x3F, 0xFF};
	unsigned char data2[1] = {0x00};
	unsigned char checksum[6] = {0, };
	int ret;

	i2c_master_send(info->client, data, 6);

	usleep_range(5 * 1000, 5 * 1000);
	/* abov_tk_check_busy(info); */

	i2c_master_send(info->client, data2, 1);
	usleep_range(5 * 1000, 5 * 1000);

	ret = abov_tk_i2c_read_data(info->client, checksum, 6);


	input_info(true, &info->client->dev, "%s: ret:%d [%X][%X][%X][%X][%X][%X]\n",
			__func__, ret, checksum[0], checksum[1], checksum[2]
			, checksum[3], checksum[4], checksum[5]);
	info->checksum_h = checksum[4];
	info->checksum_l = checksum[5];
	return 0;
}

static int abov_tk_fw_write(struct abov_tk_info *info, unsigned char *addrH,
						unsigned char *addrL, unsigned char *val)
{
	int length = 36, ret = 0;
	unsigned char data[36];

	data[0] = 0xAC;
	data[1] = 0x7A;
	memcpy(&data[2], addrH, 1);
	memcpy(&data[3], addrL, 1);
	memcpy(&data[4], val, 32);

	ret = i2c_master_send(info->client, data, length);
	if (ret != length) {
		input_err(true, &info->client->dev, "%s: write fail[%x%x], %d\n", __func__, *addrH, *addrL, ret);
		return ret;
	}

	usleep_range(2 * 1000, 2 * 1000);

	abov_tk_check_busy(info);

	return 0;
}

static int abov_tk_fw_mode_enter(struct abov_tk_info *info)
{
	unsigned char data[2] = {0xAC, 0x5B};
	u8 ic_ver = 0;
	int ret = 0;

	ret = i2c_master_send(info->client, data, 2);
	if (ret != 2) {
		pr_err("%s: write fail\n", __func__);
		return -1;
	}

	ret = i2c_master_recv(info->client, &ic_ver, 1);
	input_info(true, &info->client->dev, "%s: %2x, %2x\n", __func__, info->dtdata->firmup_cmd, ic_ver);
	if(info->dtdata->firmup_cmd != ic_ver){
		input_err(true, &info->client->dev, "%s: ic not matched, firmup fail\n", __func__);
		return -2;
	}

	return 0;

}

static int abov_tk_fw_mode_check(struct abov_tk_info *info)
{
	unsigned char buf[1] = {0};
	int ret;

	ret = abov_tk_i2c_read_data(info->client, buf, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s: write fail\n", __func__);
		return 0;
	}

	input_info(true, &info->client->dev, "%s: ret:%02X\n", __func__, buf[0]);

	if (buf[0] == ABOV_FLASH_MODE)	
		return 1;

	pr_err("%s: value is same same,  %X, %X \n", __func__, ABOV_FLASH_MODE, buf[0]);

	return 0;
}

static int abov_tk_flash_erase(struct abov_tk_info *info)
{
	unsigned char data[2] = {0xAC, 0x2D};
	int ret = 0;

	ret = i2c_master_send(info->client, data, 2);
	if (ret != 2) {
		input_err(true, &info->client->dev, "%s: write fail\n", __func__);
		return -1;
	}

	return 0;

}

static int abov_tk_fw_mode_exit(struct abov_tk_info *info)
{
	unsigned char data[2] = {0xAC, 0xE1};
	int ret = 0;

	ret = i2c_master_send(info->client, data, 2);
	if (ret != 2) {
		input_err(true, &info->client->dev, "%s: write fail\n", __func__);
		return -1;
	}

	return 0;

}



static int abov_tk_fw_update(struct abov_tk_info *info, u8 cmd)
{
	int ret, ii = 0;
	int count, log = 0;
	unsigned short address;
	unsigned char addrH, addrL;
	unsigned char data[32] = {0, };

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);

	count = info->firm_size / 32;
	address = 0x800;

	gpio_direction_output(info->dtdata->gpio_en, 0);
	msleep(30);
	gpio_direction_output(info->dtdata->gpio_en, 1);
	usleep_range(ABOV_BOOT_DELAY * 1000, ABOV_BOOT_DELAY * 1000);

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);

	ret = abov_tk_fw_mode_enter(info);
	if(ret != 0){
		input_err(true, &info->client->dev, "%s: can't enter firm mode, %d\n", __func__, ret);
		return 0;
	}
	usleep_range(5 * 1000, 5 * 1000);

	pr_err("%s: %d\n", __func__, ++log);

	if (abov_tk_fw_mode_check(info) != 1) {
		input_err(true, &info->client->dev, "%s: err, flash mode is not: %d\n", __func__, ret);
		/*return 0;*/
	}

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);

	ret = abov_tk_flash_erase(info);
	msleep(1400);

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);

	for (ii = 1; ii <= count; ii++) {	/* start form 1,  for header info */

		addrH = (unsigned char)((address >> 8) & 0xFF);
		addrL = (unsigned char)(address & 0xFF);
		if (cmd == BUILT_IN)
			memcpy(data, &info->firm_data_bin->data[ii * 32], 32);
		else if (cmd == SDCARD)
			memcpy(data, &info->firm_data_ums[ii * 32], 32);

		ret = abov_tk_fw_write(info, &addrH, &addrL, data);
		if (ret < 0) {
			input_err(true, &info->client->dev, "%s: err, no device : %d\n", __func__, ret);
			return ret;
		}
		usleep_range(3 * 1000, 3 * 1000);

		abov_tk_check_busy(info);

		address += 0x20;

		memset(data, 0, 32);
	}

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);

	ret = abov_tk_i2c_read_checksum(info);

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);

	ret = abov_tk_fw_mode_exit(info);

	input_err(true, &info->client->dev, "%s: %d\n", __func__, ++log);


	gpio_direction_output(info->dtdata->gpio_en, 0);
	msleep(30);
	gpio_direction_output(info->dtdata->gpio_en, 1);
	msleep(100);

	return ret;


}


static void abov_release_fw(struct abov_tk_info *info, u8 cmd)
{
	switch(cmd) {
	case BUILT_IN:
		release_firmware(info->firm_data_bin);
		break;

	case SDCARD:
		kfree(info->firm_data_ums);
		break;

	default:
		break;
	}
}

static int abov_flash_fw(struct abov_tk_info *info, bool probe, u8 cmd)
{
	struct i2c_client *client = info->client;
	int retry = 2;
	int ret;
	int block_count;
	const u8 *fw_data;

	ret = get_tk_fw_version(info, probe);
	if (ret)
		info->fw_ver = 0;

	ret = abov_load_fw(info, cmd);
	if (ret) {
		input_err(true, &client->dev,
			"%s fw load fail\n", __func__);
		return ret;
	}

	switch (cmd) {
	case BUILT_IN:
		fw_data = info->firm_data_bin->data;
		break;

	case SDCARD:
		fw_data = info->firm_data_ums;
		break;

	default:
		return -1;
		/* break; */
	}

	block_count = (int)(info->firm_size / 32);

	while (retry--) {
		ret = abov_tk_fw_update(info, cmd);
		if (ret < 0)
			break;

		if (cmd == BUILT_IN) {
			if ((info->checksum_h != info->checksum_h_bin) ||
				(info->checksum_l != info->checksum_l_bin)) {
				input_err(true, &client->dev,
					"%s checksum fail.(0x%x,0x%x),(0x%x,0x%x) retry:%d\n",
					__func__, info->checksum_h, info->checksum_l,
					info->checksum_h_bin, info->checksum_l_bin, retry);
				ret = -1;
				continue;
			}
		}
		abov_tk_reset_for_bootmode(info);
		msleep(ABOV_RESET_DELAY);
		ret = get_tk_fw_version(info, true);
		if (ret) {
			input_err(true, &client->dev, "%s fw version read fail\n", __func__);
			ret = -1;
			continue;
		}

		if (info->fw_ver == 0) {
			input_err(true, &client->dev, "%s fw version fail (0x%x)\n",
				__func__, info->fw_ver);
			ret = -1;
			continue;
		}

		if ((cmd == BUILT_IN) && (info->fw_ver != info->fw_ver_bin)) {
			input_err(true, &client->dev, "%s fw version fail 0x%x, 0x%x\n",
				__func__, info->fw_ver, info->fw_ver_bin);
			ret = -1;
			continue;
		}
		ret = 0;
		break;
	}

	abov_release_fw(info, cmd);

	return ret;
}

static ssize_t touchkey_fw_update(struct device *dev,
			struct device_attribute *attr, const char *buf, size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int ret;
	u8 cmd;

	switch (*buf) {
	case 's':
	case 'S':
		cmd = BUILT_IN;
		break;
	case 'i':
	case 'I':
		cmd = SDCARD;
		break;
	default:
		info->fw_update_state = 2;
		goto touchkey_fw_update_out;
	}

	info->fw_update_state = 1;
	disable_irq(info->irq);
	info->enabled = false;

	if (cmd == BUILT_IN) {
		ret = abov_load_fw_kernel(info);
		if (ret) {
			input_err(true, &client->dev,
				"failed to abov_load_fw_kernel (%d)\n", ret);
		} else {
			input_err(true, &client->dev,
				"fw version read success (%d)\n", ret);
		}
	}
	ret = abov_flash_fw(info, false, cmd);
#ifdef GLOVE_MODE
	if (info->glovemode)
		abov_mode_enable(client, ABOV_GLOVE, CMD_ON);
#endif
	info->enabled = true;
	enable_irq(info->irq);
	if (ret) {
		input_err(true, &client->dev, "%s fail\n", __func__);
		/* info->fw_update_state = 2; */
		info->fw_update_state = 0;

	} else {
		input_info(true, &client->dev, "%s success\n", __func__);
		info->fw_update_state = 0;
	}

touchkey_fw_update_out:
	input_info(true, &client->dev, "%s : %d\n", __func__, info->fw_update_state);

	return count;
}

static ssize_t touchkey_fw_update_status(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int count = 0;

	input_info(true, &client->dev, "%s : %d\n", __func__, info->fw_update_state);

	if (info->fw_update_state == 0)
		count = snprintf(buf, PAGE_SIZE, "PASS\n");
	else if (info->fw_update_state == 1)
		count = snprintf(buf, PAGE_SIZE, "Downloading\n");
	else if (info->fw_update_state == 2)
		count = snprintf(buf, PAGE_SIZE, "Fail\n");

	return count;
}

static ssize_t touchkey_crc_check(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int ret;
	unsigned char data[3] = {0x1B, 0x00, 0x10};
	unsigned char checksum[2] = {0, };

	i2c_master_send(info->client, data, 3);
	usleep_range(50 * 1000, 50 * 1000);

	ret = abov_tk_i2c_read(client, 0x1B, checksum, 2);

	if (ret < 0) {
		input_err(true, &client->dev, "%s: i2c read fail\n", __func__);
		return snprintf(buf, PAGE_SIZE, "NG,0000\n");
	}

	input_info(true, &client->dev, "%s : CRC:%02x%02x, BIN:%02x%02x\n", __func__, \
		checksum[0], checksum[1], \
		info->checksum_h_bin, info->checksum_l_bin);

	if ((checksum[0] != info->checksum_h_bin) ||
		(checksum[1] != info->checksum_l_bin)) {
		return snprintf(buf, PAGE_SIZE, "NG,%02x%02x\n",\
			checksum[0], checksum[1]);

	} else {
		return snprintf(buf, PAGE_SIZE, "OK,%02x%02x\n",\
			checksum[0], checksum[1]);
	}
}


#ifdef GLOVE_MODE
static ssize_t abov_glove_mode(struct device *dev,
	 struct device_attribute *attr, const char *buf, size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int scan_buffer;
	int ret;
	u8 cmd;

	ret = sscanf(buf, "%d", &scan_buffer);
	if (ret != 1) {
		input_err(true, &client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(scan_buffer == 0 || scan_buffer == 1)) {
		input_err(true, &client->dev, "%s: wrong command(%d)\n",
			__func__, scan_buffer);
		return count;
	}

	if (!info->enabled)
		return count;

	if (info->glovemode == scan_buffer) {
		input_info(true, &client->dev, "%s same command(%d)\n",
			__func__, scan_buffer);
		return count;
	}

	if (scan_buffer == 1) {
		input_info(true, &client->dev, "%s glove mode\n", __func__);
		cmd = CMD_ON;
	} else {
		input_info(true, &client->dev, "%s normal mode\n", __func__);
		cmd = CMD_OFF;
	}

	ret = abov_mode_enable(client, ABOV_GLOVE, cmd);
	if (ret < 0) {
		input_err(true, &client->dev, "%s fail(%d)\n", __func__, ret);
		return count;
	}

	info->glovemode = scan_buffer;

	return count;
}

static ssize_t abov_glove_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", info->glovemode);
}
#endif

/* Concept for flip mode is not requested yet
  * So Just enter sar only mode & do SW_RESET(grip baseline re-cal)
  * when flip cover cmd is recieved
  */
static ssize_t flip_cover_mode_enable(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct abov_tk_info *info = dev_get_drvdata(dev);
	struct i2c_client *client = info->client;
	int flip_mode_on;

	sscanf(buf, "%d\n", &flip_mode_on);
	input_info(true, &client->dev, "%s : %d\n", __func__, flip_mode_on);

	if (!info->enabled)
		goto out;

#ifdef CONFIG_TOUCHKEY_GRIP
	if (flip_mode_on) {
		abov_grip_sw_reset(info);
		abov_sar_only_mode(info, 1);
	} else {
		abov_sar_only_mode(info, 0);
	}
#else
#ifdef GLOVE_MODE
	if (info->glovemode) {
		int ret;
		u8 cmd = CMD_ON;
		ret = abov_mode_enable(client, ABOV_GLOVE, cmd);
		if (ret < 0) {
			input_err(true, &client->dev, "%s glove mode fail(%d)\n", __func__, ret);
			goto out;
		}
	}
#endif
	/* Do nothing yet */
#endif

out:
	info->flip_mode = flip_mode_on;
	return count;
}

static DEVICE_ATTR(touchkey_threshold, S_IRUGO, touchkey_threshold_show, NULL);
static DEVICE_ATTR(brightness, S_IRUGO | S_IWUSR | S_IWGRP, NULL,
			touchkey_led_control);
#ifdef CONFIG_TOUCHKEY_GRIP
static DEVICE_ATTR(touchkey_grip_threshold, S_IRUGO, touchkey_grip_threshold_show, NULL);
static DEVICE_ATTR(touchkey_total_cap, S_IRUGO, touchkey_total_cap_show, NULL);
static DEVICE_ATTR(sar_enable, S_IRUGO | S_IWUSR | S_IWGRP, NULL, touchkey_sar_enable);
static DEVICE_ATTR(sw_reset, S_IRUGO | S_IWUSR | S_IWGRP, NULL, touchkey_grip_sw_reset);
static DEVICE_ATTR(touchkey_earjack, S_IRUGO | S_IWUSR | S_IWGRP, NULL, touchkey_sensing_change);
static DEVICE_ATTR(touchkey_grip, S_IRUGO, touchkey_grip_show, NULL);
static DEVICE_ATTR(touchkey_grip_baseline, S_IRUGO, touchkey_grip_baseline_show, NULL);
static DEVICE_ATTR(touchkey_grip_raw, S_IRUGO, touchkey_grip_raw_show, NULL);
static DEVICE_ATTR(touchkey_grip_gain, S_IRUGO, touchkey_grip_gain_show, NULL);
static DEVICE_ATTR(touchkey_grip_check, S_IRUGO, touchkey_grip_check_show, NULL);
#ifndef CONFIG_SAMSUNG_PRODUCT_SHIP
static DEVICE_ATTR(touchkey_sar_only_mode,  S_IRUGO | S_IWUSR | S_IWGRP,
			NULL, touchkey_mode_change);
static DEVICE_ATTR(touchkey_sar_press_threshold,  S_IRUGO | S_IWUSR | S_IWGRP,
			NULL, touchkey_sar_press_threshold_store);
static DEVICE_ATTR(touchkey_sar_release_threshold,  S_IRUGO | S_IWUSR | S_IWGRP,
			NULL, touchkey_sar_release_threshold_store);
#endif
static DEVICE_ATTR(grip_irq_count, S_IRUGO | S_IWUSR | S_IWGRP, touchkey_grip_irq_count_show, touchkey_grip_irq_count_store);
#endif
static DEVICE_ATTR(touchkey_recent, S_IRUGO, touchkey_menu_show, NULL);
static DEVICE_ATTR(touchkey_back, S_IRUGO, touchkey_back_show, NULL);
static DEVICE_ATTR(touchkey_recent_raw, S_IRUGO, touchkey_menu_raw_show, NULL);
static DEVICE_ATTR(touchkey_back_raw, S_IRUGO, touchkey_back_raw_show, NULL);
static DEVICE_ATTR(touchkey_chip_name, S_IRUGO, touchkey_chip_name, NULL);
static DEVICE_ATTR(touchkey_firm_version_phone, S_IRUGO, bin_fw_ver, NULL);
static DEVICE_ATTR(touchkey_firm_version_panel, S_IRUGO, read_fw_ver, NULL);
static DEVICE_ATTR(touchkey_firm_update, S_IRUGO | S_IWUSR | S_IWGRP, NULL,
			touchkey_fw_update);
static DEVICE_ATTR(touchkey_firm_update_status, S_IRUGO | S_IWUSR | S_IWGRP,
			touchkey_fw_update_status, NULL);
static DEVICE_ATTR(touchkey_crc_check, S_IRUGO | S_IWUSR | S_IWGRP,
			touchkey_crc_check, NULL);

#ifdef GLOVE_MODE
static DEVICE_ATTR(glove_mode, S_IRUGO | S_IWUSR | S_IWGRP,
			abov_glove_mode_show, abov_glove_mode);
#endif
static DEVICE_ATTR(flip_mode, S_IRUGO | S_IWUSR | S_IWGRP, NULL,
		   flip_cover_mode_enable);


static struct attribute *sec_touchkey_attributes[] = {
	&dev_attr_touchkey_threshold.attr,
	&dev_attr_brightness.attr,
#ifdef CONFIG_TOUCHKEY_GRIP
	&dev_attr_touchkey_grip_threshold.attr,
	&dev_attr_touchkey_total_cap.attr,
	&dev_attr_sar_enable.attr,
	&dev_attr_sw_reset.attr,
	&dev_attr_touchkey_earjack.attr,
	&dev_attr_touchkey_grip.attr,
	&dev_attr_touchkey_grip_baseline.attr,
	&dev_attr_touchkey_grip_raw.attr,
	&dev_attr_touchkey_grip_gain.attr,
	&dev_attr_touchkey_grip_check.attr,
#ifndef CONFIG_SAMSUNG_PRODUCT_SHIP
	&dev_attr_touchkey_sar_only_mode.attr,
	&dev_attr_touchkey_sar_press_threshold.attr,
	&dev_attr_touchkey_sar_release_threshold.attr,
#endif
	&dev_attr_grip_irq_count.attr,
#endif
	&dev_attr_touchkey_recent.attr,
	&dev_attr_touchkey_back.attr,
	&dev_attr_touchkey_recent_raw.attr,
	&dev_attr_touchkey_chip_name.attr,
	&dev_attr_touchkey_back_raw.attr,
	&dev_attr_touchkey_firm_version_phone.attr,
	&dev_attr_touchkey_firm_version_panel.attr,
	&dev_attr_touchkey_firm_update.attr,
	&dev_attr_touchkey_firm_update_status.attr,
	&dev_attr_touchkey_crc_check.attr,
#ifdef GLOVE_MODE
	&dev_attr_glove_mode.attr,
#endif
	&dev_attr_flip_mode.attr,
	NULL,
};

static struct attribute_group sec_touchkey_attr_group = {
	.attrs = sec_touchkey_attributes,
};

static int abov_tk_fw_check(struct abov_tk_info *info)
{
	struct i2c_client *client = info->client;
	int ret;
	bool force = false;

	if (info->dtdata->bringup) {
		input_info(true, &client->dev, "%s: firmware update skip, bring up\n", __func__);
		return 0;
	}

	ret = get_tk_fw_version(info, true);
	if (ret) {
		input_err(true, &client->dev,
			"%s: i2c fail...[%d], addr[%d]\n",
			__func__, ret, info->client->addr);
#ifdef LED_TWINKLE_BOOTING
		/* regard I2C fail & LCD attached status as no TKEY device */
		if (!lcdtype) {
			input_err(true, &client->dev,
				"%s : LCD is not attached\n", __func__);
				return ret;
		}
#endif
	}
	ret = abov_load_fw_kernel(info);
	if (ret) {
		input_err(true, &client->dev,
			"failed to abov_load_fw_kernel (%d)\n", ret);
	} else {
		input_err(true, &client->dev,
			"fw version read success (%d)\n", ret);
	}

	if (info->md_ver != info->md_ver_bin) {
		input_err(true, &client->dev,
			"MD version is different.(IC %x, BN %x). Do force FW update\n",
			info->md_ver, info->md_ver_bin);
		force = true;
	}

	if (info->fw_ver < info->fw_ver_bin || info->fw_ver > 0xf0 || force == true) {
		input_err(true, &client->dev, "excute tk firmware update (0x%x -> 0x%x)\n",
			info->fw_ver, info->fw_ver_bin);
		ret = abov_flash_fw(info, true, BUILT_IN);
		if (ret) {
			input_err(true, &client->dev,
				"failed to abov_flash_fw (%d)\n", ret);
		} else {
			input_err(true, &client->dev,
				"fw update success\n");
		}
	}

	return ret;
}

int abov_power(struct abov_tk_info *info, bool on)
{
	struct abov_touchkey_devicetree_data *dtdata = info->dtdata;
	int ret = 0;

	if (gpio_is_valid(dtdata->gpio_en))
		gpio_direction_output(dtdata->gpio_en, on);

	/* 1.8V on,off control. */
	if (!dtdata->vdd_io_alwayson) {
		if (!IS_ERR_OR_NULL(dtdata->vdd_io_vreg)) {
			if (on)
				ret = regulator_enable(dtdata->vdd_io_vreg);
			else
				ret = regulator_disable(dtdata->vdd_io_vreg);
			input_err(true, &info->client->dev, "[TKEY] %s: iovdd reg %s %s\n",
					__func__, on ? "enable" : "disable",
					ret ? "NG" : "OK");
		}
	}

	input_info(true, &info->client->dev, "[TKEY] %s: %s ", __func__, on ? "on" : "off");
	if (gpio_is_valid(dtdata->gpio_en))
		input_info(true, &info->client->dev, "vdd_en:%d ", gpio_get_value(dtdata->gpio_en));
	if (!IS_ERR_OR_NULL(dtdata->vdd_io_vreg))
		input_info(true, &info->client->dev, "vio_reg:%d%s ",
				regulator_is_enabled(dtdata->vdd_io_vreg),
				dtdata->vdd_io_alwayson ? "(always on)" : "");
	if (!dtdata->vdd_led) {
		input_err(true, &info->client->dev, "%s [TKEY] %s VDD get regulator\n", __func__, SECLOG);
		dtdata->vdd_led = devm_regulator_get(&info->client->dev, "abov,lvdd");
		if (IS_ERR(dtdata->vdd_led)) {
			input_err(true, &info->client->dev, "%s [TKEY] %s annot get vdd\n", __func__, SECLOG);
			dtdata->vdd_led = NULL;
			return -ENOMEM;
		}

		if (!regulator_get_voltage(dtdata->vdd_led))
			regulator_set_voltage(dtdata->vdd_led, 3300000, 3300000);
	}

	
	if (on) {
		if (regulator_is_enabled(dtdata->vdd_led)) {
			input_err(true, &info->client->dev, "%s [TKEY] %s Regulator already enabled\n", __func__, SECLOG);
			return 0;
		}
		ret = regulator_enable(dtdata->vdd_led);
		if (ret)
			input_err(true, &info->client->dev, "%s [TKEY] %s failed to enable\n", __func__, SECLOG);
		usleep_range(10000, 11000);
	} else {
		ret = regulator_disable(dtdata->vdd_led);
		if (ret)
			input_err(true, &info->client->dev, "%s [TKEY] %s failed to disabl\n", __func__, SECLOG);
	}

	return ret;
}

static void abov_set_ta_status(struct abov_tk_info *info)
{
	u8 cmd_data = 0x10;
	u8 cmd_ta;
	int ret = 0;

	input_info(true, &info->client->dev, "%s ta_connected %d\n", __func__, ta_connected);

	if (info->enabled == false) {
		input_info(true, &info->client->dev, "%s status of ic is off\n", __func__);
		return;
	}

	if (ta_connected) {
		cmd_ta = 0x10;
	} else {
		cmd_ta = 0x20;
	}

	ret = abov_tk_i2c_write(info->client, ABOV_TSPTA, &cmd_ta, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s fail(%d)\n", __func__, ret);
	}

	ret = abov_tk_i2c_write(info->client, ABOV_SW_RESET, &cmd_data, 1);
	if (ret < 0) {
		input_err(true, &info->client->dev, "%s sw reset fail(%d)\n", __func__, ret);
	}
}

#ifdef CONFIG_VBUS_NOTIFIER
int abov_touchkey_vbus_notification(struct notifier_block *nb,
		unsigned long cmd, void *data)
{
	struct abov_tk_info *info = container_of(nb, struct abov_tk_info, vbus_nb);
	vbus_status_t vbus_type = *(vbus_status_t *)data;

	input_info(true, &info->client->dev, "%s cmd=%lu, vbus_type=%d\n", __func__, cmd, vbus_type);

	switch (vbus_type) {
	case STATUS_VBUS_HIGH:
		input_info(true, &info->client->dev, "%s : attach\n",__func__);
		ta_connected = true;
		break;
	case STATUS_VBUS_LOW:
		input_info(true, &info->client->dev, "%s : detach\n",__func__);
		ta_connected = false;

		break;
	default:
		break;
	}

	abov_set_ta_status(info);

	return 0;
}
#endif

static int abov_pinctrl_configure(struct abov_tk_info *info, bool active)
{
	struct pinctrl_state *set_state;
	int retval;

	if (active) {
		set_state =
			pinctrl_lookup_state(info->pinctrl,
						"on_irq");
		if (IS_ERR(set_state)) {
			input_err(true, &info->client->dev, "%s: cannot get ts pinctrl active state\n", __func__);
			return PTR_ERR(set_state);
		}
	} else {
		set_state =
			pinctrl_lookup_state(info->pinctrl,
						"off_irq");
		if (IS_ERR(set_state)) {
			input_err(true, &info->client->dev, "%s: cannot get gpiokey pinctrl sleep state\n", __func__);
			return PTR_ERR(set_state);
		}
	}
	retval = pinctrl_select_state(info->pinctrl, set_state);
	if (retval) {
		input_err(true, &info->client->dev, "%s: cannot set ts pinctrl active state\n", __func__);
		return retval;
	}

	input_info(true, &info->client->dev, "%s %s\n",
			__func__, active ? "ACTIVE" : "SUSPEND");

	return 0;
}

int abov_gpio_reg_init(struct device *dev,
			struct abov_touchkey_devicetree_data *dtdata)
{
	int ret = 0;

	if (dtdata->gpio_rst > 0) {
		ret = gpio_request(dtdata->gpio_rst, "tkey_gpio_rst");
		if(ret < 0){
			input_err(true, dev, "unable to request gpio_rst\n");
			return ret;
		}
	}
	ret = gpio_request(dtdata->gpio_int, "tkey_gpio_int");
	if (ret < 0) {
		input_err(true, dev, "unable to request gpio_int\n");
		return ret;
	}

	ret = gpio_request(dtdata->gpio_en, "tkey_gpio_en");
	if (ret < 0) {
		input_err(true, dev, "unable to request gpio_en\n");
		return ret;
	}

	dtdata->vdd_io_vreg = regulator_get(dev, "vddo");
	if (IS_ERR_OR_NULL(dtdata->vdd_io_vreg)) {
		regulator_put(dtdata->vdd_io_vreg);
		dtdata->vdd_io_vreg = NULL;
		input_err(true, dev, "dtdata->vdd_io_vreg get error, ignoring\n");
	} else {
		regulator_set_voltage(dtdata->vdd_io_vreg, 1800000, 1800000);

		/* 1.8V always on : for reduce probe time in bootup */
		if (dtdata->vdd_io_alwayson) {
			ret = regulator_enable(dtdata->vdd_io_vreg);
			if (ret) {
				input_err(true, dev, "[TKEY] %s: iovdd reg enable fail\n",
					__func__);
			}
		}

	}

	dtdata->power = abov_power;

	return ret;
}

#ifdef CONFIG_OF
static int abov_parse_dt(struct device *dev,
			struct abov_touchkey_devicetree_data *dtdata)
{
	struct device_node *np = dev->of_node;
	int ret;

	dtdata->gpio_rst = of_get_named_gpio(np, "abov,rst-gpio", 0);
	if (dtdata->gpio_rst < 0)
		input_err(true, dev, "unable to get gpio_rst\n");

	dtdata->gpio_en = of_get_named_gpio(np, "abov,tkey_en-gpio", 0);
	if (dtdata->gpio_en < 0) {
		input_err(true, dev, "unable to get gpio_en\n");
		return dtdata->gpio_en;
	}

	dtdata->gpio_int = of_get_named_gpio(np, "abov,irq-gpio", 0);
	if (dtdata->gpio_int < 0) {
		input_err(true, dev, "unable to get gpio_int\n");
		return dtdata->gpio_int;
	}

	dtdata->gpio_scl = of_get_named_gpio(np, "abov,scl-gpio", 0);
	if (dtdata->gpio_scl < 0) {
		input_err(true, dev, "unable to get gpio_scl\n");
		return dtdata->gpio_scl;
	}

	dtdata->gpio_sda = of_get_named_gpio(np, "abov,sda-gpio", 0);
	if (dtdata->gpio_sda < 0) {
		input_err(true, dev, "unable to get gpio_sda\n");
		return dtdata->gpio_sda;
	}

	dtdata->vdd_io_alwayson = of_property_read_bool(np, "abov,vddo_alwayson");
	if (dtdata->vdd_io_alwayson < 0) {
		input_err(true, dev, "unable to get vdd_io_alwayson\n");
		dtdata->vdd_io_alwayson = 0;
	}

	ret = of_property_read_u32(np, "abov,bringup", &dtdata->bringup);
	if (ret < 0)
		dtdata->bringup = 0;

	ret = of_property_read_u32(np, "abov,firmup_cmd", &dtdata->firmup_cmd);
	if (ret < 0)
		dtdata->firmup_cmd = 0;

	of_property_read_string(np, "abov,firmware_name", &dtdata->fw_name);
	
	dtdata->ta_notifier = of_property_read_bool(np, "abov,ta-notifier");
	dtdata->not_support_key = of_property_read_bool(np, "abov,not_support_key");

	input_info(true, dev, "%s: [GPIO] en:%d, int:%d, scl:%d, sda:%d, vdd_io:%d\n"
			"bringup:%d, firmupcmd:%x, %s: fw_name: %s\n",
			__func__, dtdata->gpio_en, dtdata->gpio_int, dtdata->gpio_scl,
			dtdata->gpio_sda, dtdata->vdd_io_alwayson, dtdata->bringup,
			dtdata->firmup_cmd, __func__, dtdata->fw_name);

	return 0;
}
#else
static int abov_parse_dt(struct device *dev,
			struct abov_touchkey_devicetree_data *dtdata)
{
	return -ENODEV;
}
#endif

static int abov_tk_probe(struct i2c_client *client,
				  const struct i2c_device_id *id)
{
	struct abov_tk_info *info;
	struct input_dev *input_dev;
	int ret = 0;

	pr_err("%s++\n", __func__);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		input_err(true, &client->dev,
			"i2c_check_functionality fail\n");
		return -EIO;
	}

#if !(defined(LED_TWINKLE_BOOTING) || defined(CONFIG_TOUCHKEY_GRIP))
	if (!lcdtype) {
		input_err(true, &client->dev,
			"%s : LCD is not attached\n", __func__);
		return -ENODEV;
	}
#endif

	info = kzalloc(sizeof(struct abov_tk_info), GFP_KERNEL);
	if (!info) {
		input_err(true, &client->dev, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto err_alloc;
	}

	input_dev = input_allocate_device();
	if (!input_dev) {
		input_err(true, &client->dev,
			"Failed to allocate memory for input device\n");
		ret = -ENOMEM;
		goto err_input_alloc;
	}

	info->client = client;
	info->input_dev = input_dev;
	info->probe_done = false;
#ifdef CONFIG_TOUCHKEY_GRIP
	wake_lock_init(&info->touchkey_wake_lock, WAKE_LOCK_SUSPEND, "touchkey wake lock");
#endif

	if (client->dev.of_node) {
		struct abov_touchkey_devicetree_data *dtdata;

		dtdata = devm_kzalloc(&client->dev,
				sizeof(struct abov_touchkey_devicetree_data), GFP_KERNEL);
		if (!dtdata) {
			input_err(true, &client->dev, "Failed to allocate memory\n");
			ret = -ENOMEM;
			goto err_config;
		}

		ret = abov_parse_dt(&client->dev, dtdata);
		if (ret)
			goto err_config;

		info->dtdata = dtdata;
	} else
		info->dtdata = client->dev.platform_data;

	if (info->dtdata == NULL) {
		input_err(true, &client->dev,"failed to get platform data\n");
		goto err_config;
	}

	/* Get pinctrl if target uses pinctrl */
	info->pinctrl = devm_pinctrl_get(&client->dev);
	if (IS_ERR(info->pinctrl)) {
		if (PTR_ERR(info->pinctrl) == -EPROBE_DEFER)
			goto err_config;

		input_err(true, &client->dev,"%s: Target does not use pinctrl\n", __func__);
		info->pinctrl = NULL;
	}

	if (info->pinctrl) {
		ret = abov_pinctrl_configure(info, true);
		if (ret)
			input_err(true, &client->dev,"%s: cannot set ts pinctrl active state\n", __func__);
	}

	ret = abov_gpio_reg_init(&client->dev, info->dtdata);
	if (ret) {
		input_err(true, &client->dev, "failed to init reg\n");
		goto pwr_config;
	}

	if (info->dtdata->power) {
		info->dtdata->power(info, true);
		msleep(ABOV_RESET_DELAY);
	}

	info->irq = -1;
	client->irq = gpio_to_irq(info->dtdata->gpio_int);
	mutex_init(&info->lock);

	info->touchkey_count = sizeof(touchkey_keycode) / sizeof(int);
	i2c_set_clientdata(client, info);

	ret = abov_tk_fw_check(info);
	if (ret) {
		input_err(true, &client->dev,
			"failed to firmware check (%d)\n", ret);
		goto err_reg_input_dev;
	}

	snprintf(info->phys, sizeof(info->phys),
		 "%s/input0", dev_name(&client->dev));
	input_dev->name = "sec_touchkey";
	input_dev->phys = info->phys;
	input_dev->id.bustype = BUS_HOST;
	input_dev->dev.parent = &client->dev;
#ifdef USE_OPEN_CLOSE
	input_dev->open = abov_tk_input_open;
	input_dev->close = abov_tk_input_close;
#endif
	set_bit(EV_KEY, input_dev->evbit);
	if(!info->dtdata->not_support_key) {
		set_bit(KEY_RECENT, input_dev->keybit);
		set_bit(KEY_BACK, input_dev->keybit);
	}
#ifdef CONFIG_TOUCHKEY_GRIP
	set_bit(KEY_CP_GRIP, input_dev->keybit);
#endif
	set_bit(EV_LED, input_dev->evbit);
	set_bit(LED_MISC, input_dev->ledbit);
	input_set_drvdata(input_dev, info);

	ret = input_register_device(input_dev);
	if (ret) {
		input_err(true, &client->dev, "failed to register input dev (%d)\n",
			ret);
		goto err_reg_input_dev;
	}

	info->enabled = true;

	if (!info->dtdata->irq_flag) {
		input_err(true, &client->dev, "no irq_flag\n");
		ret = request_threaded_irq(client->irq, NULL, abov_tk_interrupt,
			IRQF_TRIGGER_LOW | IRQF_ONESHOT, ABOV_TK_NAME, info);
	} else {
		ret = request_threaded_irq(client->irq, NULL, abov_tk_interrupt,
			info->dtdata->irq_flag, ABOV_TK_NAME, info);
	}
	if (ret < 0) {
		input_err(true, &client->dev, "Failed to register interrupt ret:%d \n", ret);
		goto err_req_irq;
	}
	info->irq = client->irq;

	sec_touchkey = sec_device_create(info, "sec_touchkey");
	if (IS_ERR(sec_touchkey))
		input_err(true, &client->dev,
		"Failed to create device for the touchkey sysfs\n");

	ret = sysfs_create_group(&sec_touchkey->kobj,
		&sec_touchkey_attr_group);
	if (ret)
		input_err(true, &client->dev, "Failed to create sysfs group\n");

	ret = sysfs_create_link(&sec_touchkey->kobj,
		&info->input_dev->dev.kobj, "input");
	if (ret < 0) {
		input_err(true, &info->client->dev,
			"%s: Failed to create input symbolic link\n",
			__func__);
	}

#ifdef LED_TWINKLE_BOOTING
	if (!lcdtype) {
		input_err(true, &client->dev,
			"%s : LCD is not connected. so start LED twinkle\n", __func__);
		INIT_DELAYED_WORK(&info->led_twinkle_work, led_twinkle_work);
		info->led_twinkle_check =  1;
		schedule_delayed_work(&info->led_twinkle_work, msecs_to_jiffies(400));
	}
#endif
#ifdef CONFIG_TOUCHKEY_GRIP
	device_init_wakeup(&client->dev, true);
#endif

#ifdef CONFIG_VBUS_NOTIFIER
	if (info->dtdata->ta_notifier) {
		vbus_notifier_register(&info->vbus_nb, abov_touchkey_vbus_notification,
					VBUS_NOTIFY_DEV_CHARGER);
	}
#endif

	input_err(true, &client->dev, "%s done\n", __func__);
	info->probe_done = true;
	
	return 0;

err_req_irq:
	input_unregister_device(input_dev);
	input_err(true, &client->dev, "%s end %p\n", __func__, input_dev);
	input_dev = NULL;
err_reg_input_dev:
	info->dtdata->power(info, false);
	mutex_destroy(&info->lock);
pwr_config:
err_config:
#ifdef CONFIG_TOUCHKEY_GRIP
	wake_lock_destroy(&info->touchkey_wake_lock);
#endif
	if (input_dev)
		input_free_device(input_dev);
err_input_alloc:
	kfree(info);
err_alloc:
	return ret;

}

#ifdef LED_TWINKLE_BOOTING
static void led_twinkle_work(struct work_struct *work)
{
	struct abov_tk_info *info = container_of(work, struct abov_tk_info,
						led_twinkle_work.work);
	static bool led_on = 1;
	static int count;

	input_err(true, &info->client->dev, "%s, on=%d, c=%d\n",__func__, led_on, count++);

	if (info->led_twinkle_check == 1) {
		touchkey_led_set(info, led_on);

		if (led_on)
			led_on = 0;
		else
			led_on = 1;

		schedule_delayed_work(&info->led_twinkle_work, msecs_to_jiffies(400));
	} else {
		if (led_on == 0)
			touchkey_led_set(info, 0);
	}
}
#endif

static int abov_tk_remove(struct i2c_client *client)
{
	struct abov_tk_info *info = i2c_get_clientdata(client);

	if (info->enabled)
		info->dtdata->power(info, false);

	info->enabled = false;
#ifdef CONFIG_TOUCHKEY_GRIP
	device_init_wakeup(&client->dev, false);
	wake_lock_destroy(&info->touchkey_wake_lock);
#endif

	if (info->irq >= 0)
		free_irq(info->irq, info);
	input_unregister_device(info->input_dev);
	input_free_device(info->input_dev);
	kfree(info);

	return 0;
}

static void abov_tk_shutdown(struct i2c_client *client)
{
	struct abov_tk_info *info = i2c_get_clientdata(client);
	u8 cmd = CMD_LED_OFF;

	info->enabled = false;

	abov_tk_i2c_write(client, ABOV_LED_CONTROL, &cmd, 1);
}

#ifndef CONFIG_TOUCHKEY_GRIP
static int abov_tk_stop(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct abov_tk_info *info = i2c_get_clientdata(client);

	if (!info->enabled)
		return 0;

	input_info(true, &client->dev, "%s: users=%d\n", __func__,
		   info->input_dev->users);

	disable_irq(info->irq);
	info->enabled = false;
	release_all_fingers(info);

	if (info->dtdata->power)
		info->dtdata->power(info, false);

	return 0;
}

static int abov_tk_start(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct abov_tk_info *info = i2c_get_clientdata(client);
	u8 led_data;

	if (!info->probe_done)
		return 0;

	if (info->enabled)
		return 0;

	input_info(true, &client->dev, "%s: users=%d\n", __func__,
		   info->input_dev->users);

	if (info->dtdata->power) {
		info->dtdata->power(info, true);
		msleep(ABOV_RESET_DELAY);
	}

	info->enabled = true;

	if (abov_touchled_cmd_reserved && abov_touchkey_led_status == CMD_LED_ON) {
		abov_touchled_cmd_reserved = 0;
		led_data = abov_touchkey_led_status;

		abov_tk_i2c_write(client, ABOV_LED_CONTROL, &led_data, 1);

		input_info(true, &client->dev, "%s: LED reserved %s\n",
			__func__, (led_data == CMD_LED_ON) ? "on" : "off");
	}
	enable_irq(info->irq);

	return 0;
}
#endif

#ifdef USE_OPEN_CLOSE
static int abov_tk_input_open(struct input_dev *dev)
{
	struct abov_tk_info *info = input_get_drvdata(dev);
	if (!info->probe_done)
		return 0;
#ifdef CONFIG_TOUCHKEY_GRIP
	input_info(true, &info->client->dev,
			"%s: sar_enable(%d)\n", __func__, info->sar_enable);
	if (info->flip_mode)
		abov_sar_only_mode(info, 1);
	else
		abov_sar_only_mode(info, 0);

	if (device_may_wakeup(&info->client->dev))
		disable_irq_wake(info->irq);
#else
	gpio_direction_input(info->dtdata->gpio_scl);
	gpio_direction_input(info->dtdata->gpio_sda);
	abov_tk_start(&info->client->dev);
	if (info->dtdata->ta_notifier && ta_connected) {
		abov_set_ta_status(info);
	}

#ifdef GLOVE_MODE
	if (info->glovemode)
		abov_mode_enable(client, ABOV_GLOVE, CMD_ON);
#endif
#endif
	return 0;
}
static void abov_tk_input_close(struct input_dev *dev)
{
	struct abov_tk_info *info = input_get_drvdata(dev);
	if (!info->probe_done)
		return;
#ifdef LED_TWINKLE_BOOTING
	info->led_twinkle_check = 0;
#endif
#ifdef CONFIG_TOUCHKEY_GRIP
	input_info(true, &info->client->dev,
			"%s: sar_enable(%d)\n", __func__, info->sar_enable);
	abov_sar_only_mode(info, 1);

	if (device_may_wakeup(&info->client->dev))
		enable_irq_wake(info->irq);
#else
	abov_tk_stop(&info->client->dev);
#endif
}
#endif

#ifdef CONFIG_PM
static int abov_pm_suspend(struct device *dev)
{
	return 0;
}

static int abov_pm_resume(struct device *dev)
{
	return 0;
}
#endif

static const struct i2c_device_id abov_tk_id[] = {
	{ABOV_TK_NAME, 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, abov_tk_id);

#ifdef CONFIG_OF
static struct of_device_id abov_match_table[] = {
	{ .compatible = "abov,a96t3x6",},
	{ },
};
#else
#define abov_match_table NULL
#endif

#ifdef CONFIG_PM
static const struct dev_pm_ops abov_pm_ops = {
	.suspend = abov_pm_suspend,
	.resume = abov_pm_resume,
};
#endif

static struct i2c_driver abov_tk_driver = {
	.probe = abov_tk_probe,
	.remove = abov_tk_remove,
	.shutdown = abov_tk_shutdown,
	.driver = {
		.name = ABOV_TK_NAME,
		.of_match_table = abov_match_table,
#if (!defined(CONFIG_HAS_EARLYSUSPEND) && !defined(USE_OPEN_CLOSE))
		.pm = &abov_pm_ops,
#endif

	},
	.id_table = abov_tk_id,
};

#if defined(CONFIG_BATTERY_SAMSUNG) && !defined(CONFIG_TOUCHKEY_GRIP)
extern unsigned int lpcharge;
#endif
static int __init touchkey_init(void)
{
	pr_err("%s %s: abov,a96t3x6\n", SECLOG, __func__);
#if defined(CONFIG_BATTERY_SAMSUNG) && !defined(CONFIG_TOUCHKEY_GRIP)
	if (lpcharge == 1) {
		pr_notice("%s %s : LPM Charging Mode!!\n", SECLOG, __func__);
		return 0;
	}
#endif

	return i2c_add_driver(&abov_tk_driver);
}

static void __exit touchkey_exit(void)
{
	i2c_del_driver(&abov_tk_driver);
}

module_init(touchkey_init);
module_exit(touchkey_exit);

/* Module information */
MODULE_AUTHOR("Samsung Electronics");
MODULE_DESCRIPTION("Touchkey driver for Abov A96T3X6 chip");
MODULE_LICENSE("GPL");
