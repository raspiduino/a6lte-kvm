/*
 * Copyright (c) Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/lcd.h>
#include <linux/backlight.h>
#include <linux/of_device.h>
#include <video/mipi_display.h>
#include <linux/i2c.h>
#include <linux/module.h>

#include "../dsim.h"
#include "../decon.h"
#include "dsim_panel.h"

#include "s6d7at0b_m10lte_param.h"
#include "dd.h"
#include "../decon_board.h"
#include "../decon_notify.h"

#define PANEL_STATE_SUSPENED	0
#define PANEL_STATE_RESUMED	1
#define PANEL_STATE_SUSPENDING	2

#define S6D7AT0B_ID_REG			0x04	/* LCD ID1,ID2,ID3 */
#define S6D7AT0B_ID_LEN			3
#define BRIGHTNESS_REG			0x51

#define VGL_READ_REG			0xF4
#define VGL_READ_LEN			5

#define get_bit(value, shift, width)	((value >> shift) & (GENMASK(width - 1, 0)))

#define DSI_WRITE(cmd, size)		do {				\
	ret = dsim_write_hl_data(lcd, cmd, size);			\
	if (ret < 0)							\
		dev_err(&lcd->ld->dev, "%s: failed to write %s\n", __func__, #cmd);	\
} while (0)

struct lcd_info {
	unsigned int			connected;
	unsigned int			bl;
	unsigned int			brightness;
	unsigned int			current_bl;
	unsigned int			state;

	struct lcd_device		*ld;
	struct backlight_device		*bd;

	union {
		struct {
			u8		reserved;
			u8		id[S6D7AT0B_ID_LEN];
		};
		u32			value;
	} id_info;

	int						lux;

	struct dsim_device		*dsim;
	struct mutex			lock;

	struct notifier_block		fb_notif_panel;
	struct i2c_client		*backlight_client;

	unsigned char			vgl_reg[VGL_READ_LEN+1];
};

static int dsim_write_hl_data(struct lcd_info *lcd, const u8 *cmd, u32 cmdsize)
{
	int ret = 0;
	int retry = 2;

	if (!lcd->connected)
		return ret;

try_write:
	if (cmdsize == 1)
		ret = dsim_write_data(lcd->dsim, MIPI_DSI_DCS_SHORT_WRITE, cmd[0], 0);
	else if (cmdsize == 2)
		ret = dsim_write_data(lcd->dsim, MIPI_DSI_DCS_SHORT_WRITE_PARAM, cmd[0], cmd[1]);
	else
		ret = dsim_write_data(lcd->dsim, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)cmd, cmdsize);

	if (ret < 0) {
		if (--retry)
			goto try_write;
		else
			dev_err(&lcd->ld->dev, "%s: fail. %02x, ret: %d\n", __func__, cmd[0], ret);
	}

	return ret;
}

#if defined(CONFIG_SEC_FACTORY)
static int dsim_read_hl_data(struct lcd_info *lcd, u8 addr, u32 size, u8 *buf)
{
	int ret = 0, rx_size = 0;
	int retry = 2;

	if (!lcd->connected)
		return ret;

try_read:
	rx_size = dsim_read_data(lcd->dsim, MIPI_DSI_DCS_READ, (u32)addr, size, buf);
	dev_info(&lcd->ld->dev, "%s: %02x, %d, %d\n", __func__, addr, size, rx_size);
	if (rx_size != size) {
		if (--retry)
			goto try_read;
		else {
			dev_err(&lcd->ld->dev, "%s: fail. %02x, %d\n", __func__, addr, rx_size);
			ret = -EPERM;
		}
	}

	return ret;
}
#endif

static int lm3632_array_write(struct i2c_client *client, u8 *ptr, u8 len)
{
	int i = 0;
	int ret = 0;
	struct lcd_info *lcd = i2c_get_clientdata(client);

	if (!lcdtype) {
		dev_info(&lcd->ld->dev, "%s: lcdtype: %d\n", __func__, lcdtype);
		return ret;
	}

	if (len % 2) {
		dev_info(&lcd->ld->dev, "%s: length(%d) invalid\n", __func__, len);
		return ret;
	}

	for (i = 0; i < len; i += 2) {
		ret = i2c_smbus_write_byte_data(lcd->backlight_client, ptr[i], ptr[i + 1]);
		if (ret < 0)
			dev_err(&lcd->ld->dev, "%s: fail. %d, %2x, %2x\n", __func__, ret, ptr[i], ptr[i + 1]);
	}

	return ret;
}

static int dsim_panel_set_brightness(struct lcd_info *lcd, int force)
{
	int ret = 0;
	unsigned char bl_reg[3];

	mutex_lock(&lcd->lock);

	lcd->brightness = lcd->bd->props.brightness;

	if (!force && lcd->state != PANEL_STATE_RESUMED) {
		dev_info(&lcd->ld->dev, "%s: panel is not active state\n", __func__);
		goto exit;
	}

	bl_reg[0] = BRIGHTNESS_REG;
	bl_reg[1] = get_bit(brightness_table[lcd->brightness], 4, 8);
	bl_reg[2] = get_bit(brightness_table[lcd->brightness], 0, 4) << 4 | BIT(0);

	dev_info(&lcd->ld->dev, "%s: brightness: %d, %d(%x %x), lx: %d\n", __func__,
		lcd->brightness, brightness_table[lcd->brightness], bl_reg[1], bl_reg[2], lcd->lux);

	DSI_WRITE(SEQ_TEST_KEY_ON_9F, ARRAY_SIZE(SEQ_TEST_KEY_ON_9F));

	DSI_WRITE(bl_reg, ARRAY_SIZE(bl_reg));

	DSI_WRITE(SEQ_TEST_KEY_OFF_9F, ARRAY_SIZE(SEQ_TEST_KEY_OFF_9F));

exit:
	mutex_unlock(&lcd->lock);

	return ret;
}

static int panel_get_brightness(struct backlight_device *bd)
{
	struct lcd_info *lcd = bl_get_data(bd);

	return brightness_table[lcd->brightness];
}

static int panel_set_brightness(struct backlight_device *bd)
{
	int ret = 0;
	struct lcd_info *lcd = bl_get_data(bd);

	if (lcd->state == PANEL_STATE_RESUMED) {
		ret = dsim_panel_set_brightness(lcd, 0);
		if (ret < 0)
			dev_err(&lcd->ld->dev, "%s: failed to set brightness\n", __func__);
	}

	return ret;
}

static const struct backlight_ops panel_backlight_ops = {
	.get_brightness = panel_get_brightness,
	.update_status = panel_set_brightness,
};

static int s6d7at0b_read_init_info(struct lcd_info *lcd)
{
	struct panel_private *priv = &lcd->dsim->priv;

	priv->lcdconnected = lcd->connected = lcdtype ? 1 : 0;

	lcd->id_info.id[0] = (lcdtype & 0xFF0000) >> 16;
	lcd->id_info.id[1] = (lcdtype & 0x00FF00) >> 8;
	lcd->id_info.id[2] = (lcdtype & 0x0000FF) >> 0;

	dev_info(&lcd->ld->dev, "%s: %x\n", __func__, cpu_to_be32(lcd->id_info.value));

	return 0;
}

#if defined(CONFIG_SEC_FACTORY)
static int s6d7at0b_read_id(struct lcd_info *lcd)
{
	struct panel_private *priv = &lcd->dsim->priv;
	int ret = 0;

	lcd->id_info.value = 0;
	priv->lcdconnected = lcd->connected = lcdtype ? 1 : 0;

	ret = dsim_read_hl_data(lcd, S6D7AT0B_ID_REG, S6D7AT0B_ID_LEN, lcd->id_info.id);
	if (ret < 0 || !lcd->id_info.value) {
		priv->lcdconnected = lcd->connected = 0;
		dev_err(&lcd->ld->dev, "%s: connected lcd is invalid\n", __func__);
	}

	dev_info(&lcd->ld->dev, "%s: %x\n", __func__, cpu_to_be32(lcd->id_info.value));

	return ret;
}

static int vgl_read_reg(struct lcd_info *lcd)
{
	int ret = 0;
	unsigned char buf[VGL_READ_LEN] = {0, };
	unsigned int pwrctl_cmd_cnt = VGL_READ_LEN + 1;

	ret = dsim_read_hl_data(lcd, VGL_READ_REG, VGL_READ_LEN, buf);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: read fail\n", __func__);

	lcd->vgl_reg[0] = VGL_READ_REG;

	memcpy(&lcd->vgl_reg[1], buf, VGL_READ_LEN);

	dev_info(&lcd->ld->dev, "%s: %*ph\n", __func__, pwrctl_cmd_cnt, lcd->vgl_reg);

	return ret;
}
#endif

static int s6d7at0b_displayon_late(struct lcd_info *lcd)
{
	int ret = 0;

	dev_info(&lcd->ld->dev, "%s\n", __func__);

	DSI_WRITE(SEQ_TEST_KEY_ON_9F, ARRAY_SIZE(SEQ_TEST_KEY_ON_9F));
	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
	DSI_WRITE(SEQ_TEST_KEY_ON_FC, ARRAY_SIZE(SEQ_TEST_KEY_ON_FC));


	DSI_WRITE(SEQ_DISPLAY_ON, ARRAY_SIZE(SEQ_DISPLAY_ON));
	DSI_WRITE(SEQ_TE_ON, ARRAY_SIZE(SEQ_TE_ON));

	DSI_WRITE(SEQ_TEST_KEY_OFF_9F, ARRAY_SIZE(SEQ_TEST_KEY_OFF_9F));
	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
	DSI_WRITE(SEQ_TEST_KEY_OFF_FC, ARRAY_SIZE(SEQ_TEST_KEY_OFF_FC));

	dsim_panel_set_brightness(lcd, 1);

	return ret;
}

static int s6d7at0b_exit(struct lcd_info *lcd)
{
	int ret = 0;

	dev_info(&lcd->ld->dev, "%s\n", __func__);

	DSI_WRITE(SEQ_TEST_KEY_ON_9F, ARRAY_SIZE(SEQ_TEST_KEY_ON_9F));

	DSI_WRITE(SEQ_DISPLAY_OFF, ARRAY_SIZE(SEQ_DISPLAY_OFF));
	DSI_WRITE(SEQ_SLEEP_IN, ARRAY_SIZE(SEQ_SLEEP_IN));

	DSI_WRITE(SEQ_TEST_KEY_OFF_9F, ARRAY_SIZE(SEQ_TEST_KEY_OFF_9F));

	msleep(100);

	return ret;
}

static int s6d7at0b_init(struct lcd_info *lcd)
{
	int ret = 0;

	dev_info(&lcd->ld->dev, "%s: ++\n", __func__);

#if defined(CONFIG_SEC_FACTORY)
	s6d7at0b_read_id(lcd);
#endif

	DSI_WRITE(SEQ_TEST_KEY_ON_9F, ARRAY_SIZE(SEQ_TEST_KEY_ON_9F));
	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
	DSI_WRITE(SEQ_TEST_KEY_ON_FC, ARRAY_SIZE(SEQ_TEST_KEY_ON_FC));

	DSI_WRITE(SEQ_S6D7AT0B_71, ARRAY_SIZE(SEQ_S6D7AT0B_71));
	DSI_WRITE(SEQ_S6D7AT0B_73, ARRAY_SIZE(SEQ_S6D7AT0B_73));
	DSI_WRITE(SEQ_S6D7AT0B_B1, ARRAY_SIZE(SEQ_S6D7AT0B_B1));
	DSI_WRITE(SEQ_S6D7AT0B_B3, ARRAY_SIZE(SEQ_S6D7AT0B_B3));
	DSI_WRITE(SEQ_S6D7AT0B_BA, ARRAY_SIZE(SEQ_S6D7AT0B_BA));
	DSI_WRITE(SEQ_S6D7AT0B_BB, ARRAY_SIZE(SEQ_S6D7AT0B_BB));
	DSI_WRITE(SEQ_S6D7AT0B_EC, ARRAY_SIZE(SEQ_S6D7AT0B_EC));
	DSI_WRITE(SEQ_S6D7AT0B_ED, ARRAY_SIZE(SEQ_S6D7AT0B_ED));
	DSI_WRITE(SEQ_S6D7AT0B_EE, ARRAY_SIZE(SEQ_S6D7AT0B_EE));
	DSI_WRITE(SEQ_S6D7AT0B_EF, ARRAY_SIZE(SEQ_S6D7AT0B_EF));
	DSI_WRITE(SEQ_S6D7AT0B_F2, ARRAY_SIZE(SEQ_S6D7AT0B_F2));
	DSI_WRITE(SEQ_S6D7AT0B_B0, ARRAY_SIZE(SEQ_S6D7AT0B_B0));
	DSI_WRITE(SEQ_S6D7AT0B_F4, ARRAY_SIZE(SEQ_S6D7AT0B_F4));
	DSI_WRITE(SEQ_S6D7AT0B_F9, ARRAY_SIZE(SEQ_S6D7AT0B_F9));
	DSI_WRITE(SEQ_S6D7AT0B_FE, ARRAY_SIZE(SEQ_S6D7AT0B_FE));
	DSI_WRITE(SEQ_S6D7AT0B_C0, ARRAY_SIZE(SEQ_S6D7AT0B_C0));
	DSI_WRITE(SEQ_S6D7AT0B_C1, ARRAY_SIZE(SEQ_S6D7AT0B_C1));
	DSI_WRITE(SEQ_S6D7AT0B_C8, ARRAY_SIZE(SEQ_S6D7AT0B_C8));
	DSI_WRITE(SEQ_S6D7AT0B_E8, ARRAY_SIZE(SEQ_S6D7AT0B_E8));
	DSI_WRITE(SEQ_S6D7AT0B_E9, ARRAY_SIZE(SEQ_S6D7AT0B_E9));
	DSI_WRITE(SEQ_S6D7AT0B_EA, ARRAY_SIZE(SEQ_S6D7AT0B_EA));
	DSI_WRITE(SEQ_S6D7AT0B_EB, ARRAY_SIZE(SEQ_S6D7AT0B_EB));

	DSI_WRITE(SEQ_S6D7AT0B_51, ARRAY_SIZE(SEQ_S6D7AT0B_51));
	DSI_WRITE(SEQ_S6D7AT0B_53, ARRAY_SIZE(SEQ_S6D7AT0B_53));
	DSI_WRITE(SEQ_S6D7AT0B_55, ARRAY_SIZE(SEQ_S6D7AT0B_55));

#if defined(CONFIG_SEC_FACTORY)
	vgl_read_reg(lcd);
#endif

	DSI_WRITE(SEQ_SLEEP_OUT, ARRAY_SIZE(SEQ_SLEEP_OUT));
	msleep(120);

	DSI_WRITE(SEQ_TEST_KEY_OFF_9F, ARRAY_SIZE(SEQ_TEST_KEY_OFF_9F));
	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
	DSI_WRITE(SEQ_TEST_KEY_OFF_FC, ARRAY_SIZE(SEQ_TEST_KEY_OFF_FC));

	dev_info(&lcd->ld->dev, "%s: --\n", __func__);

	return ret;
}

static int fb_notifier_callback(struct notifier_block *self,
				unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	struct lcd_info *lcd = NULL;
	int fb_blank;

	switch (event) {
	case FB_EVENT_BLANK:
		break;
	default:
		return NOTIFY_DONE;
	}

	lcd = container_of(self, struct lcd_info, fb_notif_panel);

	fb_blank = *(int *)evdata->data;

	dev_info(&lcd->ld->dev, "%s: %d\n", __func__, fb_blank);

	if (evdata->info->node)
		return NOTIFY_DONE;

	if (fb_blank == FB_BLANK_UNBLANK)
		s6d7at0b_displayon_late(lcd);

	return NOTIFY_DONE;
}

static int lm3632_probe(struct i2c_client *client,
	const struct i2c_device_id *id)
{
	struct lcd_info *lcd = NULL;
	int ret = 0;

	if (id && id->driver_data)
		lcd = (struct lcd_info *)id->driver_data;

	if (!lcd) {
		dsim_err("%s: failed to find driver_data for lcd\n", __func__);
		ret = -EINVAL;
		goto exit;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&lcd->ld->dev, "%s: need I2C_FUNC_I2C\n", __func__);
		ret = -ENODEV;
		goto exit;
	}

	i2c_set_clientdata(client, lcd);

	lcd->backlight_client = client;

	dev_info(&lcd->ld->dev, "%s: %s %s\n", __func__, dev_name(&client->adapter->dev), of_node_full_name(client->dev.of_node));

exit:
	return ret;
}

static struct i2c_device_id lm3632_id[] = {
	{"lm3632", 0},
	{},
};

MODULE_DEVICE_TABLE(i2c, lm3632_id);

static const struct of_device_id lm3632_i2c_dt_ids[] = {
	{ .compatible = "i2c,lm3632" },
	{ }
};

MODULE_DEVICE_TABLE(of, lm3632_i2c_dt_ids);

static struct i2c_driver lm3632_i2c_driver = {
	.driver = {
		.owner	= THIS_MODULE,
		.name	= "lm3632",
		.of_match_table	= of_match_ptr(lm3632_i2c_dt_ids),
	},
	.id_table = lm3632_id,
	.probe = lm3632_probe,
};

static int s6d7at0b_probe(struct lcd_info *lcd)
{
	int ret = 0;

	dev_info(&lcd->ld->dev, "+ %s\n", __func__);

	lcd->bd->props.max_brightness = EXTEND_BRIGHTNESS;
	lcd->bd->props.brightness = UI_DEFAULT_BRIGHTNESS;

	lcd->state = PANEL_STATE_RESUMED;
	lcd->lux = -1;

	ret = s6d7at0b_read_init_info(lcd);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: failed to init information\n", __func__);

	lcd->fb_notif_panel.notifier_call = fb_notifier_callback;
	decon_register_notifier(&lcd->fb_notif_panel);

	lm3632_id->driver_data = (kernel_ulong_t)lcd;
	i2c_add_driver(&lm3632_i2c_driver);

#if defined(CONFIG_SEC_FACTORY)
	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
	vgl_read_reg(lcd);
	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
#endif

	dev_info(&lcd->ld->dev, "- %s\n", __func__);

	return 0;
}

static ssize_t lcd_type_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "BOE_%02X%02X%02X\n", lcd->id_info.id[0], lcd->id_info.id[1], lcd->id_info.id[2]);

	return strlen(buf);
}

static ssize_t window_type_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%02x %02x %02x\n", lcd->id_info.id[0], lcd->id_info.id[1], lcd->id_info.id[2]);

	return strlen(buf);
}

static ssize_t lux_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%d\n", lcd->lux);

	return strlen(buf);
}

static ssize_t lux_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);
	int value;
	int rc;

	rc = kstrtoint(buf, 0, &value);
	if (rc < 0)
		return rc;

	if (lcd->lux != value) {
		mutex_lock(&lcd->lock);
		lcd->lux = value;
		mutex_unlock(&lcd->lock);
	}

	return size;
}

static ssize_t cabc_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);
	unsigned int value;
	int ret;

	if (lcd->state != PANEL_STATE_RESUMED)
		return -EINVAL;

	ret = kstrtouint(buf, 0, &value);
	if (ret < 0)
		return ret;

	if (value == 1) {
		DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
		DSI_WRITE(SEQ_TEST_KEY_ON_FC, ARRAY_SIZE(SEQ_TEST_KEY_ON_FC));
		DSI_WRITE(SEQ_TEST_KEY_ON_9F, ARRAY_SIZE(SEQ_TEST_KEY_ON_9F));
		DSI_WRITE(SEQ_S6D7AT0B_CABC_ON, ARRAY_SIZE(SEQ_S6D7AT0B_CABC_ON));
		DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
		DSI_WRITE(SEQ_TEST_KEY_OFF_FC, ARRAY_SIZE(SEQ_TEST_KEY_OFF_FC));
		DSI_WRITE(SEQ_TEST_KEY_OFF_9F, ARRAY_SIZE(SEQ_TEST_KEY_OFF_9F));
	} else {
		DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
		DSI_WRITE(SEQ_TEST_KEY_ON_FC, ARRAY_SIZE(SEQ_TEST_KEY_ON_FC));
		DSI_WRITE(SEQ_TEST_KEY_ON_9F, ARRAY_SIZE(SEQ_TEST_KEY_ON_9F));
		DSI_WRITE(SEQ_S6D7AT0B_55, ARRAY_SIZE(SEQ_S6D7AT0B_55));
		DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
		DSI_WRITE(SEQ_TEST_KEY_OFF_FC, ARRAY_SIZE(SEQ_TEST_KEY_OFF_FC));
		DSI_WRITE(SEQ_TEST_KEY_OFF_9F, ARRAY_SIZE(SEQ_TEST_KEY_OFF_9F));
	}

	dev_info(&lcd->ld->dev, "%s: %d\n", __func__, value);

	return size;
}

static DEVICE_ATTR(lcd_type, 0444, lcd_type_show, NULL);
static DEVICE_ATTR(window_type, 0444, window_type_show, NULL);
static DEVICE_ATTR(lux, 0644, lux_show, lux_store);
static DEVICE_ATTR(cabc, 0644, NULL, cabc_store);

static struct attribute *lcd_sysfs_attributes[] = {
	&dev_attr_lcd_type.attr,
	&dev_attr_window_type.attr,
	&dev_attr_lux.attr,
	&dev_attr_cabc.attr,
	NULL,
};

static const struct attribute_group lcd_sysfs_attr_group = {
	.attrs = lcd_sysfs_attributes,
};

static void lcd_init_sysfs(struct lcd_info *lcd)
{
	int ret = 0;
	struct i2c_client *clients[] = {lcd->backlight_client, NULL};

	ret = sysfs_create_group(&lcd->ld->dev.kobj, &lcd_sysfs_attr_group);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "failed to add lcd sysfs\n");

	init_debugfs_backlight(lcd->bd, brightness_table, clients);

	init_debugfs_param("blic", &LM3632_INIT, 8 * sizeof(u8), ARRAY_SIZE(LM3632_INIT), 2);
}

static int dsim_panel_probe(struct dsim_device *dsim)
{
	int ret = 0;
	struct lcd_info *lcd;

	dsim->priv.par = lcd = kzalloc(sizeof(struct lcd_info), GFP_KERNEL);
	if (!lcd) {
		pr_err("%s: failed to allocate for lcd\n", __func__);
		ret = -ENOMEM;
		goto probe_err;
	}

	lcd->ld = lcd_device_register("panel", dsim->dev, lcd, NULL);
	if (IS_ERR(lcd->ld)) {
		pr_err("%s: failed to register lcd device\n", __func__);
		ret = PTR_ERR(lcd->ld);
		goto probe_err;
	}

	lcd->bd = backlight_device_register("panel", dsim->dev, lcd, &panel_backlight_ops, NULL);
	if (IS_ERR(lcd->bd)) {
		pr_err("%s: failed to register backlight device\n", __func__);
		ret = PTR_ERR(lcd->bd);
		goto probe_err;
	}

	mutex_init(&lcd->lock);

	lcd->dsim = dsim;
	ret = s6d7at0b_probe(lcd);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: failed to probe panel\n", __func__);

	lcd_init_sysfs(lcd);

	dev_info(&lcd->ld->dev, "%s: %s: done\n", kbasename(__FILE__), __func__);
probe_err:
	return ret;
}

static int dsim_panel_resume_early(struct dsim_device *dsim)
{
	struct lcd_info *lcd = dsim->priv.par;

	dev_info(&lcd->ld->dev, "+ %s\n", __func__);

	/* VSP VSN setting, So, It should be called before power enabling */

	lm3632_array_write(lcd->backlight_client, LM3632_INIT, ARRAY_SIZE(LM3632_INIT));

	dev_info(&lcd->ld->dev, "- %s: %d, %d\n", __func__, lcd->state, lcd->connected);

	return 0;
}

static int dsim_panel_displayon(struct dsim_device *dsim)
{
	struct lcd_info *lcd = dsim->priv.par;

	dev_info(&lcd->ld->dev, "+ %s: %d\n", __func__, lcd->state);

	if (lcd->state == PANEL_STATE_SUSPENED)
		s6d7at0b_init(lcd);

	mutex_lock(&lcd->lock);
	lcd->state = PANEL_STATE_RESUMED;
	mutex_unlock(&lcd->lock);

	dev_info(&lcd->ld->dev, "- %s: %d, %d\n", __func__, lcd->state, lcd->connected);

	return 0;
}

static int dsim_panel_suspend(struct dsim_device *dsim)
{
	struct lcd_info *lcd = dsim->priv.par;
	int ret = 0;

	dev_info(&lcd->ld->dev, "+ %s: %d\n", __func__, lcd->state);

	if (lcd->state == PANEL_STATE_SUSPENED)
		goto exit;

	lcd->state = PANEL_STATE_SUSPENDING;

	s6d7at0b_exit(lcd);

	mutex_lock(&lcd->lock);
	lcd->state = PANEL_STATE_SUSPENED;
	mutex_unlock(&lcd->lock);

	dev_info(&lcd->ld->dev, "- %s: %d, %d\n", __func__, lcd->state, lcd->connected);

exit:
	return ret;
}

struct mipi_dsim_lcd_driver s6d7at0b_mipi_lcd_driver = {
	.name		= "s6d7at0b",
	.probe		= dsim_panel_probe,
	.resume_early	= dsim_panel_resume_early,
	.displayon	= dsim_panel_displayon,
	.suspend	= dsim_panel_suspend,
};
