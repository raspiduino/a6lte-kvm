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
#include <linux/ctype.h>
#include <video/mipi_display.h>
#include "../dsim.h"
#include "dsim_panel.h"

#include "s6e8aa5x01_j5y17_param.h"

#if defined(CONFIG_EXYNOS_DECON_MDNIE_LITE)
#include "mdnie.h"
#include "mdnie_lite_table_j5y17.h"
#endif

#ifdef CONFIG_DISPLAY_USE_INFO
#include "dpui.h"

#define	DPUI_VENDOR_NAME	"SDC"
#define DPUI_MODEL_NAME		"AMS520KT10"
#endif

#define POWER_IS_ON(pwr)					(pwr <= FB_BLANK_NORMAL)
#define LEVEL_IS_HBM(brightness)		(brightness == EXTEND_BRIGHTNESS)
#define LEVEL_IS_ACL_OFF(brightness)		(brightness >= UI_MAX_BRIGHTNESS)

#define DSI_WRITE(cmd, size)		do {				\
	ret = dsim_write_hl_data(lcd, cmd, size);			\
	if (ret < 0)							\
		dev_err(&lcd->ld->dev, "%s: failed to write %s\n", __func__, #cmd);	\
} while (0)

#ifdef SMART_DIMMING_DEBUG
#define smtd_dbg(format, arg...)	printk(format, ##arg)
#else
#define smtd_dbg(format, arg...)
#endif

#define get_bit(value, shift, width)	((value >> shift) & (GENMASK(width - 1, 0)))

union aor_info {
	u32 value;
	struct {
		u8 aor_1;
		u8 aor_2;
		u16 reserved;
	};
};

union elvss_info {
	u32 value;
	struct {
		u8 mpscon;
		u8 offset;
		u8 offset_base;
		u8 reserved;
	};
};

struct lcd_info {
	unsigned int			connected;
	unsigned int			bl;
	unsigned int			brightness;
	unsigned int			acl_enable;
	unsigned int			current_acl;
	unsigned int			current_bl;
	union elvss_info		current_elvss;
	union aor_info			current_aor;
	unsigned int			current_hbm;
	unsigned int			current_tset;
	unsigned int			state;

	struct lcd_device		*ld;
	struct backlight_device		*bd;
	struct device			svc_dev;
	struct dynamic_aid_param_t	daid;

	unsigned char			elvss_table[IBRIGHTNESS_HBM_MAX][TEMP_MAX][ELVSS_CMD_CNT];
	unsigned char			gamma_table[IBRIGHTNESS_HBM_MAX][GAMMA_CMD_CNT];

	unsigned char			(*aor_table)[AID_CMD_CNT];
	unsigned char			**acl_table;
	unsigned char			**opr_table;
	unsigned char			**hbm_table;

	unsigned char			hbm_gamma[HBM_GAMMA_CMD_CNT];

	int				temperature;
	unsigned int			temperature_index;

	union {
		struct {
			u8		reserved;
			u8		id[LDI_LEN_ID];
		};
		u32			value;
	} id_info;
	unsigned char			code[LDI_LEN_CHIP_ID];
	unsigned char			date[LDI_LEN_DATE];
	unsigned int			coordinate[2];
	unsigned char			manufacture_info[LDI_LEN_MANUFACTURE_INFO];

	unsigned int			adaptive_control;
	int						lux;
	struct class			*mdnie_class;

	struct dsim_device		*dsim;
	struct mutex			lock;

#ifdef CONFIG_DISPLAY_USE_INFO
	struct notifier_block	dpui_notif;
#endif
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

static void dsim_panel_gamma_ctrl(struct lcd_info *lcd, u8 force)
{
	u8 *gamma = NULL;
	int ret = 0;

	/* gamma addr : 0xCA */
	/* HBM gamma addr : 0xB4 */

	gamma = lcd->gamma_table[lcd->bl];
	if (gamma == NULL) {
		dev_err(&lcd->ld->dev, "%s: failed to get gamma\n", __func__);
		goto exit;
	}

	if (force)
		goto gamma_update;
	else if (lcd->current_bl != lcd->bl)
		goto gamma_update;
	else
		goto exit;

gamma_update:
	DSI_WRITE(gamma, GAMMA_CMD_CNT);

exit:
	return;
}

static void dsim_panel_aid_ctrl(struct lcd_info *lcd, u8 force)
{
	int ret = 0;
	int bl = 0;
	union aor_info aor_value;

	if (lcd->brightness > UI_MAX_BRIGHTNESS) /* for interpolation and HBM */
		bl = UI_MAX_BRIGHTNESS + 1;
	else
		bl = lcd->brightness;

	if (lcd->aor_table[bl] == NULL) {
		dev_err(&lcd->ld->dev, "%s: failed to get aid value\n", __func__);
		goto exit;
	}

	aor_value.aor_1 = lcd->aor_table[bl][LDI_OFFSET_AOR_1];
	aor_value.aor_2 = lcd->aor_table[bl][LDI_OFFSET_AOR_2];


	DSI_WRITE(lcd->aor_table[bl], AID_CMD_CNT);
	lcd->current_aor.value = aor_value.value;
	dev_info(&lcd->ld->dev, "aor: %x\n", lcd->current_aor.value);

exit:
	return;
}

static int dsim_panel_set_tset(struct lcd_info *lcd, int force)
{
	int ret = 0;
	unsigned char tset = 0;
	u8 tset_cmd[2] = {0xB8, };

	tset_cmd[1] = ((lcd->temperature < 0) ? BIT(7) : 0) | abs(lcd->temperature);

	if (force || lcd->current_tset != tset_cmd[1]) {
		lcd->current_tset = tset_cmd[1];
		DSI_WRITE(SEQ_TSET_GP, ARRAY_SIZE(SEQ_TSET_GP));
		DSI_WRITE(tset_cmd, ARRAY_SIZE(tset_cmd));
		dev_info(&lcd->ld->dev, "temperature: %d, tset: %d\n", lcd->temperature, tset);
	}

	return ret;
}

static void dsim_panel_set_elvss(struct lcd_info *lcd, u8 force)
{
	u8 *elvss = NULL;
	int ret = 0;
	union elvss_info elvss_value;

	elvss = lcd->elvss_table[lcd->bl][lcd->temperature_index];
	if (elvss == NULL) {
		dev_err(&lcd->ld->dev, "%s: failed to get elvss value\n", __func__);
		goto exit;
	}

	elvss_value.mpscon = elvss[LDI_OFFSET_ELVSS_1];
	elvss_value.offset = elvss[LDI_OFFSET_ELVSS_2];
	elvss_value.offset_base = elvss[LDI_OFFSET_ELVSS_3];

	if (force)
		goto elvss_update;
	else if (lcd->current_elvss.value != elvss_value.value)
		goto elvss_update;
	else
		goto exit;

elvss_update:
	DSI_WRITE(elvss, ELVSS_CMD_CNT);

	lcd->current_elvss.value = elvss_value.value;
	dev_info(&lcd->ld->dev, "elvss: %x\n", lcd->current_elvss.value);
exit:
	return;
}

static int dsim_panel_set_acl(struct lcd_info *lcd, int force)
{
	int ret = 0, level = ACL_STATUS_15P;

	if (lcd->acl_enable)
		goto acl_update;

	if (LEVEL_IS_ACL_OFF(lcd->brightness) && !lcd->adaptive_control)
		level = ACL_STATUS_0P;
	else if (lcd->brightness > UI_MAX_BRIGHTNESS) /* Not in gallery mode & brightness > 255 */
		level = ACL_STATUS_8P;

acl_update:
	if (force || lcd->current_acl != level) {

		if (level == ACL_STATUS_15P) {
			SEQ_ACL_SET[1] = SEQ_OPR_ACL_ON[0];
			SEQ_ACL_SET[2] = SEQ_ACL_START_POINT_50[0];
			SEQ_ACL_SET[4] = SEQ_ACL_PERCENT_15[0];
		} else if (level == ACL_STATUS_8P) {
			SEQ_ACL_SET[1] = SEQ_OPR_ACL_ON[0];
			SEQ_ACL_SET[2] = SEQ_ACL_START_POINT_60[0];
			SEQ_ACL_SET[4] = SEQ_ACL_PERCENT_8[0];
		} else { //ACL_STATUS_0P
			SEQ_ACL_SET[1] = SEQ_OPR_ACL_OFF[0];
			if (lcd->brightness == UI_MAX_BRIGHTNESS) {
				SEQ_ACL_SET[2] = SEQ_ACL_START_POINT_50[0];
				SEQ_ACL_SET[4] = SEQ_ACL_PERCENT_15[0];
			} else{
				SEQ_ACL_SET[2] = SEQ_ACL_START_POINT_60[0];
				SEQ_ACL_SET[4] = SEQ_ACL_PERCENT_8[0];
			}
		}

		DSI_WRITE(SEQ_ACL_SET, ARRAY_SIZE(SEQ_ACL_SET));
		if (level == ACL_STATUS_0P)
			DSI_WRITE(SEQ_ACL_OFF, ARRAY_SIZE(SEQ_ACL_OFF));
		else
			DSI_WRITE(SEQ_ACL_ON, ARRAY_SIZE(SEQ_ACL_ON));

		lcd->current_acl = level;
		dev_info(&lcd->ld->dev, "acl: %d, brightness: %d, adaptive_control: %d\n", lcd->current_acl, lcd->brightness, lcd->adaptive_control);
	}

	return ret;
}

static int dsim_panel_set_hbm(struct lcd_info *lcd, int force)
{
	int ret = 0, level = LEVEL_IS_HBM(lcd->brightness);

	if (force || lcd->current_hbm != level) {

		lcd->current_hbm = level;
		dev_info(&lcd->ld->dev, "hbm: %d, brightness: %d\n", lcd->current_hbm, lcd->brightness);
	}

	return ret;
}

static int low_level_set_brightness(struct lcd_info *lcd, int force)
{
	int ret = 0;

	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));

	dsim_panel_gamma_ctrl(lcd, force);

	dsim_panel_aid_ctrl(lcd, force);

	dsim_panel_set_tset(lcd, force);

	dsim_panel_set_elvss(lcd, force);

	dsim_panel_set_hbm(lcd, force);

	dsim_panel_set_acl(lcd, force);

	DSI_WRITE(SEQ_GAMMA_UPDATE, ARRAY_SIZE(SEQ_GAMMA_UPDATE));

	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));

	return 0;
}

static int get_backlight_level_from_brightness(int brightness)
{
	return brightness_table[brightness];
}

static int dsim_panel_set_brightness(struct lcd_info *lcd, int force)
{
	int ret = 0;

	mutex_lock(&lcd->lock);

	lcd->brightness = lcd->bd->props.brightness;

	lcd->bl = get_backlight_level_from_brightness(lcd->brightness);

	if (!force && lcd->state != PANEL_STATE_RESUMED) {
		dev_info(&lcd->ld->dev, "%s: panel is not active state\n", __func__);
		goto exit;
	}

	ret = low_level_set_brightness(lcd, force);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: failed to set brightness : %d\n", __func__, index_brightness_table[lcd->bl]);

	lcd->current_bl = lcd->bl;

	dev_info(&lcd->ld->dev, "brightness: %d, bl: %d, nit: %d, lx: %d\n", lcd->brightness, lcd->bl, index_brightness_table[lcd->bl], lcd->lux);
exit:
	mutex_unlock(&lcd->lock);

	return ret;
}

static int panel_get_brightness(struct backlight_device *bd)
{
	struct lcd_info *lcd = bl_get_data(bd);

	return index_brightness_table[lcd->bl];
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


static void init_dynamic_aid(struct lcd_info *lcd)
{
	lcd->daid.vreg = VREG_OUT_X1000;
	lcd->daid.iv_tbl = index_voltage_table;
	lcd->daid.iv_max = IV_MAX;
	lcd->daid.mtp = kzalloc(IV_MAX * CI_MAX * sizeof(int), GFP_KERNEL);
	lcd->daid.gamma_default = gamma_default;
	lcd->daid.formular = gamma_formula;
	lcd->daid.vt_voltage_value = vt_voltage_value;

	lcd->daid.ibr_tbl = index_brightness_table;
	lcd->daid.ibr_max = IBRIGHTNESS_MAX;

	lcd->daid.offset_color = (const struct rgb_t(*)[])offset_color;
	lcd->daid.iv_ref = index_voltage_reference;
	lcd->daid.m_gray = m_gray;
}

/* V255(msb is separated) ~ VT -> VT ~ V255(msb is not separated) and signed bit */
static void reorder_reg2mtp(u8 *reg, int *mtp)
{
	int j, c, v;

	for (c = 0, j = 0; c < CI_MAX; c++, j++) {
		if (reg[j++] & 0x01)
			mtp[(IV_MAX-1)*CI_MAX+c] = reg[j] * (-1);
		else
			mtp[(IV_MAX-1)*CI_MAX+c] = reg[j];
	}

	for (v = IV_MAX - 2; v >= 0; v--) {
		for (c = 0; c < CI_MAX; c++, j++) {
			if (reg[j] & 0x80)
				mtp[CI_MAX*v+c] = (reg[j] & 0x7F) * (-1);
			else
				mtp[CI_MAX*v+c] = reg[j];
		}
	}
}

/* VT ~ V255(msb is not separated) -> V255(msb is separated) ~ VT */
/* array idx zero (reg[0]) is reserved for gamma command address (0xCA) */
static void reorder_gamma2reg(int *gamma, u8 *reg)
{
	int j, c, v;
	int *pgamma;

	v = IV_MAX - 1;
	pgamma = &gamma[v * CI_MAX];
	for (c = 0, j = 1; c < CI_MAX; c++, pgamma++) {
		if (*pgamma & 0x100)
			reg[j++] = 1;
		else
			reg[j++] = 0;

		reg[j++] = *pgamma & 0xff;
	}

	for (v = IV_MAX - 2; v > IV_VT; v--) {
		pgamma = &gamma[v * CI_MAX];
		for (c = 0; c < CI_MAX; c++, pgamma++)
			reg[j++] = *pgamma;
	}

	v = IV_VT;
	pgamma = &gamma[v * CI_MAX];
	reg[j++] = pgamma[CI_RED] << 4 | pgamma[CI_GREEN];
	reg[j++] = pgamma[CI_BLUE];
}

static void init_mtp_data(struct lcd_info *lcd, u8 *mtp_data)
{
	int i, c;
	int *mtp = lcd->daid.mtp;
	u8 tmp[IV_MAX * CI_MAX + CI_MAX] = {0, };

	memcpy(tmp, mtp_data, LDI_LEN_MTP);

	/* C8h 31th Para: VT R */
	/* C8h 32th Para: VT G */
	/* C8h 32th Para: VT B */
	tmp[30] = get_bit(mtp_data[30], 0, 4);
	tmp[31] = get_bit(mtp_data[31], 0, 4);
	tmp[32] = get_bit(mtp_data[32], 0, 4);

	reorder_reg2mtp(tmp, mtp);

	smtd_dbg("MTP_Offset_Value\n");
	for (i = 0; i < IV_MAX; i++) {
		for (c = 0; c < CI_MAX; c++)
			smtd_dbg("%4d ", mtp[i*CI_MAX+c]);
		smtd_dbg("\n");
	}
}

static int init_gamma(struct lcd_info *lcd, u8 *mtp_data)
{
	int i, j;
	int ret = 0;
	int **gamma;

	/* allocate memory for local gamma table */
	gamma = kcalloc(IBRIGHTNESS_HBM_MAX, sizeof(int *), GFP_KERNEL);
	if (!gamma) {
		pr_err("failed to allocate gamma table\n");
		ret = -ENOMEM;
		goto err_alloc_gamma_table;
	}

	for (i = 0; i < IBRIGHTNESS_HBM_MAX; i++) {
		gamma[i] = kcalloc(IV_MAX*CI_MAX, sizeof(int), GFP_KERNEL);
		if (!gamma[i]) {
			pr_err("failed to allocate gamma\n");
			ret = -ENOMEM;
			goto err_alloc_gamma;
		}
	}

	/* pre-allocate memory for gamma table */
	for (i = 0; i < IBRIGHTNESS_MAX; i++)
		memcpy(&lcd->gamma_table[i], SEQ_GAMMA_CONDITION_SET, GAMMA_CMD_CNT);

	/* calculate gamma table */
	init_mtp_data(lcd, mtp_data);
	dynamic_aid(lcd->daid, gamma);

	/* relocate gamma order */
	for (i = 0; i < IBRIGHTNESS_MAX; i++)
		reorder_gamma2reg(gamma[i], lcd->gamma_table[i]);

	for (i = 0; i < IBRIGHTNESS_HBM_MAX; i++) {
		smtd_dbg("Gamma [%3d] = ", lcd->daid.ibr_tbl[i]);
		for (j = 0; j < GAMMA_CMD_CNT; j++)
			smtd_dbg("%4d ", lcd->gamma_table[i][j]);
		smtd_dbg("\n");
	}

	/* free local gamma table */
	for (i = 0; i < IBRIGHTNESS_MAX; i++)
		kfree(gamma[i]);
	kfree(gamma);

	return 0;

err_alloc_gamma:
	while (i > 0) {
		kfree(gamma[i-1]);
		i--;
	}
	kfree(gamma);
err_alloc_gamma_table:
	return ret;
}

static int s6e8aa5x01_read_info(struct lcd_info *lcd, u8 reg, u32 len, u8 *buf)
{
	int ret = 0, i;

	/* s6e8aa5x01 need some delay between "dsi read functions" */
	usleep_range(1000, 1100);

	ret = dsim_read_hl_data(lcd, reg, len, buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail. %02x, ret: %d\n", __func__, reg, ret);
		goto exit;
	}

	smtd_dbg("%s: %02xh\n", __func__, reg);
	for (i = 0; i < len; i++)
		smtd_dbg("%02dth value is %02x, %3d\n", i + 1, buf[i], buf[i]);

exit:
	return ret;
}

static int s6e8aa5x01_read_id(struct lcd_info *lcd)
{
	struct panel_private *priv = &lcd->dsim->priv;
	int ret = 0;

	lcd->id_info.value = 0;
	priv->lcdconnected = lcd->connected = lcdtype ? 1 : 0;

	ret = s6e8aa5x01_read_info(lcd, LDI_REG_ID, LDI_LEN_ID, lcd->id_info.id);
	if (ret < 0 || !lcd->id_info.value) {
		priv->lcdconnected = lcd->connected = 0;
		dev_err(&lcd->ld->dev, "%s: connected lcd is invalid\n", __func__);
	}

	dev_info(&lcd->ld->dev, "%s: %x\n", __func__, cpu_to_be32(lcd->id_info.value));

	return ret;
}

static int s6e8aa5x01_read_mtp(struct lcd_info *lcd, unsigned char *buf)
{
	int ret = 0;

	ret = s6e8aa5x01_read_info(lcd, LDI_REG_MTP, LDI_LEN_MTP, buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto exit;
	}

exit:
	return ret;
}

static int s6e8aa5x01_read_coordinate(struct lcd_info *lcd)
{
	int ret = 0;
	unsigned char buf[LDI_LEN_COORDINATE] = {0, };

	/* coordinate 0xA1 1st~4th */
	ret = s6e8aa5x01_read_info(lcd, LDI_REG_COORDINATE, LDI_LEN_COORDINATE, buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto exit;
	}

	lcd->coordinate[0] = buf[0] << 8 | buf[1];	/* X */
	lcd->coordinate[1] = buf[2] << 8 | buf[3];	/* Y */

exit:
	return ret;
}

static int s6e8aa5x01_read_manufacture_info(struct lcd_info *lcd)
{
	int ret = 0;
	unsigned char buf[LDI_GPARA_MANUFACTURE_INFO + LDI_LEN_MANUFACTURE_INFO] = {0, };

	ret = s6e8aa5x01_read_info(lcd, LDI_REG_MANUFACTURE_INFO, ARRAY_SIZE(buf), buf);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);

	memcpy(lcd->manufacture_info, &buf[LDI_GPARA_MANUFACTURE_INFO], LDI_LEN_MANUFACTURE_INFO);

	return ret;
}

static int s6e8aa5x01_read_date(struct lcd_info *lcd)
{
	int ret = 0;
	unsigned char buf[LDI_LEN_DATE] = {0, };

	/* date 0xC8 41th~47th */
	DSI_WRITE(SEQ_MTP_READ_DATE_GP, ARRAY_SIZE(SEQ_MTP_READ_DATE_GP));
	ret = s6e8aa5x01_read_info(lcd, LDI_REG_DATE, LDI_LEN_DATE, buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto exit;
	}

	memcpy(lcd->date, &buf[0], LDI_LEN_DATE);

exit:
	return ret;
}

static int s6e8aa5x01_read_elvss(struct lcd_info *lcd, unsigned char *buf)
{
	int ret = 0;

	ret = s6e8aa5x01_read_info(lcd, LDI_REG_ELVSS, LDI_LEN_ELVSS, buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto exit;
	}

exit:
	return ret;
}

static int s6e8aa5x01_init_elvss(struct lcd_info *lcd, u8 *elvss_data)
{
	int i, temp, ret = 0;

	for (i = 0; i < IBRIGHTNESS_HBM_MAX; i++) {
		for (temp = 0; temp < TEMP_MAX; temp++) {
			/* Duplicate with reading value from DDI */
			memcpy(&lcd->elvss_table[i][temp][1], elvss_data, LDI_LEN_ELVSS);

			lcd->elvss_table[i][temp][0] = elvss_offset_data[i][temp][0];
			lcd->elvss_table[i][temp][LDI_OFFSET_ELVSS_1] = elvss_offset_data[i][temp][1];
			lcd->elvss_table[i][temp][LDI_OFFSET_ELVSS_2] = elvss_offset_data[i][temp][2];
			if (i <= IBRIGHTNESS_029NIT)
				lcd->elvss_table[i][temp][LDI_OFFSET_ELVSS_3] = elvss_offset_data[i][temp][3];
			else if (i >= IBRIGHTNESS_MAX) /* for HBM Interpolation*/
				lcd->elvss_table[i][temp][LDI_OFFSET_ELVSS_3] = elvss_data[LDI_GPARA_HBM_ELVSS];
		}
	}

	return ret;
}

static int s6e8aa5x01_init_hbm_gamma(struct lcd_info *lcd)
{
	int ret = 0;

	/* hbm gamma is written on 0xC8 [34~39] and [73~87] */
	DSI_WRITE(SEQ_MTP_READ_HBM_GP_1, ARRAY_SIZE(SEQ_MTP_READ_HBM_GP_1));
	lcd->hbm_gamma[0] = 0xCA;
	ret = s6e8aa5x01_read_info(lcd, LDI_REG_MTP, LDI_LEN_HBM_GAMMA_1, &lcd->hbm_gamma[1]);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto exit;
	}

	DSI_WRITE(SEQ_MTP_READ_HBM_GP_2, ARRAY_SIZE(SEQ_MTP_READ_HBM_GP_2));

	ret = s6e8aa5x01_read_info(lcd, LDI_REG_MTP, LDI_LEN_HBM_GAMMA_2, &lcd->hbm_gamma[7]);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto exit;
	}

	memcpy(&lcd->gamma_table[IBRIGHTNESS_HBM_MAX - 1], SEQ_GAMMA_CONDITION_SET, GAMMA_CMD_CNT);
	memcpy(&lcd->gamma_table[IBRIGHTNESS_HBM_MAX - 1], &lcd->hbm_gamma, HBM_GAMMA_CMD_CNT);

exit:
	return ret;
}

static int s6e8aa5x01_init_interpolation_gamma(struct lcd_info *lcd)
{
	int i, j, ret = 0;
	int HBM_index = index_brightness_table[IBRIGHTNESS_HBM_MAX - 1];
	int Default_index = index_brightness_table[IBRIGHTNESS_MAX - 1];
	int Diff_index = HBM_index - Default_index;
	s64 t1, t2, ratio;

	/* HBM reg - [ ( 600 - 578 ) / (600 - 420) * ( HBM reg - Max reg ) ] */
	for (i = IBRIGHTNESS_MAX - 1; i < IBRIGHTNESS_HBM_MAX - 1; i++)
		memcpy(&lcd->gamma_table[i], SEQ_GAMMA_CONDITION_SET, GAMMA_CMD_CNT);

	for (i = IBRIGHTNESS_MAX; i < IBRIGHTNESS_HBM_MAX - 1; i++) {
		for (j = 1; j < GAMMA_CMD_CNT; j++) {
			t1 = HBM_index - index_brightness_table[i];
			t2 = Diff_index;
			ratio = (t1 << 10) / t2;
			ratio = ratio * (lcd->gamma_table[IBRIGHTNESS_HBM_MAX - 1][j] - lcd->gamma_table[IBRIGHTNESS_MAX - 1][j]);

			lcd->gamma_table[i][j] =
			lcd->gamma_table[IBRIGHTNESS_HBM_MAX - 1][j] - (ratio >> 10);
		}
	}

	return ret;
}


static int s6e8aa5x01_exit(struct lcd_info *lcd)
{
	int ret = 0;

#ifdef CONFIG_DISPLAY_USE_INFO
	u8 buf;
#endif

	dev_info(&lcd->ld->dev, "%s\n", __func__);

#ifdef CONFIG_DISPLAY_USE_INFO
/*
 * ESD_ERROR[6] = VLIN1 error is occurred by ESD = 0x40
 * ESD_ERROR[5] = Internal HSYNC error is occurred by ESD
 * ESD_ERROR[4] = CHECK_SUM error is occurred by ESD
 * ESD_ERROR[3] = ELVDD error is occurred by ESD = 0x08
 * ESD_ERROR[2] = VLIN3 error is occurred by ESD = 0x04
 * ESD_ERROR[1] = HS CLK lane error is occurred by ESD
 * ESD_ERROR[0] = MIPI DSI error is occurred by ESD
 */
	ret = s6e8aa5x01_read_info(lcd, ERR_READ_REG, sizeof(buf), &buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto dpui_skip;
	}

	inc_dpui_u32_field(DPUI_KEY_PNVLI1E, !!(buf & 0x40));

	inc_dpui_u32_field(DPUI_KEY_PNELVDE, !!(buf & 0x08));

	inc_dpui_u32_field(DPUI_KEY_PNVLO3E, !!(buf & 0x04));

	inc_dpui_u32_field(DPUI_KEY_PNESDE, !!(buf & 0x4C));

	ret = s6e8aa5x01_read_info(lcd, ERR_RDNUMED_REG, sizeof(buf), &buf);
	if (ret < 0) {
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);
		goto dpui_skip;
	}
	inc_dpui_u32_field(DPUI_KEY_PNDSIE, buf);

dpui_skip:
	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));
#endif

	/* 2. Display Off (28h) */
	DSI_WRITE(SEQ_DISPLAY_OFF, ARRAY_SIZE(SEQ_DISPLAY_OFF));

	/* 3. Sleep In (10h) */
	DSI_WRITE(SEQ_SLEEP_IN, ARRAY_SIZE(SEQ_SLEEP_IN));

	/* 4. Wait 120ms */
	msleep(120);

	return ret;
}

static int s6e8aa5x01_displayon(struct lcd_info *lcd)
{
	int ret = 0;

	dev_info(&lcd->ld->dev, "%s\n", __func__);

	/* 14. Display On(29h) */
	DSI_WRITE(SEQ_DISPLAY_ON, ARRAY_SIZE(SEQ_DISPLAY_ON));

	return ret;
}

static int s6e8aa5x01_init(struct lcd_info *lcd)
{
	int ret = 0;
#ifdef CONFIG_DISPLAY_USE_INFO
	u8 buf;
#endif

	dev_info(&lcd->ld->dev, "%s\n", __func__);

	usleep_range(5000, 6000);

	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));

	DSI_WRITE(SEQ_SLEEP_OUT, ARRAY_SIZE(SEQ_SLEEP_OUT));

	msleep(20);

	s6e8aa5x01_read_id(lcd);

	/* 2. Brightness Setting */

	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));
#if defined(CONFIG_PANEL_S6E8AA5X01_J5Y17_KOR)
	DSI_WRITE(SEQ_LTPS_SETTING, ARRAY_SIZE(SEQ_LTPS_SETTING));
#endif
	dsim_panel_set_brightness(lcd, 1);

	/* 3. Common Setting */
	DSI_WRITE(SEQ_PENTILE_SETTING, ARRAY_SIZE(SEQ_PENTILE_SETTING));
	DSI_WRITE(SEQ_DE_DIM_GP, ARRAY_SIZE(SEQ_DE_DIM_GP));
	DSI_WRITE(SEQ_DE_DIM_SETTING, ARRAY_SIZE(SEQ_DE_DIM_SETTING));
	DSI_WRITE(SEC_PCD_SETTING, ARRAY_SIZE(SEC_PCD_SETTING));
	DSI_WRITE(SEC_ERR_FLAG_SETTING, ARRAY_SIZE(SEC_ERR_FLAG_SETTING));

	/* 12. Wait 120ms */
	msleep(120);

#ifdef CONFIG_DISPLAY_USE_INFO
	DSI_WRITE(SEQ_ESD_MONITOR_ON, ARRAY_SIZE(SEQ_ESD_MONITOR_ON));

	ret = s6e8aa5x01_read_info(lcd, ERR_RDDSDR_REG, sizeof(buf), &buf);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: fail\n", __func__);

	inc_dpui_u32_field(DPUI_KEY_PNSDRE, buf&0x80 ? 0 : 1);
#endif

	/* Test Key Disable */
	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));

	return ret;
}

static int s6e8aa5x01_read_init_info(struct lcd_info *lcd, unsigned char *mtp)
{
	int ret = 0;
	unsigned char elvss_data[LDI_LEN_ELVSS] = {0, };

	s6e8aa5x01_read_id(lcd);

	DSI_WRITE(SEQ_TEST_KEY_ON_F0, ARRAY_SIZE(SEQ_TEST_KEY_ON_F0));

	s6e8aa5x01_read_mtp(lcd, mtp);
	s6e8aa5x01_read_coordinate(lcd);
	s6e8aa5x01_read_date(lcd);
	s6e8aa5x01_read_elvss(lcd, elvss_data);
	s6e8aa5x01_read_manufacture_info(lcd);
	s6e8aa5x01_init_elvss(lcd, elvss_data);
	s6e8aa5x01_init_hbm_gamma(lcd);
	s6e8aa5x01_init_interpolation_gamma(lcd);

	DSI_WRITE(SEQ_TEST_KEY_OFF_F0, ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0));

	return ret;
}

#ifdef CONFIG_DISPLAY_USE_INFO
static int panel_dpui_notifier_callback(struct notifier_block *self,
				unsigned long event, void *data)
{
	struct lcd_info *lcd = NULL;
	struct dpui_info *dpui = data;
	char tbuf[MAX_DPUI_VAL_LEN];
	int size;
	unsigned int site, rework, poc, i, invalid = 0;
	unsigned char *m_info;

	struct seq_file m = {
		.buf = tbuf,
		.size = sizeof(tbuf) - 1,
	};

	if (dpui == NULL) {
		pr_err("%s: dpui is null\n", __func__);
		return NOTIFY_DONE;
	}

	lcd = container_of(self, struct lcd_info, dpui_notif);

	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "%04d%02d%02d %02d%02d%02d",
			((lcd->date[0] & 0xF0) >> 4) + 2011, lcd->date[0] & 0xF, lcd->date[1] & 0x1F,
			lcd->date[2] & 0x1F, lcd->date[3] & 0x3F, lcd->date[4] & 0x3F);
	set_dpui_field(DPUI_KEY_MAID_DATE, tbuf, size);

	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "%d", lcd->id_info.id[0]);
	set_dpui_field(DPUI_KEY_LCDID1, tbuf, size);
	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "%d", lcd->id_info.id[1]);
	set_dpui_field(DPUI_KEY_LCDID2, tbuf, size);
	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "%d", lcd->id_info.id[2]);
	set_dpui_field(DPUI_KEY_LCDID3, tbuf, size);
	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "%s_%s", DPUI_VENDOR_NAME, DPUI_MODEL_NAME);
	set_dpui_field(DPUI_KEY_DISP_MODEL, tbuf, size);

	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "0x%02X%02X%02X%02X%02X",
			lcd->code[0], lcd->code[1], lcd->code[2], lcd->code[3], lcd->code[4]);
	set_dpui_field(DPUI_KEY_CHIPID, tbuf, size);

	size = snprintf(tbuf, MAX_DPUI_VAL_LEN, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		lcd->date[0], lcd->date[1], lcd->date[2], lcd->date[3], lcd->date[4],
		lcd->date[5], lcd->date[6], (lcd->coordinate[0] & 0xFF00) >> 8, lcd->coordinate[0] & 0x00FF,
		(lcd->coordinate[1] & 0xFF00) >> 8, lcd->coordinate[1] & 0x00FF);
	set_dpui_field(DPUI_KEY_CELLID, tbuf, size);

	m_info = lcd->manufacture_info;
	site = get_bit(m_info[0], 4, 4);
	rework = get_bit(m_info[0], 0, 4);
	poc = get_bit(m_info[1], 0, 4);
	seq_printf(&m, "%d%d%d%02x%02x", site, rework, poc, m_info[2], m_info[3]);

	for (i = 4; i < LDI_LEN_MANUFACTURE_INFO; i++) {
		if (!isdigit(m_info[i]) && !isupper(m_info[i])) {
			invalid = 1;
			break;
		}
	}
	for (i = 4; !invalid && i < LDI_LEN_MANUFACTURE_INFO; i++)
		seq_printf(&m, "%c", m_info[i]);

	set_dpui_field(DPUI_KEY_OCTAID, tbuf, m.count);

	return NOTIFY_DONE;
}
#endif /* CONFIG_DISPLAY_USE_INFO */

static int s6e8aa5x01_probe(struct lcd_info *lcd)
{
	int ret = 0;
	unsigned char mtp[LDI_LEN_MTP] = {0, };

	dev_info(&lcd->ld->dev, "+ %s\n", __func__);

	lcd->bd->props.max_brightness = EXTEND_BRIGHTNESS;
	lcd->bd->props.brightness = UI_DEFAULT_BRIGHTNESS;

	lcd->state = PANEL_STATE_RESUMED;

	lcd->temperature = NORMAL_TEMPERATURE;
	lcd->acl_enable = 0;
	lcd->current_acl = 0;
	lcd->current_hbm = 0;
	lcd->adaptive_control = ACL_STATUS_15P;

	lcd->acl_table = ACL_TABLE;
	lcd->opr_table = OPR_TABLE;
	lcd->hbm_table = NULL;
	lcd->aor_table = AOR_TABLE;
	lcd->lux = -1;

	ret = s6e8aa5x01_read_init_info(lcd, mtp);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: failed to init information\n", __func__);

	init_dynamic_aid(lcd);
	init_gamma(lcd, mtp);

	dsim_panel_set_brightness(lcd, 1);

#ifdef CONFIG_DISPLAY_USE_INFO
	lcd->dpui_notif.notifier_call = panel_dpui_notifier_callback;
	if (lcd->connected)
		dpui_logging_register(&lcd->dpui_notif, DPUI_TYPE_PANEL);
#endif

	dev_info(&lcd->ld->dev, "- %s\n", __func__);

	return 0;
}

static ssize_t lcd_type_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "SDC_%02X%02X%02X\n", lcd->id_info.id[0], lcd->id_info.id[1], lcd->id_info.id[2]);

	return strlen(buf);
}

static ssize_t window_type_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%02x %02x %02x\n", lcd->id_info.id[0], lcd->id_info.id[1], lcd->id_info.id[2]);

	return strlen(buf);
}

static ssize_t brightness_table_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int i, bl;
	char *pos = buf;

	for (i = 0; i <= EXTEND_BRIGHTNESS; i++) {
		bl = get_backlight_level_from_brightness(i);
		pos += sprintf(pos, "%3d %3d\n", i, index_brightness_table[bl]);
	}

	return pos - buf;
}

static ssize_t temperature_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	char temp[] = "-15, -14, 0, 1\n";

	strcat(buf, temp);
	return strlen(buf);
}

static ssize_t temperature_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);
	int value, rc, temperature_index = 0;

	rc = kstrtoint(buf, 10, &value);
	if (rc < 0)
		return rc;

	if (value <= -15)
		temperature_index = TEMP_BELOW_MINUS_15_DEGREE;
	else if (value > 0)
		temperature_index = TEMP_ABOVE_MINUS_00_DEGREE;
	else
		temperature_index = TEMP_ABOVE_MINUS_15_DEGREE;

	mutex_lock(&lcd->lock);
	lcd->temperature = value;
	lcd->temperature_index = temperature_index;
	mutex_unlock(&lcd->lock);

	if (lcd->state == PANEL_STATE_RESUMED)
		dsim_panel_set_brightness(lcd, 1);

	dev_info(dev, "%s: %d, %d, %d\n", __func__, value, lcd->temperature, lcd->temperature_index);

	return size;
}

static ssize_t color_coordinate_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%u, %u\n", lcd->coordinate[0], lcd->coordinate[1]);

	return strlen(buf);
}

static ssize_t manufacture_date_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);
	u16 year;
	u8 month, day, hour, min, sec;
	u16 ms;

	year = ((lcd->date[0] & 0xF0) >> 4) + 2011;
	month = lcd->date[0] & 0xF;
	day = lcd->date[1] & 0x1F;
	hour = lcd->date[2] & 0x1F;
	min = lcd->date[3] & 0x3F;
	sec = lcd->date[4];
	ms = (lcd->date[5] << 8) | lcd->date[6];

	sprintf(buf, "%04d, %02d, %02d, %02d:%02d:%02d.%04d\n", year, month, day, hour, min, sec, ms);

	return strlen(buf);
}

static ssize_t manufacture_code_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%02X%02X%02X%02X%02X\n",
		lcd->code[0], lcd->code[1], lcd->code[2], lcd->code[3], lcd->code[4]);

	return strlen(buf);
}

static ssize_t cell_id_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
		lcd->date[0], lcd->date[1], lcd->date[2], lcd->date[3], lcd->date[4],
		lcd->date[5], lcd->date[6], (lcd->coordinate[0] & 0xFF00) >> 8, lcd->coordinate[0] & 0x00FF,
		(lcd->coordinate[1] & 0xFF00) >> 8, lcd->coordinate[1] & 0x00FF);

	return strlen(buf);
}

static void show_aid_log(struct lcd_info *lcd)
{
	u8 temp[256];
	int i, j, k;
	int *mtp;

	mtp = lcd->daid.mtp;
	for (i = 0, j = 0; i < IV_MAX; i++, j += CI_MAX) {
		if (i == 0)
			dev_info(&lcd->ld->dev, "MTP Offset VT   : %4d %4d %4d\n",
				mtp[j + CI_RED], mtp[j + CI_GREEN], mtp[j + CI_BLUE]);
		else
			dev_info(&lcd->ld->dev, "MTP Offset V%3d : %4d %4d %4d\n",
				lcd->daid.iv_tbl[i], mtp[j + CI_RED], mtp[j + CI_GREEN], mtp[j + CI_BLUE]);
	}

	for (i = 0; i < IBRIGHTNESS_MAX; i++) {
		memset(temp, 0, sizeof(temp));
		for (j = 1; j < GAMMA_CMD_CNT; j++) {
			if (j == 1 || j == 3 || j == 5)
				k = lcd->gamma_table[i][j++] * 256;
			else
				k = 0;
			snprintf(temp + strnlen(temp, 256), 256, " %3d", lcd->gamma_table[i][j] + k);
		}

		dev_info(&lcd->ld->dev, "nit : %3d  %s\n", lcd->daid.ibr_tbl[i], temp);
	}

	dev_info(&lcd->ld->dev, "%s\n", __func__);
}

static ssize_t aid_log_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	show_aid_log(lcd);

	return strlen(buf);
}

static ssize_t adaptive_control_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);

	sprintf(buf, "%d\n", lcd->adaptive_control);

	return strlen(buf);
}

static ssize_t adaptive_control_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);
	int rc;
	unsigned int value;

	rc = kstrtouint(buf, 0, &value);
	if (rc < 0)
		return rc;

	if (lcd->adaptive_control != value) {
		dev_info(&lcd->ld->dev, "%s: %d, %d\n", __func__, lcd->adaptive_control, value);
		mutex_lock(&lcd->lock);
		lcd->adaptive_control = value;
		mutex_unlock(&lcd->lock);
		if (lcd->state == PANEL_STATE_RESUMED)
			dsim_panel_set_brightness(lcd, 1);
	}

	return size;
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

#if defined(CONFIG_EXYNOS_DECON_MDNIE_LITE)
		attr_store_for_each(lcd->mdnie_class, attr->attr.name, buf, size);
#endif
	}

	return size;
}

static ssize_t octa_id_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lcd_info *lcd = dev_get_drvdata(dev);
	unsigned int site, rework, poc, i, invalid = 0;
	unsigned char *m_info;

	struct seq_file m = {
		.buf = buf,
		.size = PAGE_SIZE - 1,
	};

	m_info = lcd->manufacture_info;
	site = get_bit(m_info[0], 4, 4);
	rework = get_bit(m_info[0], 0, 4);
	poc = get_bit(m_info[1], 0, 4);
	seq_printf(&m, "%d%d%d%02x%02x", site, rework, poc, m_info[2], m_info[3]);

	for (i = 4; i < LDI_LEN_MANUFACTURE_INFO; i++) {
		if (!isdigit(m_info[i]) && !isupper(m_info[i])) {
			invalid = 1;
			break;
		}
	}
	for (i = 4; !invalid && i < LDI_LEN_MANUFACTURE_INFO; i++)
		seq_printf(&m, "%c", m_info[i]);

	seq_puts(&m, "\n");

	return strlen(buf);
}

#ifdef CONFIG_DISPLAY_USE_INFO
/*
 * HW PARAM LOGGING SYSFS NODE
 */
static ssize_t dpui_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int ret;

	update_dpui_log(DPUI_LOG_LEVEL_INFO, DPUI_TYPE_PANEL);
	ret = get_dpui_log(buf, DPUI_LOG_LEVEL_INFO, DPUI_TYPE_PANEL);
	if (ret < 0) {
		pr_err("%s failed to get log %d\n", __func__, ret);
		return ret;
	}

	pr_info("%s\n", buf);
	return ret;
}

static ssize_t dpui_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	if (buf[0] == 'C' || buf[0] == 'c')
		clear_dpui_log(DPUI_LOG_LEVEL_INFO, DPUI_TYPE_PANEL);

	return size;
}

/*
 * [DEV ONLY]
 * HW PARAM LOGGING SYSFS NODE
 */
static ssize_t dpui_dbg_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int ret;

	update_dpui_log(DPUI_LOG_LEVEL_DEBUG, DPUI_TYPE_PANEL);
	ret = get_dpui_log(buf, DPUI_LOG_LEVEL_DEBUG, DPUI_TYPE_PANEL);
	if (ret < 0) {
		pr_err("%s failed to get log %d\n", __func__, ret);
		return ret;
	}

	pr_info("%s\n", buf);
	return ret;
}

static ssize_t dpui_dbg_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	if (buf[0] == 'C' || buf[0] == 'c')
		clear_dpui_log(DPUI_LOG_LEVEL_DEBUG, DPUI_TYPE_PANEL);

	return size;
}

static DEVICE_ATTR(dpui, 0660, dpui_show, dpui_store);
static DEVICE_ATTR(dpui_dbg, 0660, dpui_dbg_show, dpui_dbg_store);
#endif

static DEVICE_ATTR(lcd_type, 0444, lcd_type_show, NULL);
static DEVICE_ATTR(window_type, 0444, window_type_show, NULL);
static DEVICE_ATTR(manufacture_code, 0444, manufacture_code_show, NULL);
static DEVICE_ATTR(cell_id, 0444, cell_id_show, NULL);
static DEVICE_ATTR(brightness_table, 0444, brightness_table_show, NULL);
static DEVICE_ATTR(temperature, 0664, temperature_show, temperature_store);
static DEVICE_ATTR(color_coordinate, 0444, color_coordinate_show, NULL);
static DEVICE_ATTR(manufacture_date, 0444, manufacture_date_show, NULL);
static DEVICE_ATTR(aid_log, 0444, aid_log_show, NULL);
static DEVICE_ATTR(adaptive_control, 0664, adaptive_control_show, adaptive_control_store);
static DEVICE_ATTR(lux, 0644, lux_show, lux_store);
static DEVICE_ATTR(octa_id, 0444, octa_id_show, NULL);
static DEVICE_ATTR(SVC_OCTA, 0444, cell_id_show, NULL);
static DEVICE_ATTR(SVC_OCTA_CHIPID, 0444, octa_id_show, NULL);

static struct attribute *lcd_sysfs_attributes[] = {
	&dev_attr_lcd_type.attr,
	&dev_attr_window_type.attr,
	&dev_attr_manufacture_code.attr,
	&dev_attr_cell_id.attr,
	&dev_attr_temperature.attr,
	&dev_attr_color_coordinate.attr,
	&dev_attr_manufacture_date.attr,
	&dev_attr_aid_log.attr,
	&dev_attr_brightness_table.attr,
	&dev_attr_adaptive_control.attr,
	&dev_attr_lux.attr,
	&dev_attr_octa_id.attr,
#ifdef CONFIG_DISPLAY_USE_INFO
	&dev_attr_dpui.attr,
	&dev_attr_dpui_dbg.attr,
#endif
	NULL,
};

static const struct attribute_group lcd_sysfs_attr_group = {
	.attrs = lcd_sysfs_attributes,
};

static void lcd_init_svc(struct lcd_info *lcd)
{
	struct device *dev = &lcd->svc_dev;
	struct kobject *top_kobj = &lcd->ld->dev.kobj.kset->kobj;
	struct kernfs_node *kn = kernfs_find_and_get(top_kobj->sd, "svc");
	struct kobject *svc_kobj = NULL;
	char *buf, *path = NULL;
	int ret = 0;

	svc_kobj = kn ? kn->priv : kobject_create_and_add("svc", top_kobj);
	if (!svc_kobj)
		return;

	buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (buf) {
		path = kernfs_path(svc_kobj->sd, buf, PATH_MAX);
		dev_info(&lcd->ld->dev, "%s: %s %s\n", __func__, buf, !kn ? "create" : "");
		kfree(buf);
	}

	dev->kobj.parent = svc_kobj;
	dev_set_name(dev, "OCTA");
	dev_set_drvdata(dev, lcd);
	ret = device_register(dev);
	if (ret < 0) {
		dev_info(&lcd->ld->dev, "%s: device_register fail\n", __func__);
		return;
	}

	device_create_file(dev, &dev_attr_SVC_OCTA);
	device_create_file(dev, &dev_attr_SVC_OCTA_CHIPID);

	if (kn)
		kernfs_put(kn);
}

static void lcd_init_sysfs(struct lcd_info *lcd)
{
	int ret = 0;

	ret = sysfs_create_group(&lcd->ld->dev.kobj, &lcd_sysfs_attr_group);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "failed to add lcd sysfs\n");

	lcd_init_svc(lcd);
}


#if defined(CONFIG_EXYNOS_DECON_MDNIE_LITE)
static int mdnie_lite_write_set(struct lcd_info *lcd, struct lcd_seq_info *seq, u32 num)
{
	int ret = 0, i;

	for (i = 0; i < num; i++) {
		if (seq[i].cmd) {
			ret = dsim_write_hl_data(lcd, seq[i].cmd, seq[i].len);
			if (ret < 0) {
				dev_info(&lcd->ld->dev, "%s: %dth fail\n", __func__, i);
				return ret;
			}
		}
		if (seq[i].sleep)
			usleep_range(seq[i].sleep * 1000, seq[i].sleep * 1100);
	}
	return ret;
}

int mdnie_lite_send_seq(struct lcd_info *lcd, struct lcd_seq_info *seq, u32 num)
{
	int ret = 0;

	mutex_lock(&lcd->lock);

	if (lcd->state != PANEL_STATE_RESUMED) {
		dev_info(&lcd->ld->dev, "%s: panel is not active\n", __func__);
		ret = -EIO;
		goto exit;
	}

	ret = mdnie_lite_write_set(lcd, seq, num);

exit:
	mutex_unlock(&lcd->lock);

	return ret;
}

int mdnie_lite_read(struct lcd_info *lcd, u8 addr, u8 *buf, u32 size)
{
	int ret = 0;

	mutex_lock(&lcd->lock);

	if (lcd->state != PANEL_STATE_RESUMED) {
		dev_info(&lcd->ld->dev, "%s: panel is not active\n", __func__);
		ret = -EIO;
		goto exit;
	}

	ret = dsim_read_hl_data(lcd, addr, size, buf);

exit:
	mutex_unlock(&lcd->lock);

	return ret;
}
#endif

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

	dsim->lcd = lcd->ld = lcd_device_register("panel", dsim->dev, lcd, NULL);
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
	ret = s6e8aa5x01_probe(lcd);
	if (ret < 0)
		dev_err(&lcd->ld->dev, "%s: failed to probe panel\n", __func__);

	lcd_init_sysfs(lcd);

#if defined(CONFIG_EXYNOS_DECON_MDNIE_LITE)
	mdnie_register(&lcd->ld->dev, lcd, (mdnie_w)mdnie_lite_send_seq, (mdnie_r)mdnie_lite_read, lcd->coordinate, &tune_info);
	lcd->mdnie_class = get_mdnie_class();
#endif

	dev_info(&lcd->ld->dev, "%s: %s: done\n", kbasename(__FILE__), __func__);
probe_err:
	return ret;
}

static int dsim_panel_displayon(struct dsim_device *dsim)
{
	struct lcd_info *lcd = dsim->priv.par;

	dev_info(&lcd->ld->dev, "+ %s: %d\n", __func__, lcd->state);

	if (lcd->state == PANEL_STATE_SUSPENED)
		s6e8aa5x01_init(lcd);

	s6e8aa5x01_displayon(lcd);

	mutex_lock(&lcd->lock);
	lcd->state = PANEL_STATE_RESUMED;
	mutex_unlock(&lcd->lock);

	dev_info(&lcd->ld->dev, "- %s: %d, %d\n", __func__, lcd->state, lcd->connected);

	return 0;
}

static int dsim_panel_suspend(struct dsim_device *dsim)
{
	struct lcd_info *lcd = dsim->priv.par;

	dev_info(&lcd->ld->dev, "+ %s: %d\n", __func__, lcd->state);

	if (lcd->state == PANEL_STATE_SUSPENED)
		goto exit;

	lcd->state = PANEL_STATE_SUSPENDING;

	s6e8aa5x01_exit(lcd);

	mutex_lock(&lcd->lock);
	lcd->state = PANEL_STATE_SUSPENED;
	mutex_unlock(&lcd->lock);

	dev_info(&lcd->ld->dev, "- %s: %d, %d\n", __func__, lcd->state, lcd->connected);

exit:
	return 0;
}

struct mipi_dsim_lcd_driver s6e8aa5x01_mipi_lcd_driver = {
	.probe		= dsim_panel_probe,
	.displayon	= dsim_panel_displayon,
	.suspend	= dsim_panel_suspend,
};

