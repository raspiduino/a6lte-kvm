/*
 * Copyright (c) Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* temporary solution: Do not use these sysfs as official purpose */
/* these function are not official one. only purpose is for temporary test */

#if defined(CONFIG_DEBUG_FS) && !defined(CONFIG_SAMSUNG_PRODUCT_SHIP) && defined(CONFIG_SEC_GPIO_DVS)
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/lcd.h>
#include <linux/platform_device.h>
#include <linux/module.h>

#include <video/mipi_display.h>

#include "../dsim.h"
#include "../decon.h"
#include "../decon_notify.h"

#include "dd.h"

static bool log_boot;
#define dbg_info(fmt, ...)	pr_info(pr_fmt("%s: %3d: %s: " fmt), "dsim", __LINE__, __func__, ##__VA_ARGS__)
#define dbg_warn(fmt, ...)	pr_warn(pr_fmt("%s: %3d: %s: " fmt), "dsim", __LINE__, __func__, ##__VA_ARGS__)
#define dbg_boot(fmt, ...)	do { if (unlikely(log_boot)) dbg_info(fmt, ##__VA_ARGS__); } while (0)

#define LCD_INFO_DTS_NAME	"lcd_info"

#define D_LIST	\
_X(REFRESH,		"timing,refresh",	"refresh",		0400)	\
_X(PMS_P,		"timing,pms",		"pms",			0600)	\
_X(PMS_M,		"",			"",			0)	\
_X(PMS_S,		"",			"",			0)	\
_X(PMSK_P,		"timing,pmsk",		"pmsk",			0600)	\
_X(PMSK_M,		"",			"",			0)	\
_X(PMSK_S,		"",			"",			0)	\
_X(PMSK_K,		"",			"",			0)	\
_X(HS_CLK,		"timing,dsi-hs-clk",	"hs_clk",		0400)	\
_X(ESC_CLK,		"timing,dsi-escape-clk",	"esc_clk",	0400)	\
_X(HBP,			"timing,h-porch",	"hporch",		0600)	\
_X(HFP,			"",			"",			0)	\
_X(HSA,			"",			"",			0)	\
_X(VBP,			"timing,v-porch",	"vporch",		0600)	\
_X(VFP,			"",			"",			0)	\
_X(VSA,			"",			"",			0)	\
_X(VT_COMPENSATION,	"vt_compensation",	"vt_compensation",	0600)	\
_X(MRES_WIDTH,		"mres_width",		"mres_width",		0400)	\
_X(MRES_WIDTH_2,	"",			"",			0)	\
_X(MRES_WIDTH_3,	"",			"",			0)	\
_X(MRES_HEIGHT,		"mres_height",		"mres_height",		0400)	\
_X(MRES_HEIGHT_2,	"",			"",			0)	\
_X(MRES_HEIGHT_3,	"",			"",			0)	\
_X(CMD_UNDERRUN_LP_REF,	"cmd_underrun_lp_ref",	"cmd_underrun_lp_ref",	0600)	\
_X(CMD_UNDERRUN_LP_REF_2,	"",		"",			0)	\
_X(CMD_UNDERRUN_LP_REF_3,	"",		"",			0)	\
_X(DSIM_HBP,		"timing,dsim_h-porch",	"dsim_hporch",		0600)	\
_X(DSIM_HFP,		"",			"",			0)	\
_X(DSIM_HSA,		"",			"",			0)	\
_X(DSIM_VBP,		"timing,dsim_v-porch",	"dsim_vporch",		0600)	\
_X(DSIM_VFP,		"",			"",			0)	\
_X(DSIM_VSA,		"",			"",			0)	\
_X(DECON_HBP,		"timing,decon_h-porch",	"decon_hporch",	0600)	\
_X(DECON_HFP,		"",			"",			0)	\
_X(DECON_HSA,		"",			"",			0)	\
_X(DECON_VBP,		"timing,decon_v-porch",	"decon_vporch",	0600)	\
_X(DECON_VFP,		"",			"",			0)	\
_X(DECON_VSA,		"",			"",			0)	\
_X(LCD_INFO_END,	"",			"",			0)	\
_X(VCLK_NUMERATOR,	"vclk-num",		"vclk_numerator",	0400)	\
_X(VCLK_DENOMINATOR,	"vclk-denom",		"vclk_denominator",	0600)	\
_X(DISP_VCLK,		"disp-vclk",		"disp_vclk",		0600)	\
_X(DISP_PLL_CLK,	"disp-pll-clk",		"disp_pll",		0600)	\

#define _X(id, dts, sysfs, mode) D_##id,
enum { D_LIST D_MAX };
#undef _X

#define _X(id, dts, sysfs, mode) (#id),
static char *D_LIST_NAME[] = { D_LIST };
#undef _X

static struct {
	char *dts_name;
	char *sysfs_name;
	umode_t mode;
	u32	length;
} debugfs_list[] = {
#define _X(id, dts, sysfs, mode) {dts, sysfs, mode, 0},
	D_LIST
#undef _X
};

struct d_info {
	struct device	*dev;
	struct dentry	*debugfs_root;

	struct notifier_block	fb_notifier;
	unsigned int enable;

	u32 regdump;

	u32 default_param[D_MAX];	/* get from dts */
	u32 request_param[D_MAX];	/* get from sysfs input */
	u32 pending_param[D_MAX];	/* get from sysfs input flag */
	u32 current_param[D_MAX];	/* get from real data */

	u32 *point[D_MAX];
};

static void configure_param(struct d_info *d)
{
	struct dsim_device *dsim = get_dsim_drvdata(0);
	struct decon_device *decon = get_decon_drvdata(0);
	struct decon_lcd *lcd_info = decon->lcd_info;
#if defined(CONFIG_SOC_EXYNOS7570) || defined(CONFIG_SOC_EXYNOS7870)
	struct dsim_clks *clks = &dsim->clks_param.clks;
#else
	struct dsim_clks *clks = &dsim->clks;
#endif

	d->point[D_REFRESH]		=	&lcd_info->fps;
#if defined(CONFIG_SOC_EXYNOS9610)
	d->point[D_PMSK_P]		=	&lcd_info->dphy_pms.p;
	d->point[D_PMSK_M]		=	&lcd_info->dphy_pms.m;
	d->point[D_PMSK_S]		=	&lcd_info->dphy_pms.s;
	d->point[D_PMSK_K]		=	&lcd_info->dphy_pms.k;
#else
	d->point[D_PMS_P]		=	&lcd_info->dphy_pms.p;
	d->point[D_PMS_M]		=	&lcd_info->dphy_pms.m;
	d->point[D_PMS_S]		=	&lcd_info->dphy_pms.s;
#endif

	d->point[D_HS_CLK]		=	&clks->hs_clk;
	d->point[D_ESC_CLK]		=	&clks->esc_clk;

#if defined(CONFIG_SOC_EXYNOS7870) || defined(CONFIG_SOC_EXYNOS7885)
	d->point[D_HBP]			=	&lcd_info->hbp;
	d->point[D_HFP]			=	&lcd_info->hfp;
	d->point[D_HSA]			=	&lcd_info->hsa;
	d->point[D_VBP]			=	&lcd_info->vbp;
	d->point[D_VFP]			=	&lcd_info->vfp;
	d->point[D_VSA]			=	&lcd_info->vsa;
#endif

#if defined(CONFIG_SOC_EXYNOS7570)
	d->point[D_DSIM_HBP]		=	&lcd_info->dsim_hbp;
	d->point[D_DSIM_HFP]		=	&lcd_info->dsim_hfp;
	d->point[D_DSIM_HSA]		=	&lcd_info->dsim_hsa;
	d->point[D_DSIM_VBP]		=	&lcd_info->dsim_vbp;
	d->point[D_DSIM_VFP]		=	&lcd_info->dsim_vfp;
	d->point[D_DSIM_VSA]		=	&lcd_info->dsim_vsa;
	d->point[D_DECON_HBP]		=	&lcd_info->decon_hbp;
	d->point[D_DECON_HFP]		=	&lcd_info->decon_hfp;
	d->point[D_DECON_HSA]		=	&lcd_info->decon_hsa;
	d->point[D_DECON_VBP]		=	&lcd_info->decon_vbp;
	d->point[D_DECON_VFP]		=	&lcd_info->decon_vfp;
	d->point[D_DECON_VSA]		=	&lcd_info->decon_vsa;

	d->point[D_VCLK_NUMERATOR]	=	&decon->pdata->decon_clk.vclk_num;
	d->point[D_VCLK_DENOMINATOR]	=	&decon->pdata->decon_clk.vclk_denom;

	d->point[D_DISP_VCLK]		=	&decon->pdata->decon_clk.disp_vclk;
#endif

#if defined(CONFIG_SOC_EXYNOS7870)
	d->point[D_DISP_PLL_CLK]	=	&decon->pdata->disp_pll_clk;
	d->point[D_DISP_VCLK]		=	&decon->pdata->disp_vclk;
#endif

#if defined(CONFIG_SOC_EXYNOS7885)
	d->point[D_VT_COMPENSATION]	=	&lcd_info->vt_compensation;
	d->point[D_CMD_UNDERRUN_LP_REF]	=	&lcd_info->cmd_underrun_lp_ref;
#endif

#if defined(CONFIG_SOC_EXYNOS9610)
	d->point[D_VT_COMPENSATION]	=	&lcd_info->vt_compensation;
	d->point[D_CMD_UNDERRUN_LP_REF]	=	lcd_info->cmd_underrun_lp_ref;
#endif
}

static inline void update_value(u32 *dest, u32 *src, u32 update)
{
	if (IS_ERR_OR_NULL(dest) || IS_ERR_OR_NULL(src) || !update)
		return;

	if (*dest == *src || !update)
		return;

	*dest = *src;

	dbg_boot("dest: %4u, src: %4u, update: %u\n", *dest, *src, update);
}

static void update_point(u32 **dest, u32 *src, u32 *update)
{
	unsigned int i, j;

	for (i = 0; i < D_MAX; i++) {
		for (j = 0; j < debugfs_list[i].length; j++) {
			update_value(dest[i + j], &src[i + j], update ? update[i + j] : 1);
			if (update)
				update[i + j] = 0;
		}
	}
}

static void update_param(u32 *dest, u32 **src, u32 *update)
{
	unsigned int i, j;

	for (i = 0; i < D_MAX; i++) {
		for (j = 0; j < debugfs_list[i].length; j++)
			update_value(&dest[i + j], src[i + j], update ? update[i + j] : 1);
	}
}

static int fb_notifier_callback(struct notifier_block *self,
			unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	struct d_info *d = NULL;
	int fb_blank;

	switch (event) {
	case FB_EVENT_BLANK:
	case FB_EARLY_EVENT_BLANK:
		break;
	default:
		return NOTIFY_DONE;
	}

	d = container_of(self, struct d_info, fb_notifier);

	fb_blank = *(int *)evdata->data;

	if (evdata->info->node)
		return NOTIFY_DONE;

	dbg_info("%s: %d\n",
		(event == FB_EVENT_BLANK) ? "FB_EVENT_BLANK" : "FB_EARLY_EVENT_BLANK", fb_blank);

	log_boot = true;

	if (event == FB_EVENT_BLANK && fb_blank == FB_BLANK_UNBLANK)
		d->enable = 1;
	else if (fb_blank == FB_BLANK_POWERDOWN)
		d->enable = 0;

	if (fb_blank == FB_BLANK_UNBLANK && event == FB_EARLY_EVENT_BLANK)
		update_point(d->point, d->request_param, d->pending_param);

	if (fb_blank == FB_BLANK_UNBLANK && event == FB_EVENT_BLANK)
		update_param(d->current_param, d->point, NULL);

	return NOTIFY_DONE;
}

/* copy from debugfs/file.c */
struct array_data {
	void *array;
	void *pending;
	u32 elements;
};

static ssize_t u32_array_write(struct file *f, const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct array_data *data = ((struct seq_file *)f->private_data)->private;
	u32 *array = data->array;
	u32 *pending = data->pending;
	int array_size = data->elements;

	unsigned char ibuf[MAX_INPUT] = {0, };
	unsigned int tbuf[MAX_INPUT] = {0, };
	unsigned int value, i;
	char *pbuf, *token = NULL;
	int ret = 0, end = 0;

	ret = dd_simple_write_to_buffer(ibuf, sizeof(ibuf), ppos, user_buf, count);
	if (ret < 0) {
		dbg_info("dd_simple_write_to_buffer fail: %d\n", ret);
		goto exit;
	}

	pbuf = ibuf;
	while (--array_size >= 0 && (token = strsep(&pbuf, " "))) {
		dbg_info("%d, %s\n", array_size, token);
		ret = kstrtou32(token, 0, &value);
		if (ret < 0) {
			dbg_info("kstrtou32 fail: ret: %d\n", ret);
			break;
		}

		if (end == ARRAY_SIZE(tbuf)) {
			dbg_info("invalid input: end: %d, tbuf: %zu\n", end, ARRAY_SIZE(tbuf));
			break;
		}

		tbuf[end] = value;
		end++;
	}

	if (ret < 0 || !end || data->elements < end || end == ARRAY_SIZE(tbuf)) {
		dbg_info("invalid input: end: %d, %s\n", end, user_buf);
		goto exit;
	}

	for (i = 0; i < end; i++) {
		array[i] = tbuf[i];
		pending[i] = 1;
	}

exit:
	return count;
}

static size_t u32_format_array(char *buf, size_t bufsize,
			       u32 *array, int array_size)
{
	size_t ret = 0;

	while (--array_size >= 0) {
		size_t len;
		char term = array_size ? ' ' : '\n';

		len = snprintf(buf, bufsize, "%u%c", *array++, term);
		ret += len;

		buf += len;
		bufsize -= len;
	}
	return ret;
}

static int u32_array_show(struct seq_file *m, void *unused)
{
	struct array_data *data = m->private;
	int size, elements = data->elements;
	char *buf;
	int ret;

	/*
	 * Max size:
	 *  - 10 digits + ' '/'\n' = 11 bytes per number
	 *  - terminating NUL character
	 */
	size = elements*11;
	buf = kzalloc(size+1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	buf[size] = 0;

	ret = u32_format_array(buf, size, data->array, data->elements);

	seq_printf(m, "%s", buf);

	kfree(buf);

	return 0;
}

static int u32_array_open(struct inode *inode, struct file *f)
{
	return single_open(f, u32_array_show, inode->i_private);
}

static const struct file_operations u32_array_fops = {
	.open		= u32_array_open,
	.write		= u32_array_write,
	.read		= seq_read,
	.llseek		= no_llseek,
	.release	= single_release,
};

static struct dentry *debugfs_create_array(const char *name, umode_t mode,
					struct dentry *parent,
					u32 *request, u32 *pending, u32 elements)
{
	struct array_data *data = kzalloc(sizeof(*data), GFP_KERNEL);

	if (data == NULL)
		return NULL;

	data->array = request;
	data->pending = pending;

	data->elements = elements;

	return debugfs_create_file(name, mode, parent, data, &u32_array_fops);
}

static int init_debugfs_lcd_info(struct d_info *d)
{
	struct device_node *np = NULL;
	struct device_node *nplcd = NULL;
	struct device_node *npetc = NULL;
	int ret = 0, count;
	unsigned int i = 0;
	struct dentry *debugfs = NULL;

	nplcd = of_find_node_with_property(NULL, LCD_INFO_DTS_NAME);
	if (!nplcd) {
		dbg_warn("%s property does not exist\n", LCD_INFO_DTS_NAME);
		return -EINVAL;
	}

	dbg_info("%s property find in node %s\n", LCD_INFO_DTS_NAME, nplcd->name);

	nplcd = of_parse_phandle(nplcd, LCD_INFO_DTS_NAME, 0);
	if (!nplcd) {
		dbg_warn("%s node does not exist\n", LCD_INFO_DTS_NAME);
		return -EINVAL;
	}

	configure_param(d);

	for (i = 0; i < D_MAX; i++) {
		if (!strlen(debugfs_list[i].dts_name))
			continue;

		if (i < D_LCD_INFO_END)
			count = of_property_count_u32_elems(nplcd, debugfs_list[i].dts_name);
		else {
			npetc = of_find_node_with_property(NULL, debugfs_list[i].dts_name);
			count = npetc ? of_property_count_u32_elems(npetc, debugfs_list[i].dts_name) : 0;
		}

		if (count <= 0)
			continue;

		np = (i < D_LCD_INFO_END) ? nplcd : npetc;

		debugfs_list[i].length = count;

		debugfs = debugfs_create_array(debugfs_list[i].sysfs_name, debugfs_list[i].mode, d->debugfs_root,
			&d->request_param[i], &d->pending_param[i], count);

		if (debugfs)
			dbg_info("%s is created and length is %d\n", debugfs_list[i].sysfs_name, debugfs_list[i].length);

	}

	update_param(d->default_param, d->point, NULL);
	update_param(d->request_param, d->point, NULL);
	update_param(d->current_param, d->point, NULL);

	return ret;
}

static int status_show(struct seq_file *m, void *unused)
{
	struct d_info *d = m->private;
	unsigned int i, j;

	seq_puts(m, "--------------------------------------------------------------\n");
	seq_puts(m, "                    |    DEFAULT|    REQUEST|    CURRENT|   RW\n");
	seq_puts(m, "--------------------------------------------------------------\n");
	for (i = 0; i < D_MAX; i++) {
		for (j = 0; j < debugfs_list[i].length; j++) {
			if (d->pending_param[i + j])
				seq_printf(m, "%20s| %10u| %10u| %10u| %4s\n", D_LIST_NAME[i + j], d->default_param[i + j], d->request_param[i + j], d->current_param[i + j], (debugfs_list[i].mode & 0222) ? "RW" : "R");
			else
				seq_printf(m, "%20s| %10u| %10s| %10u| %4s\n", D_LIST_NAME[i + j], d->default_param[i + j], " ", d->current_param[i + j], (debugfs_list[i].mode & 0222) ? "RW" : "R");
		}
	}
	seq_puts(m, "\n");

	return 0;
}

static int status_open(struct inode *inode, struct file *f)
{
	return single_open(f, status_show, inode->i_private);
}

static ssize_t status_write(struct file *f, const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct d_info *d = ((struct seq_file *)f->private_data)->private;
	unsigned char ibuf[MAX_INPUT] = {0, };
	int ret = 0;

	ret = dd_simple_write_to_buffer(ibuf, sizeof(ibuf), ppos, user_buf, count);
	if (ret < 0) {
		dbg_info("dd_simple_write_to_buffer fail: %d\n", ret);
		goto exit;
	}

	if (!strncmp(ibuf, "0", count - 1)) {
		dbg_info("input is 0(zero). reset request parameter to default\n");

		memcpy(d->request_param, d->default_param, sizeof(d->request_param));
		memset(d->pending_param, 1, sizeof(d->pending_param));
	}

exit:
	return count;
}

static const struct file_operations status_fops = {
	.open		= status_open,
	.write		= status_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int regdump_show(struct seq_file *m, void *unused)
{
	struct d_info *d = m->private;
	u32 reg = 0, val = 0;
	void __iomem *ioregs = NULL;

	if (!d->enable) {
		dbg_info("enable is %s\n", d->enable ? "on" : "off");
		seq_printf(m, "enable is %s\n", d->enable ? "on" : "off");
		goto exit;
	}

	reg = d->regdump;
	if (!reg) {
		dbg_info("input reg is invalid, %8x\n", reg);
		goto exit;
	}

	ioregs = ioremap(d->regdump, SZ_4);
	if (IS_ERR_OR_NULL(ioregs)) {
		dbg_info("ioremap fail for %8x\n", reg);
		goto exit;
	}

	val = readl(ioregs);

	dbg_info("reg: %8x, val: %8x\n", reg, val);

	seq_printf(m, "reg: %8x, val: %8x\n", reg, val);

	iounmap(ioregs);

exit:
	return 0;
}

static int regdump_open(struct inode *inode, struct file *f)
{
	return single_open(f, regdump_show, inode->i_private);
}

static ssize_t regdump_write(struct file *f, const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct d_info *d = ((struct seq_file *)f->private_data)->private;
	int ret = 0;
	u32 reg = 0, val = 0;
	void __iomem *ioregs = NULL;
	unsigned char ibuf[MAX_INPUT] = {0, };

	if (!d->enable) {
		dbg_info("enable is %s\n", d->enable ? "on" : "off");
		goto exit;
	}

	ret = dd_simple_write_to_buffer(ibuf, sizeof(ibuf), ppos, user_buf, count);
	if (ret < 0) {
		dbg_info("dd_simple_write_to_buffer fail: %d\n", ret);
		goto exit;
	}

	ret = sscanf(ibuf, "%x %x", &reg, &val);
	if (clamp(ret, 1, 2) != ret) {
		dbg_info("input is invalid, %d\n", ret);
		goto exit;
	}

	if (reg > UINT_MAX) {
		dbg_info("input is invalid, reg: %02x\n", reg);
		goto exit;
	}

	if (val > UINT_MAX) {
		dbg_info("input is invalid, val: %02x\n", val);
		goto exit;
	}

	if (!reg) {
		dbg_info("input reg is invalid, %8x\n", reg);
		goto exit;
	}

	d->regdump = reg;

	ioregs = ioremap(d->regdump, SZ_4);
	if (IS_ERR_OR_NULL(ioregs)) {
		dbg_info("ioremap fail for %8x\n", reg);
		goto exit;
	}

	if (ret == 2)
		writel(val, ioregs);
	else if (ret == 1)
		val = readl(ioregs);

	dbg_info("reg: %8x, val: %8x%s\n", reg, val, (ret == 2) ? ", write_mode" : "");

	iounmap(ioregs);
exit:
	return count;
}

static const struct file_operations regdump_fops = {
	.open		= regdump_open,
	.write		= regdump_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int help_show(struct seq_file *m, void *unused)
{
	struct d_info *d = m->private;
	unsigned int i, j;

	seq_puts(m, "\n");
	seq_puts(m, "------------------------------------------------------------\n");
	seq_puts(m, "* ATTENTION\n");
	seq_puts(m, "* These sysfs can NOT be mandatory official purpose\n");
	seq_puts(m, "* These sysfs has risky, harmful, unstable function\n");
	seq_puts(m, "* So we can not support these sysfs for official use\n");
	seq_puts(m, "* DO NOT request improvement related with these function\n");
	seq_puts(m, "* DO NOT request these function as the mandatory requirements\n");
	seq_puts(m, "* If you insist, we eliminate these function immediately\n");
	seq_puts(m, "------------------------------------------------------------\n");
	seq_puts(m, "\n");
	seq_puts(m, "----------\n");
	seq_puts(m, "# cd /d/dd_dpu\n");
	seq_puts(m, "\n");
	seq_puts(m, "---------- usage\n");
	seq_puts(m, "1. you can request to change paremter like below\n");
	for (i = 0; i < D_MAX; i++) {
		if (!debugfs_list[i].length || !(debugfs_list[i].mode & 0222))
			continue;

		seq_puts(m, "# echo ");
		for (j = 0; j < debugfs_list[i].length; j++)
			seq_printf(m, "%s ", D_LIST_NAME[i + j]);
		seq_printf(m, "> %s\n", debugfs_list[i].sysfs_name);
	}

	for (i = 0; i < D_MAX; i++) {
		if (!debugfs_list[i].length || !(debugfs_list[i].mode & 0222))
			continue;

		seq_puts(m, "ex) # echo ");
		for (j = 0; j < debugfs_list[i].length; j++)
			seq_printf(m, "%d ", d->default_param[i + j]);
		seq_printf(m, "> %s\n", debugfs_list[i].sysfs_name);
	}

	seq_puts(m, "\n");
	seq_puts(m, "2. and you must do lcd off -> on to apply your request\n");
	seq_puts(m, "3. it is IMPOSSIBLE to apply parameter immediately during lcd on runtime\n");
	seq_puts(m, "\n");
	seq_puts(m, "---------- status usage\n");
	seq_puts(m, "1. you can check current configuration status like below\n");
	seq_puts(m, "# cat status\n");
	seq_puts(m, "--------------------------------------------------------------\n");
	seq_puts(m, "                    |    DEFAULT|    REQUEST|    CURRENT|   RW\n");
	seq_puts(m, "--------------------------------------------------------------\n");
	for (i = 0; i < D_MAX; i++) {
		for (j = 0; j < debugfs_list[i].length; j++) {
			if (d->pending_param[i + j])
				seq_printf(m, "%20s| %10u| %10u| %10u| %4s\n", D_LIST_NAME[i + j], d->default_param[i + j], d->request_param[i + j], d->current_param[i + j], (debugfs_list[i].mode & 0222) ? "RW" : "R");
			else
				seq_printf(m, "%20s| %10u| %10s| %10u| %4s\n", D_LIST_NAME[i + j], d->default_param[i + j], " ", d->current_param[i + j], (debugfs_list[i].mode & 0222) ? "RW" : "R");
		}
	}
	seq_puts(m, "\n");
	seq_puts(m, "= DEFAULT: default booting parameter\n");
	seq_puts(m, "= REQUEST: request parameter (not applied yet)\n");
	seq_puts(m, "= CURRENT: current applied parameter\n");
	seq_puts(m, "\n");


	return 0;
}

static int help_open(struct inode *inode, struct file *f)
{
	return single_open(f, help_show, inode->i_private);
}

static const struct file_operations help_fops = {
	.open		= help_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int init_debugfs_dpu(void)
{
	int ret = 0;
	static struct dentry *debugfs_root;
	struct d_info *d = NULL;
	struct dsim_device *dsim = get_dsim_drvdata(0);
	struct device *dev = dsim->dev;

	if (!dev) {
		dbg_warn("failed to get device\n");
		ret = -ENODEV;
		goto exit;
	}

	dbg_info("+\n");

	d = kzalloc(sizeof(struct d_info), GFP_KERNEL);

	if (!debugfs_root)
		debugfs_root = debugfs_create_dir("dd_dpu", NULL);

	d->dev = dev;
	d->debugfs_root = debugfs_root;

	debugfs_create_file("_help", 0400, debugfs_root, d, &help_fops);
	debugfs_create_file("status", 0400, debugfs_root, d, &status_fops);
	debugfs_create_file("regdump", 0600, debugfs_root, d, &regdump_fops);

	init_debugfs_lcd_info(d);

	d->fb_notifier.notifier_call = fb_notifier_callback;
	ret = decon_register_notifier(&d->fb_notifier);
	d->enable = 1;

	dbg_info("-\n");

exit:
	return ret;
}

static int __init dd_dpu_init(void)
{
	init_debugfs_dpu();

	return 0;
}

late_initcall(dd_dpu_init);
#endif

