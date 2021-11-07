/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Core file for Samsung EXYNOS DECON driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/pm_runtime.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/fb.h>
#include <linux/delay.h>
#include <linux/clk-provider.h>
#include <linux/console.h>
#include <linux/dma-buf.h>
#include <linux/exynos_ion.h>
#include <linux/ion.h>
#include <linux/highmem.h>
#include <linux/memblock.h>
#include <linux/exynos_iovmm.h>
#include <linux/bug.h>
#include <linux/of_address.h>
#include <linux/smc.h>
#include <linux/debugfs.h>

#include <media/exynos_mc.h>
#include <video/mipi_display.h>
#include <media/v4l2-subdev.h>

#include "decon.h"
#include "dsim.h"
#include "decon_helper.h"
#include "./panels/lcd_ctrl.h"
#include "../../../../staging/android/sw_sync.h"
#include "vpp/vpp.h"
#include "decon_bts.h"

#ifdef CONFIG_MACH_VELOCE8890
#define DISP_SYSMMU_DIS
#define DISP_PWR_CLK_CTRL_DIS
#endif

#define SUCCESS_EXYNOS_SMC	2
#define TRACE_VPP_LOG(d, prot) ({	\
	d->vpp_log[d->log_cnt].decon_id = d->id;	\
	d->vpp_log[d->log_cnt].time = sched_clock();	\
	d->vpp_log[d->log_cnt].protection = prot;	\
	d->vpp_log[d->log_cnt].line = __LINE__;		\
	d->log_cnt = ++d->log_cnt >= MAX_VPP_LOG ? 0 : d->log_cnt;	\
	})

#ifdef CONFIG_OF
static const struct of_device_id decon_device_table[] = {
	{ .compatible = "samsung,exynos8-decon_driver" },
	{},
};
MODULE_DEVICE_TABLE(of, decon_device_table);
#endif

int decon_log_level = 6;
module_param(decon_log_level, int, 0644);

struct decon_device *decon_f_drvdata;
EXPORT_SYMBOL(decon_f_drvdata);
struct decon_device *decon_s_drvdata;
EXPORT_SYMBOL(decon_s_drvdata);
struct decon_device *decon_t_drvdata;
EXPORT_SYMBOL(decon_t_drvdata);

static int decon_runtime_resume(struct device *dev);
static int decon_runtime_suspend(struct device *dev);
static void decon_set_protected_content(struct decon_device *decon,
		struct decon_reg_data *reg);

static void vpp_dump(struct decon_device *decon);
#ifdef CONFIG_USE_VSYNC_SKIP
static atomic_t extra_vsync_wait;
#endif /* CCONFIG_USE_VSYNC_SKIP */

void decon_dump(struct decon_device *decon)
{
	int acquired = console_trylock();

	decon_info("\n=== DECON%d SFR DUMP ===\n", decon->id);
	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
			decon->regs, 0x2AC, false);

	if (decon->lcd_info->mic_enabled) {
		decon_info("\n=== DECON%d MIC SFR DUMP ===\n", decon->id);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
				decon->regs + 0x1000, 0x20, false);
	} else if (decon->lcd_info->dsc_enabled) {
		decon_info("\n=== DECON%d DSC0 SFR DUMP ===\n", decon->id);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
				decon->regs + 0x2000, 0xA0, false);

		decon_info("\n=== DECON%d DSC1 SFR DUMP ===\n", decon->id);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
				decon->regs + 0x3000, 0xA0, false);
	}

	if (decon->pdata->dsi_mode != DSI_MODE_SINGLE) {
		decon_info("\n=== DECON%d DISPIF2 SFR DUMP ===\n", decon->id);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
				decon->regs + 0x5080, 0x80, false);

		decon_info("\n=== DECON%d DISPIF3 SFR DUMP ===\n", decon->id);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
				decon->regs + 0x6080, 0x80, false);
	}

	decon_info("\n=== DECON%d SHADOW SFR DUMP ===\n", decon->id);
	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 4,
			decon->regs + SHADOW_OFFSET, 0x2AC, false);

	v4l2_subdev_call(decon->output_sd, core, ioctl, DSIM_IOC_DUMP, NULL);
	vpp_dump(decon);

	if (acquired)
		console_unlock();
}

/* ---------- CHECK FUNCTIONS ----------- */
static void decon_win_conig_to_regs_param
	(int transp_length, struct decon_win_config *win_config,
	 struct decon_window_regs *win_regs, enum decon_idma_type idma_type)
{
	u8 alpha0, alpha1;

	if ((win_config->plane_alpha > 0) && (win_config->plane_alpha < 0xFF)) {
		alpha0 = win_config->plane_alpha;
		alpha1 = 0;
		if (!transp_length && (win_config->blending == DECON_BLENDING_PREMULT))
			win_config->blending = DECON_BLENDING_COVERAGE;

		if (transp_length && (win_config->blending == DECON_BLENDING_PREMULT))
			decon_err("%s: (DECON_BLENDING_PREMULT + Plane Alpha) not supported", __func__);
	} else {
		alpha0 = 0xFF;
		alpha1 = 0xff;
	}

	win_regs->wincon = wincon(transp_length, alpha0, alpha1,
			win_config->plane_alpha, win_config->blending);
	win_regs->start_pos = win_start_pos(win_config->dst.x, win_config->dst.y);
	win_regs->end_pos = win_end_pos(win_config->dst.x, win_config->dst.y,
			win_config->dst.w, win_config->dst.h);
	win_regs->pixel_count = (win_config->dst.w * win_config->dst.h);
	win_regs->whole_w = win_config->dst.f_w;
	win_regs->whole_h = win_config->dst.f_h;
	win_regs->offset_x = win_config->dst.x;
	win_regs->offset_y = win_config->dst.y;
	win_regs->type = idma_type;

	decon_dbg("DMATYPE_%d@ SRC:(%d,%d) %dx%d  DST:(%d,%d) %dx%d\n",
			idma_type,
			win_config->src.x, win_config->src.y,
			win_config->src.f_w, win_config->src.f_h,
			win_config->dst.x, win_config->dst.y,
			win_config->dst.w, win_config->dst.h);
}

static u16 fb_panstep(u32 res, u32 res_virtual)
{
	return res_virtual > res ? 1 : 0;
}

u32 wincon(u32 transp_len, u32 a0, u32 a1,
	int plane_alpha, enum decon_blending blending)
{
	u32 data = 0;
	int is_plane_alpha = (plane_alpha < 255 && plane_alpha > 0) ? 1 : 0;

	if (transp_len == 1 && blending == DECON_BLENDING_PREMULT)
		blending = DECON_BLENDING_COVERAGE;

	if (is_plane_alpha) {
		if (transp_len) {
			if (blending != DECON_BLENDING_NONE)
				data |= WIN_CONTROL_ALPHA_MUL_F;
		} else {
			if (blending == DECON_BLENDING_PREMULT)
				blending = DECON_BLENDING_COVERAGE;
		}
	}

	if (transp_len > 1)
		data |= WIN_CONTROL_ALPHA_SEL_F(W_ALPHA_SEL_F_BYAEN);

	switch (blending) {
	case DECON_BLENDING_NONE:
		data |= WIN_CONTROL_FUNC_F(PD_FUNC_COPY);
		break;

	case DECON_BLENDING_PREMULT:
		if (!is_plane_alpha) {
			data |= WIN_CONTROL_FUNC_F(PD_FUNC_SOURCE_OVER);
		} else {
			/* need to check the eq: it is SPEC-OUT */
			data |= WIN_CONTROL_FUNC_F(PD_FUNC_SOURCE_A_TOP);
		}
		break;

	case DECON_BLENDING_COVERAGE:
	default:
		data |= WIN_CONTROL_FUNC_F(PD_FUNC_LEGACY);
		break;
	}

	data |= WIN_CONTROL_ALPHA0_F(a0) | WIN_CONTROL_ALPHA1_F(a1);

	return data;
}

#ifdef CONFIG_USE_VSYNC_SKIP
void decon_extra_vsync_wait_set(int set_count)
{
	atomic_set(&extra_vsync_wait, set_count);
}

int decon_extra_vsync_wait_get(void)
{
	return atomic_read(&extra_vsync_wait);
}

void decon_extra_vsync_wait_add(int skip_count)
{
	atomic_add(skip_count, &extra_vsync_wait);
}
#endif /* CONFIG_USE_VSYNC_SKIP */


static inline bool is_rgb32(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return true;
	default:
		return false;
	}
}

static u32 decon_red_length(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 8;

	case DECON_PIXEL_FORMAT_RGBA_5551:
		return 5;

	case DECON_PIXEL_FORMAT_RGB_565:
		return 5;

	default:
		return 0;
	}
}

static u32 decon_red_offset(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_RGBA_5551:
		return 0;

	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
		return 8;

	case DECON_PIXEL_FORMAT_RGB_565:
		return 11;

	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 16;

	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
		return 24;

	default:
		return 0;
	}
}

static u32 decon_green_length(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 8;

	case DECON_PIXEL_FORMAT_RGBA_5551:
		return 5;

	case DECON_PIXEL_FORMAT_RGB_565:
		return 6;

	default:
		decon_warn("unrecognized pixel format %u\n", format);
		return 0;
	}
}

static u32 decon_green_offset(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 8;

	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
		return 16;

	case DECON_PIXEL_FORMAT_RGBA_5551:
	case DECON_PIXEL_FORMAT_RGB_565:
		return 5;
	default:
		decon_warn("unrecognized pixel format %u\n", format);
		return 0;
	}
}

static u32 decon_blue_length(int format)
{
	return decon_red_length(format);
}

static u32 decon_blue_offset(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
		return 16;

	case DECON_PIXEL_FORMAT_RGBA_5551:
		return 10;

	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
		return 8;

	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
		return 24;

	case DECON_PIXEL_FORMAT_RGB_565:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 0;

	default:
		decon_warn("unrecognized pixel format %u\n", format);
		return 0;
	}
}

static u32 decon_transp_length(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
		return 8;

	case DECON_PIXEL_FORMAT_RGBA_5551:
		return 1;

	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_RGB_565:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 0;

	default:
		return 0;
	}
}

static u32 decon_transp_offset(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
		return 24;

	case DECON_PIXEL_FORMAT_RGBA_5551:
		return 15;

	case DECON_PIXEL_FORMAT_RGBX_8888:
		return decon_blue_offset(format);

	case DECON_PIXEL_FORMAT_BGRX_8888:
		return decon_red_offset(format);

	case DECON_PIXEL_FORMAT_RGB_565:
		return 0;

	default:
		return 0;
	}
}

static u32 decon_padding(int format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return 8;

	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_RGBA_5551:
	case DECON_PIXEL_FORMAT_RGB_565:
	case DECON_PIXEL_FORMAT_BGRA_8888:
		return 0;

	default:
		decon_warn("unrecognized pixel format %u\n", format);
		return 0;
	}

}

bool decon_validate_x_alignment(struct decon_device *decon, int x, u32 w,
		u32 bits_per_pixel)
{
	uint8_t pixel_alignment = 32 / bits_per_pixel;

	if (x % pixel_alignment) {
		decon_err("left X coordinate not properly aligned to %u-pixel boundary (bpp = %u, x = %u)\n",
				pixel_alignment, bits_per_pixel, x);
		return 0;
	}
	if ((x + w) % pixel_alignment) {
		decon_err("right X coordinate not properly aligned to %u-pixel boundary (bpp = %u, x = %u, w = %u)\n",
				pixel_alignment, bits_per_pixel, x, w);
		return 0;
	}

	return 1;
}

static unsigned int decon_calc_bandwidth(u32 w, u32 h, u32 bits_per_pixel, int fps)
{
	unsigned int bw = w * h;

	bw *= DIV_ROUND_UP(bits_per_pixel, 8);
	bw *= fps;

	return bw;
}

/* ---------- OVERLAP COUNT CALCULATION ----------- */
static inline int rect_width(struct decon_rect *r)
{
	return	r->right - r->left;
}

static inline int rect_height(struct decon_rect *r)
{
	return	r->bottom - r->top;
}

#ifdef CONFIG_FB_WINDOW_UPDATE
static bool decon_intersect(struct decon_rect *r1, struct decon_rect *r2)
{
	return !(r1->left > r2->right || r1->right < r2->left ||
		r1->top > r2->bottom || r1->bottom < r2->top);
}

static int decon_intersection(struct decon_rect *r1,
			struct decon_rect *r2, struct decon_rect *r3)
{
	r3->top = max(r1->top, r2->top);
	r3->bottom = min(r1->bottom, r2->bottom);
	r3->left = max(r1->left, r2->left);
	r3->right = min(r1->right, r2->right);
	return 0;
}

static int decon_union(struct decon_rect *r1,
		struct decon_rect *r2, struct decon_rect *r3)
{
	r3->top = min(r1->top, r2->top);
	r3->bottom = max(r1->bottom, r2->bottom);
	r3->left = min(r1->left, r2->left);
	r3->right = max(r1->right, r2->right);
	return 0;
}

static bool is_decon_rect_differ(struct decon_rect *r1,
		struct decon_rect *r2)
{
	return ((r1->left != r2->left) || (r1->top != r2->top) ||
		(r1->right != r2->right) || (r1->bottom != r2->bottom));
}

static inline bool does_layer_need_scale(struct decon_win_config *config)
{
	return (config->dst.w != config->src.w) || (config->dst.h != config->src.h);
}
#endif

static int decon_set_win_blocking_mode(struct decon_device *decon, struct decon_win *win,
		struct decon_win_config *win_config, struct decon_reg_data *regs)
{
#ifdef CONFIG_DECON_BLOCKING_MODE
	struct decon_rect r1, r2, overlap_rect, block_rect;
	unsigned int overlap_size, blocking_size = 0;
	struct decon_win_config *config = &win_config[win->index];
	int j;
	bool enabled = false;

	/* Blocking mode is supported for only RGB32 color formats */
	if (!is_rgb32(config->format) ||
		((config->plane_alpha < 255) && (config->plane_alpha > 0)))
		return 0;

	/* Blocking Mode is not supported if there is a rotation */
	if (is_rotation(config))
		return 0;

	r1.left = win_config[win->index].dst.x;
	r1.top = win_config[win->index].dst.y;
	r1.right = r1.left + win_config[win->index].dst.w - 1;
	r1.bottom = r1.top + win_config[win->index].dst.h - 1;

	/* Calculate the window Blocking region from the top windows opaque rect */
	memset(&block_rect, 0, sizeof(struct decon_rect));
	for (j = win->index + 1; j < decon->pdata->max_win; j++) {
		config = &win_config[j];
		if (config->state != DECON_WIN_STATE_BUFFER)
			continue;

		/* If top window needs plane alpha, bottom window can't use blocking mode */
		if ((config->plane_alpha < 255) && (config->plane_alpha > 0))
			continue;

		if (!(config->covered_opaque_area.w && config->covered_opaque_area.h))
			continue;

		r2.left = config->covered_opaque_area.x;
		r2.top = config->covered_opaque_area.y;
		r2.right = r2.left + config->covered_opaque_area.w - 1;
		r2.bottom = r2.top + config->covered_opaque_area.h - 1;
		/* overlaps or not */
		if (decon_intersect(&r1, &r2)) {
			decon_intersection(&r1, &r2, &overlap_rect);
			if (!is_decon_rect_differ(&r1, &overlap_rect)) {
				/* window rect and blocking rect is same. */
				win_config[win->index].state = DECON_WIN_STATE_DISABLED;
				return 1;
			}

			if (overlap_rect.right - overlap_rect.left + 1 <
					MIN_BLK_MODE_WIDTH ||
				overlap_rect.bottom - overlap_rect.top + 1 <
					MIN_BLK_MODE_HEIGHT)
				continue;

			overlap_size = (overlap_rect.right - overlap_rect.left) *
					(overlap_rect.bottom - overlap_rect.top);

			if (overlap_size > blocking_size) {
				memcpy(&block_rect, &overlap_rect,
						sizeof(struct decon_rect));
				blocking_size = (block_rect.right - block_rect.left) *
						(block_rect.bottom - block_rect.top);
				enabled = true;
			}
		}
	}

	config = &win_config[win->index];
	if ((rect_width(&block_rect) * rect_height(&block_rect)) <
			(config->transparent_area.w * config->transparent_area.h)) {
		block_rect.left = config->transparent_area.x;
		block_rect.top = config->transparent_area.y;
		block_rect.right = block_rect.left + config->transparent_area.w - 1;
		block_rect.bottom = block_rect.top + config->transparent_area.h - 1;
		enabled = true;
	}

	if (enabled) {
		regs->block_rect[win->index].w = block_rect.right - block_rect.left + 1;
		regs->block_rect[win->index].h = block_rect.bottom - block_rect.top + 1;
		regs->block_rect[win->index].x = block_rect.left - win_config[win->index].dst.x;
		regs->block_rect[win->index].y = block_rect.top -  win_config[win->index].dst.y;
		decon_dbg("win-%d: block_rect[%d %d %d %d]\n", win->index, regs->block_rect[win->index].x,
			regs->block_rect[win->index].y, regs->block_rect[win->index].w,
			regs->block_rect[win->index].h);
		memcpy(&win_config->block_area, &regs->block_rect[win->index],
				sizeof(struct decon_win_rect));
	}
#endif
	return 0;
}

static void vpp_dump(struct decon_device *decon)
{
	int i;

	for (i = 0; i < MAX_VPP_SUBDEV; i++) {
		if (decon->vpp_used[i]) {
			struct v4l2_subdev *sd = NULL;
			sd = decon->mdev->vpp_sd[i];
			BUG_ON(!sd);
			v4l2_subdev_call(sd, core, ioctl, VPP_DUMP, NULL);
		}
	}
}

static void decon_vpp_stop(struct decon_device *decon, bool do_reset)
{
	int i;
	unsigned long state = (unsigned long)do_reset;

	for (i = 0; i < MAX_VPP_SUBDEV; i++) {
		if (decon->vpp_used[i] && (!(decon->vpp_usage_bitmask & (1 << i)))) {
			struct v4l2_subdev *sd = NULL;
			sd = decon->mdev->vpp_sd[i];
			BUG_ON(!sd);
			if (decon->vpp_err_stat[i])
				state = VPP_STOP_ERR;
			v4l2_subdev_call(sd, core, ioctl, VPP_STOP,
						(unsigned long *)state);
			decon->vpp_used[i] = false;
			decon->vpp_err_stat[i] = false;
		}
	}
}

#ifdef CONFIG_FB_WINDOW_UPDATE
static inline void decon_win_update_rect_reset(struct decon_device *decon)
{
	decon->update_win.x = 0;
	decon->update_win.y = 0;
	decon->update_win.w = 0;
	decon->update_win.h = 0;
	decon->need_update = true;
}

static void decon_wait_for_framedone(struct decon_device *decon)
{
	int ret;
	s64 time_ms = ktime_to_ms(ktime_get()) - ktime_to_ms(decon->trig_mask_timestamp);

	if (time_ms < MAX_FRM_DONE_WAIT) {
		DISP_SS_EVENT_LOG(DISP_EVT_DECON_FRAMEDONE_WAIT, &decon->sd, ktime_set(0, 0));
		ret = wait_event_interruptible_timeout(decon->wait_frmdone,
				(decon->frame_done_cnt_target <= decon->frame_done_cnt_cur),
				msecs_to_jiffies(MAX_FRM_DONE_WAIT - time_ms));
	}
}

static int decon_reg_ddi_partial_cmd(struct decon_device *decon, struct decon_win_rect *rect)
{
	struct decon_win_rect win_rect;
	int ret;

	decon_wait_for_framedone(decon);
	/* TODO: need to set DSI_IDX */
	decon_reg_wait_linecnt_is_zero_timeout(decon->id, 0, 35 * 1000);
	DISP_SS_EVENT_LOG(DISP_EVT_LINECNT_ZERO, &decon->sd, ktime_set(0, 0));
	/* Partial Command */
	win_rect.x = rect->x;
	win_rect.y = rect->y;
	/* w is right & h is bottom */
	win_rect.w = rect->x + rect->w - 1;
	win_rect.h = rect->y + rect->h - 1;
	ret = v4l2_subdev_call(decon->output_sd, core, ioctl,
			DSIM_IOC_PARTIAL_CMD, &win_rect);
	if (ret) {
		decon_win_update_rect_reset(decon);
		decon_err("%s: partial_area CMD is failed  %s [%d %d %d %d]\n",
				__func__, decon->output_sd->name, rect->x,
				rect->y, rect->w, rect->h);
	}

	return ret;
}

static int decon_win_update_disp_config(struct decon_device *decon,
					struct decon_win_rect *win_rect)
{
	struct decon_lcd lcd_info;
	int ret = 0;

	memcpy(&lcd_info, decon->lcd_info, sizeof(struct decon_lcd));
	lcd_info.xres = win_rect->w;
	lcd_info.yres = win_rect->h;

	lcd_info.hfp = decon->lcd_info->hfp + ((decon->lcd_info->xres - win_rect->w) >> 1);
	lcd_info.vfp = decon->lcd_info->vfp + decon->lcd_info->yres - win_rect->h;

	v4l2_set_subdev_hostdata(decon->output_sd, &lcd_info);
	ret = v4l2_subdev_call(decon->output_sd, core, ioctl, DSIM_IOC_SET_PORCH, NULL);
	if (ret) {
		decon_win_update_rect_reset(decon);
		decon_err("failed to set porch values of DSIM [%d %d %d %d]\n",
				win_rect->x, win_rect->y,
				win_rect->w, win_rect->h);
	}

	decon_reg_set_partial_update(decon->id, decon->pdata->dsi_mode, &lcd_info);
	decon_win_update_dbg("[WIN_UPDATE]%s : vfp %d vbp %d vsa %d hfp %d hbp %d hsa %d w %d h %d\n",
			__func__,
			lcd_info.vfp, lcd_info.vbp, lcd_info.vsa,
			lcd_info.hfp, lcd_info.hbp, lcd_info.hsa,
			win_rect->w, win_rect->h);

	return ret;
}
#endif

int decon_tui_protection(struct decon_device *decon, bool tui_en)
{
	int ret = 0;
	int i;
	struct decon_mode_info psr;

	if (tui_en) {
		/* Blocking LPD */
		decon_lpd_block_exit(decon);
		mutex_lock(&decon->output_lock);
		flush_kthread_worker(&decon->update_regs_worker);

		/* disable all the windows */
		for (i = 0; i < decon->pdata->max_win; i++)
			decon_write(decon->id, WIN_CONTROL(i), 0);
#ifdef CONFIG_FB_WINDOW_UPDATE
		/* Restore window_partial_update */
		if (decon->need_update) {
			decon->update_win.x = 0;
			decon->update_win.y = 0;
			decon->update_win.w = decon->lcd_info->xres;
			decon->update_win.h = decon->lcd_info->yres;
			decon_reg_ddi_partial_cmd(decon, &decon->update_win);
			decon_win_update_disp_config(decon, &decon->update_win);
			decon->need_update = false;
		}
#endif
		decon_to_psr_info(decon, &psr);
		decon_reg_start(decon->id, &psr);
		decon_reg_update_req_and_unmask(decon->id, &psr);
		decon_wait_for_vsync(decon, VSYNC_TIMEOUT_MSEC);
		/*
		 * TODO: stop the VPP
		decon->vpp_usage_bitmask = 0;
		decon_vpp_stop(decon, false);
		*/
		decon->out_type = DECON_OUT_TUI;
		mutex_unlock(&decon->output_lock);
	} else {
		mutex_lock(&decon->output_lock);
		decon->out_type = DECON_OUT_DSI;
		mutex_unlock(&decon->output_lock);
		/* UnBlocking LPD */
		decon_lpd_unblock(decon);
	}

	return ret;
}

static void decon_free_dma_buf(struct decon_device *decon,
		struct decon_dma_buf_data *dma)
{
	if (!dma->dma_addr)
		return;

	if (dma->fence)
		sync_fence_put(dma->fence);

	ion_iovmm_unmap(dma->attachment, dma->dma_addr);

	dma_buf_unmap_attachment(dma->attachment, dma->sg_table,
			DMA_TO_DEVICE);

	dma_buf_detach(dma->dma_buf, dma->attachment);
	dma_buf_put(dma->dma_buf);
	ion_free(decon->ion_client, dma->ion_handle);
	memset(dma, 0, sizeof(struct decon_dma_buf_data));
}

/* ---------- FB_BLANK INTERFACE ----------- */
int decon_enable(struct decon_device *decon)
{
	struct decon_mode_info psr;
	struct decon_param p;
	int state = decon->state;
	int ret = 0;

	decon_dbg("enable decon-%d\n", decon->id);
	exynos_ss_printk("%s:state %d: active %d:+\n", __func__,
				decon->state, pm_runtime_active(decon->dev));

	if (decon->state != DECON_STATE_LPD_EXIT_REQ)
		mutex_lock(&decon->output_lock);

	if (!decon->id && (decon->out_type == DECON_OUT_DSI) &&
				(decon->state == DECON_STATE_INIT)) {
		decon_info("decon%d init state\n", decon->id);
		decon->state = DECON_STATE_ON;
		goto err;
	}

	if (decon->state == DECON_STATE_ON) {
		decon_warn("decon%d already enabled\n", decon->id);
		goto err;
	}

#if defined(CONFIG_PM_RUNTIME)
	pm_runtime_get_sync(decon->dev);
#else
	decon_runtime_resume(decon->dev);
#endif
	call_init_ops(decon, bts_set_init, decon);

	if (decon->state == DECON_STATE_LPD_EXIT_REQ) {
		ret = v4l2_subdev_call(decon->output_sd, core, ioctl,
				DSIM_IOC_ENTER_ULPS, (unsigned long *)0);
		if (ret) {
			decon_err("%s: failed to exit ULPS state for %s\n",
					__func__, decon->output_sd->name);
			goto err;
		}
	} else {
		if (decon->pdata->psr_mode != DECON_VIDEO_MODE) {
			if (decon->pinctrl && decon->decon_te_on) {
				if (pinctrl_select_state(decon->pinctrl, decon->decon_te_on)) {
					decon_err("failed to turn on Decon_TE\n");
					goto err;
				}
			}
		}
		if (decon->out_type == DECON_OUT_DSI) {
			pm_stay_awake(decon->dev);
			dev_warn(decon->dev, "pm_stay_awake");
			ret = v4l2_subdev_call(decon->output_sd, video, s_stream, 1);
			if (ret) {
				decon_err("starting stream failed for %s\n",
						decon->output_sd->name);
				goto err;
			}
		}
	}

	decon_to_init_param(decon, &p);
	decon_reg_init(decon->id, decon->out_idx, &p);

#if defined(CONFIG_EXYNOS_DECON_MDNIE)
	if (!decon->id)
		mdnie_reg_start(decon->lcd_info->xres, decon->lcd_info->yres);
#endif

	decon_to_psr_info(decon, &psr);
	if (decon->state != DECON_STATE_LPD_EXIT_REQ) {
		/* In case of resume*/
		if (decon->out_type != DECON_OUT_WB) {
			decon_reg_start(decon->id, &psr);
			decon_reg_update_req_and_unmask(decon->id, &psr);
		}
#ifdef CONFIG_DECON_MIPI_DSI_PKTGO
		if (!decon->id) {
			ret = v4l2_subdev_call(decon->output_sd, core, ioctl, DSIM_IOC_PKT_GO_ENABLE, NULL);
			if (ret)
				decon_err("Failed to call DSIM packet go enable!\n");
		}
#endif
	}

#ifdef CONFIG_FB_WINDOW_UPDATE
	if ((decon->out_type == DECON_OUT_DSI) && (decon->need_update)) {
		if (decon->state != DECON_STATE_LPD_EXIT_REQ) {
			decon->need_update = false;
			decon->update_win.x = 0;
			decon->update_win.y = 0;
			decon->update_win.w = decon->lcd_info->xres;
			decon->update_win.h = decon->lcd_info->yres;
		} else {
			decon_win_update_disp_config(decon, &decon->update_win);
		}
	}
#endif
	if (!decon->id && !decon->eint_status) {
		enable_irq(decon->irq);
		decon->eint_status = 1;
	}

	decon->state = DECON_STATE_ON;
	decon_reg_set_int(decon->id, &psr, 1);

err:
	exynos_ss_printk("%s:state %d: active %d:-\n", __func__,
				decon->state, pm_runtime_active(decon->dev));
	if (state != DECON_STATE_LPD_EXIT_REQ)
		mutex_unlock(&decon->output_lock);
	return ret;
}

int decon_disable(struct decon_device *decon)
{
	struct decon_mode_info psr;
	int ret = 0;
	unsigned long irq_flags;
	int state = decon->state;

	exynos_ss_printk("disable decon-%d, state(%d) cnt %d\n", decon->id,
				decon->state, pm_runtime_active(decon->dev));

	if (decon->state != DECON_STATE_LPD_ENT_REQ)
		mutex_lock(&decon->output_lock);

	if (decon->state == DECON_STATE_OFF) {
		decon_info("decon%d already disabled\n", decon->id);
		goto err;
	} else if (decon->state == DECON_STATE_LPD) {
#ifdef DECON_LPD_OPT
		decon_lcd_off(decon);
		decon_info("decon is LPD state. only lcd is off\n");
#endif
		goto err;
	}

	flush_kthread_worker(&decon->update_regs_worker);

	decon_to_psr_info(decon, &psr);
	decon_reg_set_int(decon->id, &psr, 0);

	if (!decon->id && (decon->vsync_info.irq_refcount <= 0) &&
			decon->eint_status) {
		disable_irq(decon->irq);
		decon->eint_status = 0;
	}

	decon_to_psr_info(decon, &psr);
	decon_reg_stop(decon->id, decon->out_idx, &psr);
	decon_reg_clear_int_all(decon->id);

	/* DMA protection disable must be happen on vpp domain is alive */
	if (decon->out_type != DECON_OUT_WB) {
		decon_set_protected_content(decon, NULL);
		decon->vpp_usage_bitmask = 0;
		decon_vpp_stop(decon, true);
	}

#if defined(CONFIG_EXYNOS_DECON_MDNIE)
	if (!decon->id)
		mdnie_reg_stop();
#endif
	/* Synchronize the decon->state with irq_handler */
	spin_lock_irqsave(&decon->slock, irq_flags);
	if (state == DECON_STATE_LPD_ENT_REQ)
		decon->state = DECON_STATE_LPD;
	spin_unlock_irqrestore(&decon->slock, irq_flags);

	call_init_ops(decon, bts_release_init, decon);
#if defined(CONFIG_PM_RUNTIME)
	pm_runtime_put_sync(decon->dev);
#else
	decon_runtime_suspend(decon->dev);
#endif

	if (state == DECON_STATE_LPD_ENT_REQ) {
		ret = v4l2_subdev_call(decon->output_sd, core, ioctl,
				DSIM_IOC_ENTER_ULPS, (unsigned long *)1);
		if (ret) {
			decon_err("%s: failed to enter ULPS state for %s\n",
					__func__, decon->output_sd->name);
			goto err;
		}
		decon->state = DECON_STATE_LPD;
	} else {
		if (decon->out_type != DECON_OUT_WB) {
			/* stop output device (mipi-dsi or hdmi) */
			ret = v4l2_subdev_call(decon->output_sd, video, s_stream, 0);
			if (ret) {
				decon_err("stopping stream failed for %s\n",
						decon->output_sd->name);
				goto err;
			}
		}
		if (decon->out_type == DECON_OUT_DSI) {
			pm_relax(decon->dev);
			dev_warn(decon->dev, "pm_relax");
		}

		if (decon->pdata->psr_mode != DECON_VIDEO_MODE) {
			if (decon->pinctrl && decon->decon_te_off) {
				if (pinctrl_select_state(decon->pinctrl, decon->decon_te_off)) {
					decon_err("failed to turn off Decon_TE\n");
					goto err;
				}
			}
		}

		decon->state = DECON_STATE_OFF;
	}

err:
	exynos_ss_printk("%s:state %d: active%d:-\n", __func__,
				decon->state, pm_runtime_active(decon->dev));
	if (state != DECON_STATE_LPD_ENT_REQ)
		mutex_unlock(&decon->output_lock);
	return ret;
}

static int decon_blank(int blank_mode, struct fb_info *info)
{
	struct decon_win *win = info->par;
	struct decon_device *decon = win->decon;
	int ret = 0;

	decon_info("decon-%d %s mode: %dtype (0: DSI, 1: HDMI, 2:WB)\n",
			decon->id,
			blank_mode == FB_BLANK_UNBLANK ? "UNBLANK" : "POWERDOWN",
			decon->out_type);

	decon_lpd_block_exit(decon);

#ifdef CONFIG_USE_VSYNC_SKIP
	decon_extra_vsync_wait_set(ERANGE);
#endif /* CONFIG_USE_VSYNC_SKIP */

	switch (blank_mode) {
	case FB_BLANK_POWERDOWN:
	case FB_BLANK_NORMAL:
		DISP_SS_EVENT_LOG(DISP_EVT_BLANK, &decon->sd, ktime_set(0, 0));
		ret = decon_disable(decon);
		if (ret) {
			decon_err("failed to disable decon\n");
			goto blank_exit;
		}
		break;
	case FB_BLANK_UNBLANK:
		DISP_SS_EVENT_LOG(DISP_EVT_UNBLANK, &decon->sd, ktime_set(0, 0));
		ret = decon_enable(decon);
		if (ret) {
			decon_err("failed to enable decon\n");
			goto blank_exit;
		}
		break;
	case FB_BLANK_VSYNC_SUSPEND:
	case FB_BLANK_HSYNC_SUSPEND:
	default:
		ret = -EINVAL;
	}

blank_exit:
	decon_lpd_unblock(decon);
	decon_info("%s -\n", __func__);
	return ret;
}

/* ---------- FB_IOCTL INTERFACE ----------- */
static void decon_activate_vsync(struct decon_device *decon)
{
	int prev_refcount;

	mutex_lock(&decon->vsync_info.irq_lock);

	prev_refcount = decon->vsync_info.irq_refcount++;
	if (!prev_refcount)
		DISP_SS_EVENT_LOG(DISP_EVT_ACT_VSYNC, &decon->sd, ktime_set(0, 0));

	mutex_unlock(&decon->vsync_info.irq_lock);
}

static void decon_deactivate_vsync(struct decon_device *decon)
{
	int new_refcount;

	mutex_lock(&decon->vsync_info.irq_lock);

	new_refcount = --decon->vsync_info.irq_refcount;
	WARN_ON(new_refcount < 0);
	if (!new_refcount)
		DISP_SS_EVENT_LOG(DISP_EVT_DEACT_VSYNC, &decon->sd, ktime_set(0, 0));

	mutex_unlock(&decon->vsync_info.irq_lock);
}

int decon_wait_for_vsync(struct decon_device *decon, u32 timeout)
{
	ktime_t timestamp;
	int ret;

	if (decon->out_type == DECON_OUT_TUI)
		return 0;

	timestamp = decon->vsync_info.timestamp;
	decon_activate_vsync(decon);

	if (timeout) {
		ret = wait_event_interruptible_timeout(decon->vsync_info.wait,
				!ktime_equal(timestamp,
						decon->vsync_info.timestamp),
				msecs_to_jiffies(timeout));
	} else {
		ret = wait_event_interruptible(decon->vsync_info.wait,
				!ktime_equal(timestamp,
						decon->vsync_info.timestamp));
	}

	decon_deactivate_vsync(decon);

	if (timeout && ret == 0) {
		if (decon->eint_pend && decon->eint_mask) {
			decon_err("decon%d wait for vsync timeout(p:0x%x, m:0x%x)\n",
				decon->id, readl(decon->eint_pend),
				readl(decon->eint_mask));
		} else {
			decon_err("decon%d wait for vsync timeout\n", decon->id);
		}

		return -ETIMEDOUT;
	}

	return 0;
}

int decon_set_window_position(struct fb_info *info,
				struct decon_user_window user_window)
{
	return 0;
}

int decon_set_plane_alpha_blending(struct fb_info *info,
				struct s3c_fb_user_plane_alpha user_alpha)
{
	return 0;
}

int decon_set_chroma_key(struct fb_info *info,
			struct s3c_fb_user_chroma user_chroma)
{
	return 0;
}

int decon_set_vsync_int(struct fb_info *info, bool active)
{
	struct decon_win *win = info->par;
	struct decon_device *decon = win->decon;
	bool prev_active = decon->vsync_info.active;

	decon->vsync_info.active = active;
	smp_wmb();

	if (active && !prev_active)
		decon_activate_vsync(decon);
	else if (!active && prev_active)
		decon_deactivate_vsync(decon);

	return 0;
}

static unsigned int decon_map_ion_handle(struct decon_device *decon,
		struct device *dev, struct decon_dma_buf_data *dma,
		struct ion_handle *ion_handle, struct dma_buf *buf, int win_no)
{
	dma->fence = NULL;
	dma->dma_buf = buf;

	dma->attachment = dma_buf_attach(dma->dma_buf, dev);
	if (IS_ERR_OR_NULL(dma->attachment)) {
		decon_err("dma_buf_attach() failed: %ld\n",
				PTR_ERR(dma->attachment));
		goto err_buf_map_attach;
	}

	dma->sg_table = dma_buf_map_attachment(dma->attachment,
			DMA_TO_DEVICE);
	if (IS_ERR_OR_NULL(dma->sg_table)) {
		decon_err("dma_buf_map_attachment() failed: %ld\n",
				PTR_ERR(dma->sg_table));
		goto err_buf_map_attachment;
	}

	dma->dma_addr = ion_iovmm_map(dma->attachment, 0,
			dma->dma_buf->size, DMA_TO_DEVICE, 0);
	if (!dma->dma_addr || IS_ERR_VALUE(dma->dma_addr)) {
		decon_err("iovmm_map() failed: %pa\n", &dma->dma_addr);
		goto err_iovmm_map;
	}

	exynos_ion_sync_dmabuf_for_device(dev, dma->dma_buf, dma->dma_buf->size,
			DMA_TO_DEVICE);

	dma->ion_handle = ion_handle;

	return dma->dma_buf->size;

err_iovmm_map:
	dma_buf_unmap_attachment(dma->attachment, dma->sg_table,
			DMA_TO_DEVICE);
err_buf_map_attachment:
	dma_buf_detach(dma->dma_buf, dma->attachment);
err_buf_map_attach:
	return 0;
}



static int decon_get_plane_cnt(enum decon_pixel_format format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
	case DECON_PIXEL_FORMAT_RGBA_5551:
	case DECON_PIXEL_FORMAT_RGB_565:
		return 1;

	case DECON_PIXEL_FORMAT_NV16:
	case DECON_PIXEL_FORMAT_NV61:
	case DECON_PIXEL_FORMAT_NV12:
	case DECON_PIXEL_FORMAT_NV21:
	case DECON_PIXEL_FORMAT_NV12M:
	case DECON_PIXEL_FORMAT_NV21M:
		return 2;

	case DECON_PIXEL_FORMAT_YVU422_3P:
	case DECON_PIXEL_FORMAT_YUV420:
	case DECON_PIXEL_FORMAT_YVU420:
	case DECON_PIXEL_FORMAT_YUV420M:
	case DECON_PIXEL_FORMAT_YVU420M:
		return 3;

	default:
		decon_err("invalid format(%d)\n", format);
		return 1;
	}

}

static u32 get_vpp_src_format(u32 format, int id)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_NV12:
		return DECON_PIXEL_FORMAT_NV21;
	case DECON_PIXEL_FORMAT_NV21:
		return DECON_PIXEL_FORMAT_NV12;
	case DECON_PIXEL_FORMAT_NV12M:
		return DECON_PIXEL_FORMAT_NV21M;
	case DECON_PIXEL_FORMAT_NV21M:
		return DECON_PIXEL_FORMAT_NV12M;
	case DECON_PIXEL_FORMAT_YUV420:
		return DECON_PIXEL_FORMAT_YVU420;
	case DECON_PIXEL_FORMAT_YVU420:
		return DECON_PIXEL_FORMAT_YUV420;
	case DECON_PIXEL_FORMAT_YUV420M:
		return DECON_PIXEL_FORMAT_YVU420M;
	case DECON_PIXEL_FORMAT_YVU420M:
		return DECON_PIXEL_FORMAT_YUV420M;
	case DECON_PIXEL_FORMAT_ARGB_8888:
		return DECON_PIXEL_FORMAT_BGRA_8888;
	case DECON_PIXEL_FORMAT_ABGR_8888:
		return DECON_PIXEL_FORMAT_RGBA_8888;
	case DECON_PIXEL_FORMAT_RGBA_8888:
		return DECON_PIXEL_FORMAT_ABGR_8888;
	case DECON_PIXEL_FORMAT_BGRA_8888:
		return DECON_PIXEL_FORMAT_ARGB_8888;
	case DECON_PIXEL_FORMAT_XRGB_8888:
		return DECON_PIXEL_FORMAT_BGRX_8888;
	case DECON_PIXEL_FORMAT_XBGR_8888:
		return DECON_PIXEL_FORMAT_RGBX_8888;
	case DECON_PIXEL_FORMAT_RGBX_8888:
		return DECON_PIXEL_FORMAT_XBGR_8888;
	case DECON_PIXEL_FORMAT_BGRX_8888:
		return DECON_PIXEL_FORMAT_XRGB_8888;
	default:
		return format;
	}
}

static u32 get_vpp_out_format(u32 format)
{
	switch (format) {
	case DECON_PIXEL_FORMAT_NV12:
	case DECON_PIXEL_FORMAT_NV21:
	case DECON_PIXEL_FORMAT_NV12M:
	case DECON_PIXEL_FORMAT_NV21M:
	case DECON_PIXEL_FORMAT_YUV420:
	case DECON_PIXEL_FORMAT_YVU420:
	case DECON_PIXEL_FORMAT_YUV420M:
	case DECON_PIXEL_FORMAT_YVU420M:
	case DECON_PIXEL_FORMAT_RGB_565:
	case DECON_PIXEL_FORMAT_BGRA_8888:
	case DECON_PIXEL_FORMAT_RGBA_8888:
	case DECON_PIXEL_FORMAT_ABGR_8888:
	case DECON_PIXEL_FORMAT_ARGB_8888:
	case DECON_PIXEL_FORMAT_BGRX_8888:
	case DECON_PIXEL_FORMAT_RGBX_8888:
	case DECON_PIXEL_FORMAT_XBGR_8888:
	case DECON_PIXEL_FORMAT_XRGB_8888:
		return DECON_PIXEL_FORMAT_BGRA_8888;
	default:
		return format;
	}
}

static bool decon_get_protected_idma(struct decon_device *decon, u32 prot_bits)
{
	int i;
	u32 used_idma = 0;

	for (i = 0; i < MAX_DMA_TYPE - 1; i++)
		if ((prot_bits & (1 << i)) >> i)
			used_idma++;

	if (used_idma)
		return true;
	else
		return false;
}

static void decon_set_protected_content(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	bool prot;
	int type, i, ret = 0;
	u32 change = 0;
	u32 cur_protect_bits = 0;

	/**
	 * get requested DMA protection configs
	 * 0:G0 1:G1 2:VG0 3:VG1 4:VGR0 5:VGR1 6:G2 7:G3 8:WB1
	 */
	/* IDMA protection configs (G0,G1,VG0,VG1,VGR0,VGR1,G2,G3) */
	for (i = 0; i < decon->pdata->max_win; i++) {
		if (!regs)
			break;

		cur_protect_bits |=
			(regs->protection[i] << regs->vpp_config[i].idma_type);
	}

	/* ODMA(for writeback) protection config (WB1)*/
	if (decon->out_type == DECON_OUT_WB)
		if (decon_get_protected_idma(decon, cur_protect_bits))
			cur_protect_bits |= (1 << ODMA_WB);

	if (decon->prev_protection_bitmask != cur_protect_bits) {
		decon_reg_wait_linecnt_is_zero_timeout(decon->id, 0, 35 * 1000);

		/* apply protection configs for each DMA */
		for (type = 0; type < MAX_DMA_TYPE; type++) {
			prot = cur_protect_bits & (1 << type);

			change = (cur_protect_bits & (1 << type)) ^
				(decon->prev_protection_bitmask & (1 << type));

			if (change) {
					struct v4l2_subdev *sd = NULL;
					sd = decon->mdev->vpp_sd[type];
					v4l2_subdev_call(sd, core, ioctl,
						VPP_WAIT_IDLE, NULL);
					TRACE_VPP_LOG(decon, prot);

				ret = exynos_smc(SMC_PROTECTION_SET, 0,
						type + DECON_TZPC_OFFSET, prot);
				if (ret != SUCCESS_EXYNOS_SMC) {
					WARN(1, "decon%d DMA-%d smc call fail\n",
							decon->id, type);
				} else {
					TRACE_VPP_LOG(decon, prot);
					decon_info("decon%d DMA-%d protection %s\n",
							decon->id, type, prot ? "enabled" : "disabled");
				}
			}
		}
	}

	/* save current portection configs */
	decon->prev_protection_bitmask = cur_protect_bits;
}

static int decon_set_win_buffer(struct decon_device *decon, struct decon_win *win,
		struct decon_win_config *win_config, struct decon_reg_data *regs)
{
	struct ion_handle *handle;
	struct fb_var_screeninfo prev_var = win->fbinfo->var;
	struct dma_buf *buf[MAX_BUF_PLANE_CNT];
	struct decon_dma_buf_data dma_buf_data[MAX_BUF_PLANE_CNT];
	unsigned short win_no = win->index;
	int ret, i;
	size_t buf_size = 0;
	int plane_cnt;
	u32 format;
	int vpp_id;
	struct device *dev;

	if (win_config->format >= DECON_PIXEL_FORMAT_MAX) {
		decon_err("unknown pixel format %u\n", win_config->format);
		return -EINVAL;
	}

	if (win_config->blending >= DECON_BLENDING_MAX) {
		decon_err("unknown blending %u\n", win_config->blending);
		return -EINVAL;
	}

	if (win_no == 0 && win_config->blending != DECON_BLENDING_NONE) {
		decon_err("blending not allowed on window 0\n");
		return -EINVAL;
	}

	if (win_config->dst.w == 0 || win_config->dst.h == 0 ||
			win_config->dst.x < 0 || win_config->dst.y < 0) {
		decon_err("win[%d] size is abnormal (w:%d, h:%d, x:%d, y:%d)\n",
				win_no, win_config->dst.w, win_config->dst.h,
				win_config->dst.x, win_config->dst.y);
		return -EINVAL;
	}

	format = get_vpp_out_format(win_config->format);

	win->fbinfo->var.red.length = decon_red_length(format);
	win->fbinfo->var.red.offset = decon_red_offset(format);
	win->fbinfo->var.green.length = decon_green_length(format);
	win->fbinfo->var.green.offset = decon_green_offset(format);
	win->fbinfo->var.blue.length = decon_blue_length(format);
	win->fbinfo->var.blue.offset = decon_blue_offset(format);
	win->fbinfo->var.transp.length =
			decon_transp_length(win_config->format);
	win->fbinfo->var.transp.offset =
			decon_transp_offset(win_config->format);
	win->fbinfo->var.bits_per_pixel = win->fbinfo->var.red.length +
			win->fbinfo->var.green.length +
			win->fbinfo->var.blue.length +
			win->fbinfo->var.transp.length +
			decon_padding(format);

	if (win_config->dst.w * win->fbinfo->var.bits_per_pixel / 8 < 128) {
		decon_err("window wide < 128bytes, width = %u, bpp = %u)\n",
				win_config->dst.w,
				win->fbinfo->var.bits_per_pixel);
		ret = -EINVAL;
		goto err_invalid;
	}

	if (!decon_validate_x_alignment(decon, win_config->dst.x,
				win_config->dst.w,
				win->fbinfo->var.bits_per_pixel)) {
		ret = -EINVAL;
		goto err_invalid;
	}

	plane_cnt = decon_get_plane_cnt(win_config->format);
	for (i = 0; i < plane_cnt; ++i) {
		handle = ion_import_dma_buf(decon->ion_client, win_config->fd_idma[i]);
		if (IS_ERR(handle)) {
			decon_err("failed to import fd\n");
			ret = PTR_ERR(handle);
			goto err_invalid;
		}

		buf[i] = dma_buf_get(win_config->fd_idma[i]);
		if (IS_ERR_OR_NULL(buf[i])) {
			decon_err("dma_buf_get() failed: %ld\n", PTR_ERR(buf[i]));
			ret = PTR_ERR(buf[i]);
			goto err_buf_get;
		}

		vpp_id = win_config->idma_type;
		dev = decon->mdev->vpp_dev[vpp_id];
		buf_size = decon_map_ion_handle(decon, dev, &dma_buf_data[i],
				handle, buf[i], win_no);
		if (!buf_size) {
			ret = -ENOMEM;
			goto err_map;
		}
		win_config->vpp_parm.addr[i] = dma_buf_data[i].dma_addr;
		handle = NULL;
		buf[i] = NULL;
	}
	if (win_config->fence_fd >= 0) {
		dma_buf_data[0].fence = sync_fence_fdget(win_config->fence_fd);
		if (!dma_buf_data[0].fence) {
			decon_err("failed to import fence fd\n");
			ret = -EINVAL;
			goto err_offset;
		}
		decon_dbg("%s(%d): fence_fd(%d), fence(%lx)\n", __func__, __LINE__,
				win_config->fence_fd, (ulong)dma_buf_data[0].fence);
	}

	win->fbinfo->fix.smem_start = dma_buf_data[0].dma_addr;
	win->fbinfo->fix.smem_len = buf_size;
	win->fbinfo->var.xres = win_config->dst.w;
	win->fbinfo->var.xres_virtual = win_config->dst.f_w;
	win->fbinfo->var.yres = win_config->dst.h;
	win->fbinfo->var.yres_virtual = win_config->dst.f_h;
	win->fbinfo->var.xoffset = win_config->src.x;
	win->fbinfo->var.yoffset = win_config->src.y;

	win->fbinfo->fix.line_length = win_config->src.f_w *
			win->fbinfo->var.bits_per_pixel / 8;
	win->fbinfo->fix.xpanstep = fb_panstep(win_config->dst.w,
			win->fbinfo->var.xres_virtual);
	win->fbinfo->fix.ypanstep = fb_panstep(win_config->dst.h,
			win->fbinfo->var.yres_virtual);

	plane_cnt = decon_get_plane_cnt(win_config->format);
	for (i = 0; i < plane_cnt; ++i)
		regs->dma_buf_data[win_no][i] = dma_buf_data[i];
	regs->protection[win_no] = win_config->protection;

	decon_win_conig_to_regs_param(win->fbinfo->var.transp.length, win_config,
				&regs->win_regs[win_no], win_config->idma_type);

	return 0;

err_offset:
	for (i = 0; i < plane_cnt; ++i)
		decon_free_dma_buf(decon, &dma_buf_data[i]);
err_map:
	for (i = 0; i < plane_cnt; ++i)
		dma_buf_put(buf[i]);
err_buf_get:
	if (handle)
		ion_free(decon->ion_client, handle);
err_invalid:
	win->fbinfo->var = prev_var;
	return ret;
}

static int decon_set_wb_buffer(struct decon_device *decon,
		struct decon_win_config *win_config, struct decon_reg_data *regs)
{
	struct ion_handle *handle;
	struct dma_buf *buf;
	struct decon_dma_buf_data dma_buf_data[MAX_BUF_PLANE_CNT];
	int ret = 0, i;
	size_t buf_size = 0;
	int plane_cnt;
	struct device *dev;
	struct decon_win_config *config = &win_config[MAX_DECON_WIN];

	DISP_SS_EVENT_LOG(DISP_EVT_WB_SET_BUFFER, &decon->sd, ktime_set(0, 0));

	plane_cnt = decon_get_plane_cnt(config->format);
	for (i = 0; i < plane_cnt; ++i) {
		handle = ion_import_dma_buf(decon->ion_client, config->fd_idma[i]);
		if (IS_ERR(handle)) {
			decon_err("failed to import fd_odma:%d\n", config->fd_idma[i]);
			ret = PTR_ERR(handle);
			goto fail;
		}

		buf = dma_buf_get(config->fd_idma[i]);
		if (IS_ERR_OR_NULL(buf)) {
			decon_err("dma_buf_get() failed: %ld\n", PTR_ERR(buf));
			ret = PTR_ERR(buf);
			goto fail_buf;
		}

		/* idma_type Should be ODMA_WB */
		dev = decon->mdev->vpp_dev[config->idma_type];
		buf_size = decon_map_ion_handle(decon, dev, &dma_buf_data[i],
				handle, buf, 0);
		if (!buf_size) {
			decon_err("failed to mapping buffer\n");
			ret = -ENOMEM;
			goto fail_map;
		}
		regs->dma_buf_data[MAX_DECON_WIN][i] = dma_buf_data[i];
		config->vpp_parm.addr[i] = dma_buf_data[i].dma_addr;
	}

	handle = NULL;
	buf = NULL;

	return ret;

fail_map:
	if (buf)
		dma_buf_put(buf);

fail_buf:
	if (handle)
		ion_free(decon->ion_client, handle);

fail:
	decon_err("failed save write back buffer configuration\n");
	return ret;
}

#ifdef CONFIG_FB_WINDOW_UPDATE
static inline void decon_update_2_full(struct decon_device *decon,
			struct decon_reg_data *regs,
			struct decon_lcd *lcd_info,
			int flag)
{
	if (flag)
		regs->need_update = true;

	decon->need_update = false;
	decon->update_win.x = 0;
	decon->update_win.y = 0;
	decon->update_win.w = lcd_info->xres;
	decon->update_win.h = lcd_info->yres;
	regs->update_win.w = lcd_info->xres;
	regs->update_win.h = lcd_info->yres;
	decon_win_update_dbg("[WIN_UPDATE]update2org: [%d %d %d %d]\n",
			decon->update_win.x, decon->update_win.y, decon->update_win.w, decon->update_win.h);
	return;

}

static void decon_calibrate_win_update_size(struct decon_device *decon,
		struct decon_win_config *win_config,
		struct decon_win_config *update_config)
{
	int i;
	struct decon_rect r1, r2;
	bool rect_changed = false;

	if (update_config->state != DECON_WIN_STATE_UPDATE)
		return;

	r1.left = update_config->dst.x;
	r1.top = update_config->dst.y;
	r1.right = r1.left + update_config->dst.w - 1;
	r1.bottom = r1.top + update_config->dst.h - 1;
	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win_config *config = &win_config[i];
		if (config->state != DECON_WIN_STATE_DISABLED) {
			if ((is_rotation(config) || does_layer_need_scale(config))) {
				update_config->state = DECON_WIN_STATE_DISABLED;
				return;
			}
			if ((config->src.w != config->dst.w) ||
					(config->src.h != config->dst.h)) {
				r2.left = config->dst.x;
				r2.top = config->dst.y;
				r2.right = r2.left + config->dst.w - 1;
				r2.bottom = r2.top + config->dst.h - 1;
				if (decon_intersect(&r1, &r2) &&
					is_decon_rect_differ(&r1, &r2)) {
					decon_union(&r1, &r2, &r1);
					rect_changed = true;
				}
			}
		}
	}

	if (rect_changed) {
		decon_win_update_dbg("update [%d %d %d %d] -> [%d %d %d %d]\n",
			update_config->dst.x, update_config->dst.y,
			update_config->dst.w, update_config->dst.h,
			r1.left, r1.top, r1.right - r1.left + 1,
			r1.bottom - r1.top + 1);
		update_config->dst.x = r1.left;
		update_config->dst.y = r1.top;
		update_config->dst.w = r1.right - r1.left + 1;
		update_config->dst.h = r1.bottom - r1.top + 1;
	}

	if (update_config->dst.x & 0x7) {
		update_config->dst.w += update_config->dst.x & 0x7;
		update_config->dst.x = update_config->dst.x & (~0x7);
	}
	update_config->dst.w = ((update_config->dst.w + 7) & (~0x7));
	if (update_config->dst.x + update_config->dst.w > decon->lcd_info->xres) {
		update_config->dst.w = decon->lcd_info->xres;
		update_config->dst.x = 0;
	}

	return;
}

static void decon_set_win_update_config(struct decon_device *decon,
		struct decon_win_config *win_config,
		struct decon_reg_data *regs)
{
	int i;
	struct decon_win_config *update_config = &win_config[DECON_WIN_UPDATE_IDX];
	struct decon_win_config temp_config;
	struct decon_rect r1, r2;
	struct decon_lcd *lcd_info = decon->lcd_info;
	int need_update = decon->need_update;
	bool is_scale_layer;

	decon_calibrate_win_update_size(decon, win_config, update_config);

	/* if the current mode is not WINDOW_UPDATE, set the config as WINDOW_UPDATE */
	if ((update_config->state == DECON_WIN_STATE_UPDATE) &&
			((update_config->dst.x != decon->update_win.x) ||
			 (update_config->dst.y != decon->update_win.y) ||
			 (update_config->dst.w != decon->update_win.w) ||
			 (update_config->dst.h != decon->update_win.h))) {
		decon->update_win.x = update_config->dst.x;
		decon->update_win.y = update_config->dst.y;
		decon->update_win.w = update_config->dst.w;
		decon->update_win.h = update_config->dst.h;
		decon->need_update = true;
		regs->need_update = true;
		regs->update_win.x = update_config->dst.x;
		regs->update_win.y = update_config->dst.y;
		regs->update_win.w = update_config->dst.w;
		regs->update_win.h = update_config->dst.h;

		decon_win_update_dbg("[WIN_UPDATE]need_update_1: [%d %d %d %d]\n",
				update_config->dst.x, update_config->dst.y, update_config->dst.w, update_config->dst.h);
	} else if (decon->need_update &&
			(update_config->state != DECON_WIN_STATE_UPDATE)) {
		/* Platform requested for normal mode, switch to normal mode from WINDOW_UPDATE */
		decon_update_2_full(decon, regs, lcd_info, true);
		return;
	} else if (decon->need_update) {
		/* It is just for debugging info */
		regs->update_win.x = update_config->dst.x;
		regs->update_win.y = update_config->dst.y;
		regs->update_win.w = update_config->dst.w;
		regs->update_win.h = update_config->dst.h;
	}

	if (update_config->state != DECON_WIN_STATE_UPDATE)
		return;

	r1.left = update_config->dst.x;
	r1.top = update_config->dst.y;
	r1.right = r1.left + update_config->dst.w - 1;
	r1.bottom = r1.top + update_config->dst.h - 1;

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win_config *config = &win_config[i];
		if (config->state == DECON_WIN_STATE_DISABLED)
			continue;
		r2.left = config->dst.x;
		r2.top = config->dst.y;
		r2.right = r2.left + config->dst.w - 1;
		r2.bottom = r2.top + config->dst.h - 1;
		if (!decon_intersect(&r1, &r2))
			continue;
		decon_intersection(&r1, &r2, &r2);
		if (((r2.right - r2.left) != 0) ||
			((r2.bottom - r2.top) != 0)) {
			if (decon_get_plane_cnt(config->format) == 1) {
				/*
				 * Platform requested for win_update mode. But, the win_update is
				 * smaller than the VPP min size. So, change the mode to normal mode
				 */
				if (((r2.right - r2.left) < 32) ||
					((r2.bottom - r2.top) < 16)) {
					decon_update_2_full(decon, regs, lcd_info, need_update);
					return;
				}
			} else {
				if (((r2.right - r2.left) < 64) ||
					((r2.bottom - r2.top) < 32)) {
					decon_update_2_full(decon, regs, lcd_info, need_update);
					return;
				}
			}
		}
	}

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win_config *config = &win_config[i];
		if (config->state == DECON_WIN_STATE_DISABLED)
			continue;
		r2.left = config->dst.x;
		r2.top = config->dst.y;
		r2.right = r2.left + config->dst.w - 1;
		r2.bottom = r2.top + config->dst.h - 1;
		if (!decon_intersect(&r1, &r2)) {
			config->state = DECON_WIN_STATE_DISABLED;
			continue;
		}
		memcpy(&temp_config, config, sizeof(struct decon_win_config));
		is_scale_layer = does_layer_need_scale(config);
		if (update_config->dst.x > config->dst.x)
			config->dst.w = min(update_config->dst.w,
					config->dst.x + config->dst.w - update_config->dst.x);
		else if (update_config->dst.x + update_config->dst.w < config->dst.x + config->dst.w)
			config->dst.w = min(config->dst.w,
					update_config->dst.w + update_config->dst.x - config->dst.x);

		if (update_config->dst.y > config->dst.y)
			config->dst.h = min(update_config->dst.h,
					config->dst.y + config->dst.h - update_config->dst.y);
		else if (update_config->dst.y + update_config->dst.h < config->dst.y + config->dst.h)
			config->dst.h = min(config->dst.h,
					update_config->dst.h + update_config->dst.y - config->dst.y);

		config->dst.x = max(config->dst.x - update_config->dst.x, 0);
		config->dst.y = max(config->dst.y - update_config->dst.y, 0);

		if (!is_scale_layer) {
			if (update_config->dst.y > temp_config.dst.y)
				config->src.y += (update_config->dst.y - temp_config.dst.y);

			if (update_config->dst.x > temp_config.dst.x)
				config->src.x += (update_config->dst.x - temp_config.dst.x);
			config->src.w = config->dst.w;
			config->src.h = config->dst.h;
		}

		if (regs->need_update == true)
			decon_win_update_dbg("[WIN_UPDATE]win_idx %d: idma_type%d:,	\
				dst[%d %d %d %d] -> [%d %d %d %d], src[%d %d %d %d] -> [%d %d %d %d]\n",
				i, temp_config.idma_type,
				temp_config.dst.x, temp_config.dst.y, temp_config.dst.w, temp_config.dst.h,
				config->dst.x, config->dst.y, config->dst.w, config->dst.h,
				temp_config.src.x, temp_config.src.y, temp_config.src.w, temp_config.src.h,
				config->src.x, config->src.y, config->src.w, config->src.h);
	}

	return;
}
#endif

void decon_reg_chmap_validate(struct decon_device *decon, struct decon_reg_data *regs)
{
	unsigned short i, bitmap = 0;

	for (i = 0; i < decon->pdata->max_win; i++) {
		if ((regs->win_regs[i].wincon & WIN_CONTROL_EN_F) &&
			(!regs->win_regs[i].winmap_state)) {
			if (bitmap & (1 << regs->vpp_config[i].idma_type)) {
				decon_warn("Channel-%d is mapped to multiple windows\n",
					regs->vpp_config[i].idma_type);
				regs->win_regs[i].wincon &= (~WIN_CONTROL_EN_F);
			}
			bitmap |= 1 << regs->vpp_config[i].idma_type;
		}
	}
}

#ifdef CONFIG_FB_WINDOW_UPDATE
static int decon_reg_set_win_update_config(struct decon_device *decon, struct decon_reg_data *regs)
{
	int ret = 0;

	if (regs->need_update) {
		decon_reg_ddi_partial_cmd(decon, &regs->update_win);
		ret = decon_win_update_disp_config(decon, &regs->update_win);
	}
	return ret;
}
#endif

static void decon_check_vpp_used(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	int i = 0;
	decon->vpp_usage_bitmask = 0;

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win *win = decon->windows[i];
		if (!regs->win_regs[i].winmap_state)
			win->vpp_id = regs->vpp_config[i].idma_type;
		else
			win->vpp_id = 0xF;
		if ((regs->win_regs[i].wincon & WIN_CONTROL_EN_F) &&
			(!regs->win_regs[i].winmap_state)) {
			decon->vpp_usage_bitmask |= (1 << win->vpp_id);
			decon->vpp_used[win->vpp_id] = true;
		}
	}
}

void decon_vpp_wait_for_update(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	int i = 0;
	struct v4l2_subdev *sd = NULL;

	for (i = 0; i < MAX_VPP_SUBDEV; i++) {
		if (decon->vpp_used[i] && (!(decon->vpp_usage_bitmask & (1 << i)))) {
			sd = decon->mdev->vpp_sd[i];
			v4l2_subdev_call(sd, core, ioctl,
					VPP_WAIT_FOR_UPDATE, NULL);
		}
	}
}

void decon_vpp_wait_wb_framedone(struct decon_device *decon)
{
	struct v4l2_subdev *sd = NULL;

	sd = decon->mdev->vpp_sd[ODMA_WB];
	v4l2_subdev_call(sd, core, ioctl,
			VPP_WAIT_FOR_FRAMEDONE, NULL);
}

static void decon_get_vpp_min_lock(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	int i = 0;
	struct v4l2_subdev *sd = NULL;

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win *win = decon->windows[i];
		if (decon->vpp_usage_bitmask & (1 << win->vpp_id)) {
			sd = decon->mdev->vpp_sd[win->vpp_id];
			v4l2_subdev_call(sd, core, ioctl,
					VPP_GET_BTS_VAL, &regs->vpp_config[i]);
		}
	}
}

static void decon_set_vpp_min_lock_early(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	int i = 0;
	struct v4l2_subdev *sd = NULL;

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win *win = decon->windows[i];
		if (decon->vpp_usage_bitmask & (1 << win->vpp_id)) {
			struct vpp_dev *vpp;
			sd = decon->mdev->vpp_sd[win->vpp_id];
			vpp = v4l2_get_subdevdata(sd);
			if (vpp->cur_bw > vpp->prev_bw) {
				v4l2_subdev_call(sd, core, ioctl,
						VPP_SET_BW,
						&regs->vpp_config[i]);
			}

			v4l2_subdev_call(sd, core, ioctl,
					VPP_SET_ROT_MIF,
					&regs->vpp_config[i]);

			if (decon->disp_cur > decon->disp_prev) {
				pm_qos_update_request(&decon->disp_qos, decon->disp_cur);
				pm_qos_update_request(&decon->int_qos, decon->disp_cur);
			}
		}
	}
}

static void decon_set_vpp_min_lock_lately(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	int i = 0;
	struct v4l2_subdev *sd = NULL;
	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win *win = decon->windows[i];
		if (decon->vpp_usage_bitmask & (1 << win->vpp_id)) {
			struct vpp_dev *vpp;
			sd = decon->mdev->vpp_sd[win->vpp_id];
			vpp = v4l2_get_subdevdata(sd);
			if (vpp->cur_bw < vpp->prev_bw) {
				v4l2_subdev_call(sd, core, ioctl,
						VPP_SET_BW,
						&regs->vpp_config[i]);
			}
			vpp->prev_bw = vpp->cur_bw;

			v4l2_subdev_call(sd, core, ioctl,
					VPP_SET_ROT_MIF,
					&regs->vpp_config[i]);

			if (decon->disp_cur < decon->disp_prev) {
				pm_qos_update_request(&decon->disp_qos, decon->disp_cur);
				pm_qos_update_request(&decon->int_qos, decon->disp_cur);
			}
			decon->disp_prev = decon->disp_cur;

		}
	}
}

void decon_set_vpp_disp_min_lock(struct decon_device *decon,
		struct decon_reg_data *regs)
{
	int i = 0;
	u64 disp_bw[4] = {0, 0, 0, 0};
	u64 disp_max_bw = 0;
	struct v4l2_subdev *sd = NULL;

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win *win = decon->windows[i];
		if (decon->vpp_usage_bitmask & (1 << win->vpp_id)) {
			struct vpp_dev *vpp;
			sd = decon->mdev->vpp_sd[win->vpp_id];
			vpp = v4l2_get_subdevdata(sd);

			/*
			 *  VPP0(G0), VPP1(G1), VPP2(VG0), VPP3(VG1),
			 *  VPP4(G2), VPP5(G3), VPP6(VGR0), VPP7(VGR1), VPP8(WB)
			 *  vpp_bus_bw[0] = DISP0_0_BW = G0 + VG0;
			 *  vpp_bus_bw[1] = DISP0_1_BW = G1 + VG1;
			 *  vpp_bus_bw[2] = DISP1_0_BW = G2 + VGR0;
			 *  vpp_bus_bw[3] = DISP1_1_BW = G3 + VGR1 + WB;
			 */
			if((vpp->id == 0) || (vpp->id == 2))
				disp_bw[0] = disp_bw[0] + vpp->disp_cur_bw;
			if((vpp->id == 1) || (vpp->id == 3))
				disp_bw[1] = disp_bw[1] + vpp->disp_cur_bw;
			if((vpp->id == 4) || (vpp->id == 6))
				disp_bw[2] = disp_bw[2] + vpp->disp_cur_bw;
			if((vpp->id == 5) || (vpp->id == 7) || (vpp->id == 8))
				disp_bw[3] = disp_bw[3] + vpp->disp_cur_bw;
		}
	}

	disp_max_bw = disp_bw[0];
	for (i = 0; i < 4; i++) {
		if (disp_max_bw < disp_bw[i])
			disp_max_bw = disp_bw[i];
	}
	decon->disp_cur = disp_max_bw;
}

static void __decon_update_regs(struct decon_device *decon, struct decon_reg_data *regs)
{
	unsigned short i, j;
	struct decon_mode_info psr;
	struct v4l2_subdev *sd = NULL;
	int plane_cnt;
	int vpp_ret = 0;
	int win_bitmap = 0;

	decon_to_psr_info(decon, &psr);
	decon_reg_wait_for_update_timeout(decon->id, SHADOW_UPDATE_TIMEOUT);
	if (psr.trig_mode == DECON_HW_TRIG)
		decon_reg_set_trigger(decon->id, &psr, DECON_TRIG_DISABLE);

	/* TODO: check and wait until the required IDMA is free */
	decon_reg_chmap_validate(decon, regs);

#ifdef CONFIG_FB_WINDOW_UPDATE
	/* if any error in config, skip the trigger UNAMSK. keep others as it is*/
	if (decon->out_type == DECON_OUT_DSI)
		decon_reg_set_win_update_config(decon, regs);
#endif

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win *win = decon->windows[i];

		if (regs->win_regs[i].wincon & WIN_CONTROL_EN_F)
			win_bitmap |= 1 << i;

		/* set decon registers for each window */
		decon_reg_set_window_control(decon->id, i, &regs->win_regs[i],
							regs->win_regs[i].winmap_state);

		/* set plane data */
		plane_cnt = decon_get_plane_cnt(regs->vpp_config[i].format);
		for (j = 0; j < plane_cnt; ++j)
			decon->windows[i]->dma_buf_data[j] = regs->dma_buf_data[i][j];

		decon->windows[i]->plane_cnt = plane_cnt;
		if (decon->vpp_usage_bitmask & (1 << win->vpp_id)) {
			sd = decon->mdev->vpp_sd[win->vpp_id];
			vpp_ret = v4l2_subdev_call(sd, core, ioctl,
					VPP_WIN_CONFIG, &regs->vpp_config[i]);
			if (vpp_ret) {
				decon_err("Failed to config VPP-%d\n", win->vpp_id);
				regs->win_regs[i].wincon &= (~WIN_CONTROL_EN_F);
				decon_write(decon->id, WIN_CONTROL(i), regs->win_regs[i].wincon);
				decon->vpp_usage_bitmask &= ~(1 << win->vpp_id);
				decon->vpp_err_stat[win->vpp_id] = true;
			}
		}
	}

	if (decon->out_type == DECON_OUT_WB) {
		decon->vpp_usage_bitmask |= (1 << ODMA_WB);
		decon->vpp_used[ODMA_WB] = true;
		sd = decon->mdev->vpp_sd[ODMA_WB];
		if (v4l2_subdev_call(sd, core, ioctl, VPP_WIN_CONFIG,
				&regs->vpp_config[MAX_DECON_WIN])) {
			decon_err("Failed to config VPP-%d\n", ODMA_WB);
			decon->vpp_usage_bitmask &= ~(1 << ODMA_WB);
			decon->vpp_err_stat[ODMA_WB] = true;
		} else
			DISP_SS_EVENT_LOG(DISP_EVT_WB_SW_TRIGGER, &decon->sd, ktime_set(0, 0));
	}

	/* DMA protection(SFW) enable must be happen on vpp domain is alive */
	decon_set_protected_content(decon, regs);

#if defined(CONFIG_EXYNOS_DECON_MDNIE)
	mdnie_reg_update_frame(decon->lcd_info->xres, decon->lcd_info->yres);
#endif

	decon_reg_all_win_shadow_update_req(decon->id);
	decon_to_psr_info(decon, &psr);
	if (decon_reg_start(decon->id, &psr) < 0)
		BUG();
	DISP_SS_EVENT_LOG(DISP_EVT_TRIG_UNMASK, &decon->sd, ktime_set(0, 0));
#ifdef CONFIG_DECON_MIPI_DSI_PKTGO
	if (!decon->id) {
		ret = v4l2_subdev_call(decon->output_sd, core, ioctl, DSIM_IOC_PKT_GO_ENABLE, NULL);
		if (ret)
			decon_err("Failed to call DSIM packet go enable in %s!\n", __func__);
	}
#endif
}

static void decon_fence_wait(struct sync_fence *fence)
{
	int err = sync_fence_wait(fence, 900);
	if (err >= 0)
		return;

	if (err < 0)
		decon_warn("error waiting on acquire fence: %d\n", err);
}

int decon_wait_until_size_match(struct decon_device *decon,
		int dsi_idx, unsigned long timeout)
{
	unsigned long delay_time = 100;
	unsigned long cnt = timeout / delay_time;
	u32 decon_yres, dsim_yres;
	u32 decon_xres, dsim_xres;
	u32 need_save = true;
	struct disp_ss_size_info info;

	if ((decon->pdata->psr_mode == DECON_VIDEO_MODE) ||
		(decon->pdata->out_type != DECON_OUT_DSI))
		return 0;

	while (--cnt) {
		/* Check a DECON and DSIM size mismatch */
		decon_yres = decon_reg_get_height(decon->id, decon->pdata->dsi_mode);
		dsim_yres = dsim_reg_get_yres(dsi_idx);

		decon_xres = decon_reg_get_width(decon->id, decon->pdata->dsi_mode);
		dsim_xres = dsim_reg_get_xres(dsi_idx);

		if (decon_yres == dsim_yres && decon_xres == dsim_xres)
			goto wait_done;

		if (need_save) {
			/* TODO: Save a err data */
			info.w_in = decon_xres;
			info.h_in = decon_yres;
			info.w_out = dsim_xres;
			info.h_out = dsim_yres;
			DISP_SS_EVENT_SIZE_ERR_LOG(&decon->sd, &info);
			need_save = false;
		}

		udelay(delay_time);
	}

	if (!cnt) {
		decon_err("size mis-match, HW_SW_TRIG_CONTROL:0x%x decon_xres:%d,	\
				dsim_xres:%d, decon_yres:%d, dsim_yres:%d\n",
				decon_read(decon->id, HW_SW_TRIG_CONTROL),
				decon_xres, dsim_xres, decon_yres, dsim_yres);
	}
wait_done:
	return 0;
}

void decon_wait_for_vstatus(struct decon_device *decon, u32 timeout)
{
	int ret;

	if (decon->id)
		return;

	ret = wait_event_timeout(decon->wait_vstatus,
			(decon->frame_start_cnt_target <= decon->frame_start_cnt_cur),
			msecs_to_jiffies(timeout));
	if (!ret)
		decon_warn("%s:timeout\n", __func__);
}

static void decon_update_regs(struct decon_device *decon, struct decon_reg_data *regs)
{
	struct decon_dma_buf_data old_dma_bufs[decon->pdata->max_win][MAX_BUF_PLANE_CNT];
	int old_plane_cnt[MAX_DECON_WIN];
	struct decon_mode_info psr;
	int i, j;
#ifdef CONFIG_USE_VSYNC_SKIP
	int vsync_wait_cnt = 0;
#endif /* CONFIG_USE_VSYNC_SKIP */

	decon->cur_frame_has_yuv = 0;

	if (decon->state == DECON_STATE_LPD)
		decon_exit_lpd(decon);

	for (i = 0; i < decon->pdata->max_win; i++) {
		for (j = 0; j < MAX_BUF_PLANE_CNT; ++j)
			memset(&old_dma_bufs[i][j], 0, sizeof(struct decon_dma_buf_data));
		old_plane_cnt[i] = 0;
	}

	for (i = 0; i < decon->pdata->max_win; i++) {
		old_plane_cnt[i] = decon->windows[i]->plane_cnt;
		for (j = 0; j < old_plane_cnt[i]; ++j)
			old_dma_bufs[i][j] = decon->windows[i]->dma_buf_data[j];
		if (regs->dma_buf_data[i][0].fence)
			decon_fence_wait(regs->dma_buf_data[i][0].fence);
	}

	decon_check_vpp_used(decon, regs);
	decon_get_vpp_min_lock(decon, regs);
	decon_set_vpp_disp_min_lock(decon, regs);
	decon_set_vpp_min_lock_early(decon, regs);

	DISP_SS_EVENT_LOG_WINCON(&decon->sd, regs);

#ifdef CONFIG_USE_VSYNC_SKIP
	if (decon->out_type == DECON_OUT_DSI) {
		vsync_wait_cnt = decon_extra_vsync_wait_get();
		decon_extra_vsync_wait_set(0);

		if (vsync_wait_cnt < ERANGE && regs->num_of_window <= 2) {
			while ((vsync_wait_cnt--) > 0) {
				if ((decon_extra_vsync_wait_get() >= ERANGE)) {
					decon_extra_vsync_wait_set(0);
					break;
				}

				decon_wait_for_vsync(decon, VSYNC_TIMEOUT_MSEC);
			}
		}
	}
#endif /* CONFIG_USE_VSYNC_SKIP */

	decon_to_psr_info(decon, &psr);
	__decon_update_regs(decon, regs);
	if (decon->out_type == DECON_OUT_WB) {
		decon_reg_release_resource(decon->id, &psr);
		decon_vpp_wait_wb_framedone(decon);
		/* Stop to prevent resource conflict */
		decon->vpp_usage_bitmask = 0;
		decon_set_protected_content(decon, NULL);
		decon_dbg("write-back timeline:%d, max:%d\n",
				decon->timeline->value, decon->timeline_max);
	} else {
		decon->frame_start_cnt_target = decon->frame_start_cnt_cur + 1;
		decon_wait_for_vsync(decon, VSYNC_TIMEOUT_MSEC);
		decon_wait_for_vstatus(decon, 50);
		if (decon_reg_wait_for_update_timeout(decon->id, SHADOW_UPDATE_TIMEOUT) < 0) {
			decon_dump(decon);
			BUG();
		}

		/* wait until decon & dsim size matches */
		decon_wait_until_size_match(decon, decon->out_idx, 50 * 1000); /* 50ms */

		if (!decon->id) {
			/* clear I80 Framedone pending interrupt */
			decon_write_mask(decon->id, INTERRUPT_PENDING, ~0,
				INTERRUPT_FRAME_DONE_INT_EN);
			decon->frame_done_cnt_target = decon->frame_done_cnt_cur + 1;
		}

		if (!decon->sw_te_wa)
			decon_reg_set_trigger(decon->id, &psr, DECON_TRIG_DISABLE);
	}

	DISP_SS_EVENT_LOG(DISP_EVT_TRIG_MASK, &decon->sd, ktime_set(0, 0));
	decon->trig_mask_timestamp =  ktime_get();
	for (i = 0; i < decon->pdata->max_win; i++) {
		for (j = 0; j < old_plane_cnt[i]; ++j)
			if (decon->out_type == DECON_OUT_WB)
				decon_free_dma_buf(decon, &regs->dma_buf_data[i][j]);
			else
				decon_free_dma_buf(decon, &old_dma_bufs[i][j]);
	}

	if (decon->out_type == DECON_OUT_WB) {
		old_plane_cnt[0] = decon_get_plane_cnt(regs->vpp_config[MAX_DECON_WIN].format);
		for (j = 0; j < old_plane_cnt[0]; ++j)
			decon_free_dma_buf(decon, &regs->dma_buf_data[MAX_DECON_WIN][j]);
	}

	sw_sync_timeline_inc(decon->timeline, 1);
	decon_set_vpp_min_lock_lately(decon, regs);
	decon_vpp_stop(decon, false);
}

static void decon_update_regs_handler(struct kthread_work *work)
{
	struct decon_device *decon =
			container_of(work, struct decon_device, update_regs_work);
	struct decon_reg_data *data, *next;
	struct list_head saved_list;

	if (decon->state == DECON_STATE_LPD)
		decon_warn("%s: LPD state: %d\n", __func__, decon_get_lpd_block_cnt(decon));

	mutex_lock(&decon->update_regs_list_lock);
	saved_list = decon->update_regs_list;
	list_replace_init(&decon->update_regs_list, &saved_list);
	mutex_unlock(&decon->update_regs_list_lock);

	list_for_each_entry_safe(data, next, &saved_list, list) {
		decon_update_regs(decon, data);
		decon_lpd_unblock(decon);
		list_del(&data->list);
		kfree(data);
	}
}

static void decon_win_config_dump(struct decon_device *decon,
	struct decon_win_config *win_config)
{
	int i;

	for (i = 0; i < decon->pdata->max_win; i++) {
		struct decon_win_config *config = &win_config[i];
		if (config->state != DECON_WIN_STATE_DISABLED)
		decon_dbg("win-%d, state:%d, format:%d, idma_type:%d, src[%d %d %d %d %d %d],"
			"dst[%d %d %d %d %d %d]", i, config->state, config->format, config->idma_type,
			config->src.x, config->src.y, config->src.w, config->src.h, config->src.f_w,
			config->src.f_h, config->dst.x, config->dst.y, config->dst.w, config->dst.h,
			config->dst.f_w, config->dst.f_h);
	}
}

static int decon_set_win_config(struct decon_device *decon,
		struct decon_win_config_data *win_data)
{
	struct decon_win_config *win_config = win_data->config;
	int ret = 0;
	unsigned short i, j;
	struct decon_reg_data *regs;
	struct sync_fence *fence;
	struct sync_pt *pt;
	int fd;
	unsigned int bw = 0;
	int plane_cnt = 0;

	fd = get_unused_fd();
	if (fd < 0)
		return fd;

	mutex_lock(&decon->output_lock);

	if ((decon->state == DECON_STATE_OFF) ||
		(decon->out_type == DECON_OUT_TUI)) {
		decon->timeline_max++;
		pt = sw_sync_pt_create(decon->timeline, decon->timeline_max);
		fence = sync_fence_create("display", pt);
		sync_fence_install(fence, fd);
		win_data->fence = fd;

		sw_sync_timeline_inc(decon->timeline, 1);
		goto err;
	}

	regs = kzalloc(sizeof(struct decon_reg_data), GFP_KERNEL);
	if (!regs) {
		decon_err("could not allocate decon_reg_data\n");
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < decon->pdata->max_win; i++) {
		decon->windows[i]->prev_fix =
			decon->windows[i]->fbinfo->fix;
		decon->windows[i]->prev_var =
			decon->windows[i]->fbinfo->var;

	}

#ifdef CONFIG_FB_WINDOW_UPDATE
	if (decon->out_type == DECON_OUT_DSI)
		decon_set_win_update_config(decon, win_config, regs);
#endif
	decon_win_config_dump(decon, win_config);
	for (i = 0; i < decon->pdata->max_win && !ret; i++) {
		struct decon_win_config *config = &win_config[i];
		struct decon_win *win = decon->windows[i];
		struct decon_window_regs *win_regs = &regs->win_regs[win->index];

		bool enabled = 0;
		bool color_map = true;
		u32 color = 0;

		switch (config->state) {
		case DECON_WIN_STATE_DISABLED:
			break;
		case DECON_WIN_STATE_COLOR:
			enabled = 1;
			color = config->color;
			decon_win_conig_to_regs_param(0, config, win_regs, IDMA_G0);
			break;
		case DECON_WIN_STATE_BUFFER:
			if (!decon->id && ((config->idma_type == IDMA_G0) &&
					(i != MAX_DECON_WIN - 1))) {
				decon_info("%s: idma_type %d win-id %d\n",
						__func__, config->idma_type, i);
				break;
			}
			if (IS_ENABLED(CONFIG_DECON_BLOCKING_MODE))
				if (decon_set_win_blocking_mode(decon, win, win_config, regs))
					break;

			ret = decon_set_win_buffer(decon, win, config, regs);
			if (!ret) {
				enabled = 1;
				color_map = false;
			}
			break;
		default:
			decon_warn("unrecognized window state %u",
					config->state);
			ret = -EINVAL;
			break;
		}
		if (enabled)
			win_regs->wincon |= WIN_CONTROL_EN_F;
		else
			win_regs->wincon &= ~WIN_CONTROL_EN_F;

		if (color_map) {
			win_regs->colormap = color;
			win_regs->winmap_state = color_map;
		}

		if (enabled && config->state == DECON_WIN_STATE_BUFFER) {
			bw += decon_calc_bandwidth(config->dst.w, config->dst.h,
					win->fbinfo->var.bits_per_pixel,
					win->fps);
			regs->num_of_window++;
		}
	}

	if (decon->out_type == DECON_OUT_WB)
		ret = decon_set_wb_buffer(decon, win_config, regs);

	for (i = 0; i < MAX_VPP_SUBDEV; i++) {
		memcpy(&regs->vpp_config[i], &win_config[i],
				sizeof(struct decon_win_config));
		regs->vpp_config[i].format =
			get_vpp_src_format(regs->vpp_config[i].format, win_config[i].idma_type);
	}
	regs->bandwidth = bw;

	decon_dbg("Total BW = %d Mbits, Max BW per window = %d Mbits\n",
			bw / (1024 * 1024), MAX_BW_PER_WINDOW / (1024 * 1024));

	if (ret) {
		for (i = 0; i < decon->pdata->max_win; i++) {
			decon->windows[i]->fbinfo->fix = decon->windows[i]->prev_fix;
			decon->windows[i]->fbinfo->var = decon->windows[i]->prev_var;

			plane_cnt = decon_get_plane_cnt(regs->vpp_config[i].format);
			for (j = 0; j < plane_cnt; ++j)
				decon_free_dma_buf(decon, &regs->dma_buf_data[i][j]);
		}
		if (decon->out_type == DECON_OUT_WB) {
			plane_cnt = decon_get_plane_cnt(regs->vpp_config[MAX_DECON_WIN].format);
			for (j = 0; j < plane_cnt; ++j)
				decon_free_dma_buf(decon, &regs->dma_buf_data[MAX_DECON_WIN][j]);
		}
		put_unused_fd(fd);
		kfree(regs);
	} else {
		decon_lpd_block(decon);
		decon->timeline_max++;
		pt = sw_sync_pt_create(decon->timeline, decon->timeline_max);
		fence = sync_fence_create("display", pt);
		sync_fence_install(fence, fd);
		win_data->fence = fd;
		mutex_lock(&decon->update_regs_list_lock);
		list_add_tail(&regs->list, &decon->update_regs_list);
		mutex_unlock(&decon->update_regs_list_lock);
		queue_kthread_work(&decon->update_regs_worker,
				&decon->update_regs_work);
	}
err:
	mutex_unlock(&decon->output_lock);
	return ret;
}

static int decon_ioctl(struct fb_info *info, unsigned int cmd,
			unsigned long arg)
{
	struct decon_win *win = info->par;
	struct decon_device *decon = win->decon;
	int ret;
	u32 crtc;

	decon_lpd_block_exit(decon);

	switch (cmd) {
	case FBIO_WAITFORVSYNC:
		if (get_user(crtc, (u32 __user *)arg)) {
			ret = -EFAULT;
			break;
		}

		if (crtc == 0)
			ret = decon_wait_for_vsync(decon, VSYNC_TIMEOUT_MSEC);
		else
			ret = -ENODEV;

		break;

	case S3CFB_WIN_POSITION:
		if (copy_from_user(&decon->ioctl_data.user_window,
				(struct decon_user_window __user *)arg,
				sizeof(decon->ioctl_data.user_window))) {
			ret = -EFAULT;
			break;
		}

		if (decon->ioctl_data.user_window.x < 0)
			decon->ioctl_data.user_window.x = 0;
		if (decon->ioctl_data.user_window.y < 0)
			decon->ioctl_data.user_window.y = 0;

		ret = decon_set_window_position(info, decon->ioctl_data.user_window);
		break;

	case S3CFB_WIN_SET_PLANE_ALPHA:
		if (copy_from_user(&decon->ioctl_data.user_alpha,
				(struct s3c_fb_user_plane_alpha __user *)arg,
				sizeof(decon->ioctl_data.user_alpha))) {
			ret = -EFAULT;
			break;
		}

		ret = decon_set_plane_alpha_blending(info, decon->ioctl_data.user_alpha);
		break;

	case S3CFB_WIN_SET_CHROMA:
		if (copy_from_user(&decon->ioctl_data.user_chroma,
				   (struct s3c_fb_user_chroma __user *)arg,
				   sizeof(decon->ioctl_data.user_chroma))) {
			ret = -EFAULT;
			break;
		}

		ret = decon_set_chroma_key(info, decon->ioctl_data.user_chroma);
		break;

	case S3CFB_SET_VSYNC_INT:
		if (get_user(decon->ioctl_data.vsync, (int __user *)arg)) {
			ret = -EFAULT;
			break;
		}

		ret = decon_set_vsync_int(info, decon->ioctl_data.vsync);
		break;

	case S3CFB_WIN_CONFIG:
		DISP_SS_EVENT_LOG(DISP_EVT_WIN_CONFIG, &decon->sd, ktime_set(0, 0));
		if (copy_from_user(&decon->ioctl_data.win_data,
				   (struct decon_win_config_data __user *)arg,
				   sizeof(decon->ioctl_data.win_data))) {
			ret = -EFAULT;
			break;
		}

		ret = decon_set_win_config(decon, &decon->ioctl_data.win_data);
		if (ret)
			break;

		if (copy_to_user(&((struct decon_win_config_data __user *)arg)->fence,
				 &decon->ioctl_data.win_data.fence,
				 sizeof(decon->ioctl_data.win_data.fence))) {
			ret = -EFAULT;
			break;
		}
		break;

	default:
		ret = -ENOTTY;
	}

	decon_lpd_unblock(decon);
	return ret;
}

int decon_release(struct fb_info *info, int user)
{
	struct decon_win *win = info->par;
	struct decon_device *decon = win->decon;

	decon_info("%s +\n", __func__);

	if (decon->id && decon->pdata->out_type == DECON_OUT_DSI) {
		find_subdev_mipi(decon, decon->out_idx);
		decon_info("output device of decon%d is changed to %s\n",
				decon->id, decon->output_sd->name);
	}

	decon_info("%s -\n", __func__);

	return 0;
}

#ifdef CONFIG_COMPAT
static int decon_compat_ioctl(struct fb_info *info, unsigned int cmd,
		unsigned long arg)
{
	arg = (unsigned long) compat_ptr(arg);
	return decon_ioctl(info, cmd, arg);
}
#endif

/* ---------- FREAMBUFFER INTERFACE ----------- */
static struct fb_ops decon_fb_ops = {
	.owner		= THIS_MODULE,
	.fb_check_var	= decon_check_var,
	.fb_set_par	= decon_set_par,
	.fb_blank	= decon_blank,
	.fb_setcolreg	= decon_setcolreg,
	.fb_fillrect    = cfb_fillrect,
	.fb_copyarea    = cfb_copyarea,
	.fb_imageblit   = cfb_imageblit,
#ifdef CONFIG_COMPAT
	.fb_compat_ioctl = decon_compat_ioctl,
#endif
	.fb_ioctl	= decon_ioctl,
	.fb_pan_display	= decon_pan_display,
	.fb_mmap	= decon_mmap,
	.fb_release	= decon_release,
};

/* ---------- POWER MANAGEMENT ----------- */
void decon_clocks_info(struct decon_device *decon)
{
	decon_info("%s: %ld Mhz\n", __clk_get_name(decon->res.pclk),
				clk_get_rate(decon->res.pclk) / MHZ);
	decon_info("%s: %ld Mhz\n", __clk_get_name(decon->res.eclk_leaf),
				clk_get_rate(decon->res.eclk_leaf) / MHZ);
	if (decon->id != 2) {
		decon_info("%s: %ld Mhz\n", __clk_get_name(decon->res.vclk_leaf),
				clk_get_rate(decon->res.vclk_leaf) / MHZ);
	}
}

void decon_put_clocks(struct decon_device *decon)
{
	if (decon->id != 2) {
		clk_put(decon->res.dpll);
		clk_put(decon->res.vclk);
		clk_put(decon->res.vclk_leaf);
	}
	clk_put(decon->res.pclk);
	clk_put(decon->res.eclk);
	clk_put(decon->res.eclk_leaf);
}

static int decon_runtime_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct decon_device *decon = platform_get_drvdata(pdev);

	DISP_SS_EVENT_LOG(DISP_EVT_DECON_RESUME, &decon->sd, ktime_set(0, 0));
	decon_dbg("decon%d %s +\n", decon->id, __func__);
	mutex_lock(&decon->mutex);

	if (decon->id != 2) {
		clk_prepare_enable(decon->res.dpll);
		clk_prepare_enable(decon->res.vclk);
		clk_prepare_enable(decon->res.vclk_leaf);
	}
	clk_prepare_enable(decon->res.pclk);
	clk_prepare_enable(decon->res.eclk);
	clk_prepare_enable(decon->res.eclk_leaf);

	if (!decon->id)
		decon_f_set_clocks(decon);
	else if (decon->id == 2)
		decon_t_set_clocks(decon);
	else
		decon_s_set_clocks(decon);

	if (decon->state == DECON_STATE_INIT)
		decon_clocks_info(decon);

	mutex_unlock(&decon->mutex);
	decon_dbg("decon%d %s -\n", decon->id, __func__);

	return 0;
}

static int decon_runtime_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct decon_device *decon = platform_get_drvdata(pdev);

	DISP_SS_EVENT_LOG(DISP_EVT_DECON_SUSPEND, &decon->sd, ktime_set(0, 0));
	decon_dbg("decon%d %s +\n", decon->id, __func__);
	mutex_lock(&decon->mutex);

	clk_disable_unprepare(decon->res.eclk);
	clk_disable_unprepare(decon->res.eclk_leaf);
	clk_disable_unprepare(decon->res.pclk);
	if (decon->id != 2) {
		clk_disable_unprepare(decon->res.vclk);
		clk_disable_unprepare(decon->res.vclk_leaf);
		clk_disable_unprepare(decon->res.dpll);
	}

	mutex_unlock(&decon->mutex);
	decon_dbg("decon%d %s -\n", decon->id, __func__);

	return 0;
}

static const struct dev_pm_ops decon_pm_ops = {
	.runtime_suspend = decon_runtime_suspend,
	.runtime_resume	 = decon_runtime_resume,
};

/* ---------- MEDIA CONTROLLER MANAGEMENT ----------- */
static long decon_sd_ioctl(struct v4l2_subdev *sd, unsigned int cmd, void *arg)
{
	struct decon_device *decon = container_of(sd, struct decon_device, sd);
	long ret = 0;

	switch (cmd) {
	case DECON_IOC_LPD_EXIT_LOCK:
		decon_lpd_block_exit(decon);
		break;
	case DECON_IOC_LPD_UNLOCK:
		decon_lpd_unblock(decon);
		break;
	default:
		dev_err(decon->dev, "unsupported ioctl");
		ret = -EINVAL;
	}
	return ret;
}

static int decon_s_stream(struct v4l2_subdev *sd, int enable)
{
	return 0;
}

static int decon_s_fmt(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh,
		       struct v4l2_subdev_format *format)
{
	struct decon_device *decon = container_of(sd, struct decon_device, sd);
	struct decon_lcd *porch;

	if (format->pad != DECON_PAD_WB) {
		decon_err("it is possible only output format setting\n");
		return -EINVAL;
	}

	if (format->format.width * format->format.height > 3840 * 2160) {
		decon_err("size is bigger than 3840x2160\n");
		return -EINVAL;
	}

	porch = kzalloc(sizeof(struct decon_lcd), GFP_KERNEL);
	if (!porch) {
		decon_err("could not allocate decon_lcd for wb\n");
		return -ENOMEM;
	}

	decon->lcd_info = porch;
	decon->lcd_info->width = format->format.width;
	decon->lcd_info->height = format->format.height;
	decon->lcd_info->xres = format->format.width;
	decon->lcd_info->yres = format->format.height;
	decon->lcd_info->vfp = 2;
	decon->lcd_info->vbp = 20;
	decon->lcd_info->hfp = 20;
	decon->lcd_info->hbp = 20;
	decon->lcd_info->vsa = 2;
	decon->lcd_info->hsa = 20;
	decon->lcd_info->fps = 60;
	decon->out_type = DECON_OUT_WB;

	decon_info("decon-%d output size for writeback %dx%d\n", decon->id,
			decon->lcd_info->width, decon->lcd_info->height);

	return 0;
}

static const struct v4l2_subdev_core_ops decon_sd_core_ops = {
	.ioctl = decon_sd_ioctl,
};

static const struct v4l2_subdev_video_ops decon_sd_video_ops = {
	.s_stream = decon_s_stream,
};

static const struct v4l2_subdev_pad_ops	decon_sd_pad_ops = {
	.set_fmt = decon_s_fmt,
};

static const struct v4l2_subdev_ops decon_sd_ops = {
	.video = &decon_sd_video_ops,
	.core = &decon_sd_core_ops,
	.pad = &decon_sd_pad_ops,
};

static int decon_link_setup(struct media_entity *entity,
			      const struct media_pad *local,
			      const struct media_pad *remote, u32 flags)
{
	return 0;
}

static const struct media_entity_operations decon_entity_ops = {
	.link_setup = decon_link_setup,
};

static int decon_register_subdev_nodes(struct decon_device *decon,
					struct exynos_md *md)
{
	int ret = v4l2_device_register_subdev_nodes(&md->v4l2_dev);
	if (ret) {
		decon_err("failed to make nodes for subdev\n");
		return ret;
	}

	decon_dbg("Register V4L2 subdev nodes for DECON\n");

	return 0;

}

static int decon_create_links(struct decon_device *decon,
					struct exynos_md *md)
{
	int ret = 0;
	char err[80];
#ifdef CONFIG_EXYNOS_VPP
	int i, j;
	u32 flags = MEDIA_LNK_FL_IMMUTABLE | MEDIA_LNK_FL_ENABLED;
#endif

	decon_dbg("decon%d create links\n", decon->id);
	memset(err, 0, sizeof(err));

	/*
	 * Link creation : vpp -> decon-int and ext.
	 * All windos of decon should be connected to all
	 * VPP each other.
	 */
#ifdef CONFIG_EXYNOS_VPP
	for (i = 0; i < MAX_VPP_SUBDEV; ++i) {
		for (j = 0; j < decon->n_sink_pad; j++) {
			ret = media_entity_create_link(&md->vpp_sd[i]->entity,
					VPP_PAD_SOURCE, &decon->sd.entity,
					j, flags);
			if (ret) {
				snprintf(err, sizeof(err), "%s --> %s",
						md->vpp_sd[i]->entity.name,
						decon->sd.entity.name);
				return ret;
			}
		}
	}
	decon_info("vpp <-> decon links are created successfully\n");
#endif

	switch (decon->id) {
	case 0:
		if (decon->pdata->out_type == DECON_OUT_DSI)
			ret = create_link_mipi(decon, 0);
		break;
	case 1:
		if (decon->pdata->out_type == DECON_OUT_DSI)
			ret = create_link_mipi(decon, 2);
		break;
	case 3:
		if (decon->pdata->out_type == DECON_OUT_DSI)
			ret = create_link_mipi(decon, 1);
		break;
	}

	return ret;
}

static void decon_unregister_entity(struct decon_device *decon)
{
	v4l2_device_unregister_subdev(&decon->sd);
}

static int decon_register_entity(struct decon_device *decon)
{
	struct v4l2_subdev *sd = &decon->sd;
	struct media_pad *pads = decon->pads;
	struct media_entity *me = &sd->entity;
	struct exynos_md *md;
	int i, n_pad, ret = 0;

	/* init DECON sub-device */
	v4l2_subdev_init(sd, &decon_sd_ops);
	sd->owner = THIS_MODULE;
	snprintf(sd->name, sizeof(sd->name), "exynos-decon%d", decon->id);

	/* DECON sub-device can be opened in user space */
	sd->flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;

	/* init DECON sub-device as entity */
	n_pad = decon->n_sink_pad + decon->n_src_pad;
	for (i = 0; i < decon->n_sink_pad; i++)
		pads[i].flags = MEDIA_PAD_FL_SINK;
	for (i = decon->n_sink_pad; i < n_pad; i++)
		pads[i].flags = MEDIA_PAD_FL_SOURCE;

	me->ops = &decon_entity_ops;
	ret = media_entity_init(me, n_pad, pads, 0);
	if (ret) {
		decon_err("failed to initialize media entity\n");
		return ret;
	}

	md = (struct exynos_md *)module_name_to_driver_data(MDEV_MODULE_NAME);
	if (!md) {
		decon_err("failed to get output media device\n");
		return -ENODEV;
	}

	ret = v4l2_device_register_subdev(&md->v4l2_dev, sd);
	if (ret) {
		decon_err("failed to register DECON subdev\n");
		return ret;
	}
	decon_dbg("%s entity init\n", sd->name);

	switch (decon->id) {
		/* All decons can be LINKED to DSIM0/1/2 */
	case 0:
		/* Fixed to DSIM0 or eDP */
		if (decon->pdata->out_type == DECON_OUT_DSI) {
			ret = find_subdev_mipi(decon, 0);
		} else {
			/* TODO */
			decon_err("Not Supported output media device\n");
			return -ENODEV;
		}

		break;
	case 1:
		/* Fixed to DSIM1 */
		if (decon->pdata->out_type == DECON_OUT_DSI) {
			ret = find_subdev_mipi(decon, 1);
		}

		break;
	case 2:
		break;
	}

	return ret;
}

static void decon_release_windows(struct decon_win *win)
{
	if (win->fbinfo)
		framebuffer_release(win->fbinfo);
}

static int decon_fb_alloc_memory(struct decon_device *decon, struct decon_win *win)
{
	struct decon_fb_pd_win *windata = &win->windata;
	unsigned int real_size, virt_size, size;
	struct fb_info *fbi = win->fbinfo;
	struct ion_handle *handle;
	dma_addr_t map_dma;
	struct dma_buf *buf;
	void *vaddr;
	struct device *dev;
	unsigned int ret;

	dev_info(decon->dev, "allocating memory for display\n");

	real_size = windata->win_mode.videomode.xres * windata->win_mode.videomode.yres;
	virt_size = windata->virtual_x * windata->virtual_y;

	dev_info(decon->dev, "real_size=%u (%u.%u), virt_size=%u (%u.%u)\n",
		real_size, windata->win_mode.videomode.xres, windata->win_mode.videomode.yres,
		virt_size, windata->virtual_x, windata->virtual_y);

	size = (real_size > virt_size) ? real_size : virt_size;
	size *= (windata->max_bpp > 16) ? 32 : windata->max_bpp;
	size /= 8;

	fbi->fix.smem_len = size;
	size = PAGE_ALIGN(size);

	dev_info(decon->dev, "want %u bytes for window[%d]\n", size, win->index);

#if defined(CONFIG_ION_EXYNOS)
	handle = ion_alloc(decon->ion_client, (size_t)size, 0,
					EXYNOS_ION_HEAP_SYSTEM_MASK, 0);
	if (IS_ERR(handle)) {
		dev_err(decon->dev, "failed to ion_alloc\n");
		return -ENOMEM;
	}

	buf = ion_share_dma_buf(decon->ion_client, handle);
	if (IS_ERR_OR_NULL(buf)) {
		dev_err(decon->dev, "ion_share_dma_buf() failed\n");
		goto err_share_dma_buf;
	}

	vaddr = ion_map_kernel(decon->ion_client, handle);

	fbi->screen_base = vaddr;

	win->dma_buf_data[1].fence = NULL;
	win->dma_buf_data[2].fence = NULL;
	win->plane_cnt = 1;
	dev = decon->mdev->vpp_dev[decon->default_idma];
	ret = decon_map_ion_handle(decon, dev, &win->dma_buf_data[0],
			handle, buf, win->index);
	if (!ret)
		goto err_map;
	map_dma = win->dma_buf_data[0].dma_addr;

	dev_info(decon->dev, "alloated memory\n");
#else
	fbi->screen_base = dma_alloc_writecombine(decon->dev, size,
						  &map_dma, GFP_KERNEL);
	if (!fbi->screen_base)
		return -ENOMEM;

	dev_dbg(decon->dev, "mapped %x to %p\n",
		(unsigned int)map_dma, fbi->screen_base);

	memset(fbi->screen_base, 0x0, size);
#endif
	fbi->fix.smem_start = map_dma;

	dev_info(decon->dev, "fb start addr = 0x%x\n", (u32)fbi->fix.smem_start);

	return 0;

#ifdef CONFIG_ION_EXYNOS
err_map:
	dma_buf_put(buf);
err_share_dma_buf:
	ion_free(decon->ion_client, handle);
	return -ENOMEM;
#endif
}

static void decon_missing_pixclock(struct decon_fb_videomode *win_mode)
{
	u64 pixclk = 1000000000000ULL;
	u32 div;
	u32 width, height;

	width = win_mode->videomode.xres;
	height = win_mode->videomode.yres;

	div = width * height * (win_mode->videomode.refresh ? : 60);

	do_div(pixclk, div);
	win_mode->videomode.pixclock = pixclk;
}

static int decon_acquire_windows(struct decon_device *decon, int idx)
{
	struct decon_win *win;
	struct fb_info *fbinfo;
	struct fb_var_screeninfo *var;
	struct decon_lcd *lcd_info = NULL;
	int ret, i;

	decon_dbg("acquire DECON window%d\n", idx);

	fbinfo = framebuffer_alloc(sizeof(struct decon_win), decon->dev);
	if (!fbinfo) {
		decon_err("failed to allocate framebuffer\n");
		return -ENOENT;
	}

	win = fbinfo->par;
	decon->windows[idx] = win;
	var = &fbinfo->var;
	win->fbinfo = fbinfo;
	/*fbinfo->fbops = &decon_fb_ops;*/
	/*fbinfo->flags = FBINFO_FLAG_DEFAULT;*/
	win->decon = decon;
	win->index = idx;

	win->windata.default_bpp = 32;
	win->windata.max_bpp = 32;
	if (decon->pdata->out_type == DECON_OUT_DSI) {
		lcd_info = decon->lcd_info;
		win->windata.virtual_x = lcd_info->xres;
		win->windata.virtual_y = lcd_info->yres * 2;
		win->windata.width = lcd_info->xres;
		win->windata.height = lcd_info->yres;
		win->windata.win_mode.videomode.left_margin = lcd_info->hbp;
		win->windata.win_mode.videomode.right_margin = lcd_info->hfp;
		win->windata.win_mode.videomode.upper_margin = lcd_info->vbp;
		win->windata.win_mode.videomode.lower_margin = lcd_info->vfp;
		win->windata.win_mode.videomode.hsync_len = lcd_info->hsa;
		win->windata.win_mode.videomode.vsync_len = lcd_info->vsa;
		win->windata.win_mode.videomode.xres = lcd_info->xres;
		win->windata.win_mode.videomode.yres = lcd_info->yres;
		decon_missing_pixclock(&win->windata.win_mode);
	}

	for (i = 0; i < MAX_BUF_PLANE_CNT; ++i)
		memset(&win->dma_buf_data[i], 0, sizeof(win->dma_buf_data));

	if ((decon->pdata->out_type == DECON_OUT_DSI)
			&& (win->index == decon->pdata->default_win)) {
		ret = decon_fb_alloc_memory(decon, win);
		if (ret) {
			dev_err(decon->dev, "failed to allocate display memory\n");
			return ret;
		}
	}

	fb_videomode_to_var(&fbinfo->var, &win->windata.win_mode.videomode);

	fbinfo->fix.type	= FB_TYPE_PACKED_PIXELS;
	fbinfo->fix.accel	= FB_ACCEL_NONE;
	fbinfo->var.activate	= FB_ACTIVATE_NOW;
	fbinfo->var.vmode	= FB_VMODE_NONINTERLACED;
	fbinfo->var.bits_per_pixel = win->windata.default_bpp;
	fbinfo->var.width	= win->windata.width;
	fbinfo->var.height	= win->windata.height;
	fbinfo->fbops		= &decon_fb_ops;
	fbinfo->flags		= FBINFO_FLAG_DEFAULT;
	fbinfo->pseudo_palette  = &win->pseudo_palette;
	decon_dbg("default_win %d win_idx %d xres %d yres %d\n", decon->pdata->default_win, idx, fbinfo->var.xres, fbinfo->var.yres);

	ret = decon_check_var(&fbinfo->var, fbinfo);
	if (ret < 0) {
		dev_err(decon->dev, "check_var failed on initial video params\n");
		return ret;
	}

	ret = fb_alloc_cmap(&fbinfo->cmap, 256 /* palette size */, 1);
	if (ret == 0)
		fb_set_cmap(&fbinfo->cmap, fbinfo);
	else
		dev_err(decon->dev, "failed to allocate fb cmap\n");

	decon_dbg("decon%d window[%d] create\n", decon->id, idx);
	return 0;
}

static int decon_acquire_window(struct decon_device *decon)
{
	int i, ret;

	for (i = 0; i < decon->n_sink_pad; i++) {
		ret = decon_acquire_windows(decon, i);
		if (ret < 0) {
			decon_err("failed to create decon-int window[%d]\n", i);
			for (; i >= 0; i--)
				decon_release_windows(decon->windows[i]);
			return ret;
		}
	}

	return 0;
}

int decon_get_disp_ss_addr(struct decon_device *decon)
{
	if (of_have_populated_dt()) {
		struct device_node *nd;

		nd = of_find_compatible_node(NULL, NULL,
				"samsung,exynos8-disp_ss");
		if (!nd) {
			decon_err("failed find compatible node(sysreg-disp)");
			return -ENODEV;
		}

		decon->ss_regs = of_iomap(nd, 0);
		if (!decon->ss_regs) {
			decon_err("Failed to get sysreg-disp address.");
			return -ENOMEM;
		}
	} else {
		decon_err("failed have populated device tree");
		return -EIO;
	}

	return 0;
}

static void decon_parse_pdata(struct decon_device *decon, struct device *dev)
{
	struct device_node *te_eint;

	if (dev->of_node) {
		decon->id = of_alias_get_id(dev->of_node, "decon");
		of_property_read_u32(dev->of_node, "n_sink_pad",
					&decon->n_sink_pad);
		of_property_read_u32(dev->of_node, "n_src_pad",
					&decon->n_src_pad);
		of_property_read_u32(dev->of_node, "max_win",
					&decon->pdata->max_win);
		of_property_read_u32(dev->of_node, "default_win",
					&decon->pdata->default_win);
		/* video mode: 0, dp: 1 mipi command mode: 2 */
		of_property_read_u32(dev->of_node, "psr_mode",
					&decon->pdata->psr_mode);
		/* H/W trigger: 0, S/W trigger: 1 */
		of_property_read_u32(dev->of_node, "trig_mode",
					&decon->pdata->trig_mode);
		decon_info("decon-%s: max win%d, %s mode, %s trigger\n",
			(decon->id == 0) ? "f" : ((decon->id == 1) ? "s" : "t"),
			decon->pdata->max_win,
			decon->pdata->psr_mode ? "command" : "video",
			decon->pdata->trig_mode ? "sw" : "hw");

		/* DSI: 0, EDP: 1  & HDMI: 2*/
		of_property_read_u32(dev->of_node, "out_type",
				&decon->pdata->out_type);
		decon_info("out type(%d). 0: DSI 1: EDP 2: HDMI 3: WB\n",
				decon->pdata->out_type);

		/* DSI_MODE_SINGLE: 0, DSI_MODE_DUAL_DISPLAY: 1  & DSI_MODE_DUAL_DSI: 2*/
		of_property_read_u32(dev->of_node, "dsi_mode",
				&decon->pdata->dsi_mode);
		decon_info("dsi mode(%d). 0: DSI_MODE_SINGLE 1: DSI_MODE_DUAL_DISPLAY 2: DSI_MODE_DUAL_DSI\n",
				decon->pdata->dsi_mode);

		if ((decon->pdata->out_type == DECON_OUT_DSI) ||
			(decon->pdata->out_type == DECON_OUT_EDP)) {
			te_eint = of_get_child_by_name(decon->dev->of_node, "te_eint");
			if (!te_eint) {
				decon_info("No DT node for te_eint\n");
			} else {
				decon->eint_pend = of_iomap(te_eint, 0);
				if (!decon->eint_pend)
					decon_info("Failed to get te eint pend\n");

				decon->eint_mask = of_iomap(te_eint, 1);
				if (!decon->eint_mask)
					decon_info("Failed to get te eint mask\n");
			}
		}

	} else {
		decon_warn("no device tree information\n");
	}
}

#ifdef CONFIG_DECON_EVENT_LOG
static int decon_debug_event_show(struct seq_file *s, void *unused)
{
	struct decon_device *decon = s->private;
	DISP_SS_EVENT_SHOW(s, decon);
	return 0;
}

static int decon_debug_event_open(struct inode *inode, struct file *file)
{
	return single_open(file, decon_debug_event_show, inode->i_private);
}

static const struct file_operations decon_event_fops = {
	.open = decon_debug_event_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif

/* --------- DRIVER INITIALIZATION ---------- */
static int decon_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct decon_device *decon;
	struct resource *res;
	struct fb_info *fbinfo;
	int ret = 0;
	char device_name[MAX_NAME_SIZE], debug_name[MAX_NAME_SIZE];

	struct decon_mode_info psr;
	struct decon_param p;
	struct decon_window_regs win_regs;
	struct dsim_device *dsim;
	struct exynos_md *md;
	struct device_node *cam_stat;
	int i = 0;
	int win_idx = 0;
	struct v4l2_subdev *sd = NULL;
	struct decon_win_config config;

	dev_info(dev, "%s start\n", __func__);

	decon = devm_kzalloc(dev, sizeof(struct decon_device), GFP_KERNEL);
	if (!decon) {
		decon_err("no memory for decon device\n");
		return -ENOMEM;
	}

	/* setup pointer to master device */
	decon->dev = dev;
	decon->pdata = devm_kzalloc(dev, sizeof(struct exynos_decon_platdata),
						GFP_KERNEL);
	if (!decon->pdata) {
		decon_err("no memory for DECON platdata\n");
		return -ENOMEM;
	}
	/* parse decon config from the DT */
	decon_parse_pdata(decon, dev);
	win_idx = decon->pdata->default_win;

	/* init clock setting for decon */
	switch (decon->id) {
	case 0:
		decon_f_drvdata = decon;
		decon_f_get_clocks(decon);
		decon->decon[1] = decon_s_drvdata;
		decon->decon[2] = decon_t_drvdata;
		decon->default_idma = IDMA_G1;
		decon->dma_rsm = devm_kzalloc(dev, sizeof(struct dma_rsm), GFP_KERNEL);
		if (!decon->dma_rsm) {
			decon_err("no memory for decon dma_rsm\n");
			return -ENOMEM;
		}
		break;
	case 1:
		decon_s_drvdata = decon;
		decon_s_get_clocks(decon);
		decon->decon[0] = decon_f_drvdata;
		decon->decon[2] = decon_t_drvdata;
		decon->default_idma = IDMA_G2;
		decon->dma_rsm = decon_f_drvdata->dma_rsm;
		break;
	case 2:
		decon_t_drvdata = decon;
		decon_t_get_clocks(decon);
		decon->decon[0] = decon_f_drvdata;
		decon->decon[1] = decon_s_drvdata;
		decon->default_idma = IDMA_G3;
		decon->dma_rsm = decon_f_drvdata->dma_rsm;
		break;
	}

	/* Get memory resource and map SFR region. */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	decon->regs = devm_ioremap_resource(dev, res);
	if (decon->regs == NULL) {
		decon_err("failed to claim register region\n");
		return -ENOENT;
	}

	spin_lock_init(&decon->slock);
	init_waitqueue_head(&decon->vsync_info.wait);
	init_waitqueue_head(&decon->wait_frmdone);
	init_waitqueue_head(&decon->wait_vstatus);
	mutex_init(&decon->vsync_info.irq_lock);
	snprintf(device_name, MAX_NAME_SIZE, "decon%d", decon->id);
	decon->timeline = sw_sync_timeline_create(device_name);

	if (decon->pdata->out_type == DECON_OUT_WB)
		decon->timeline_max = 0;
	else
		decon->timeline_max = 1;

	/* Get IRQ resource and register IRQ, create thread */
	switch (decon->id) {
	case 0:
		ret = decon_f_register_irq(pdev, decon);
		if (ret)
			goto fail;

		ret = decon_f_create_vsync_thread(decon);
		if (ret)
			goto fail;

		ret = decon_f_create_psr_thread(decon);
		if (ret)
			goto fail_vsync_thread;

		snprintf(debug_name, MAX_NAME_SIZE, "decon");
		decon->debug_root = debugfs_create_dir(debug_name, NULL);
		if (!decon->debug_root) {
			decon_err("failed to create debugfs root directory.\n");
			goto fail_psr_thread;
		}
		break;
	case 1:
		if (decon->decon[0])
			decon->debug_root = decon->decon[0]->debug_root;

		ret = decon_s_register_irq(pdev, decon);
		if (ret)
			goto fail;
		break;
	case 2:
		if (decon->decon[0])
			decon->debug_root = decon->decon[0]->debug_root;

		ret = decon_t_register_irq(pdev, decon);
		if (ret)
			goto fail;

		decon_t_set_lcd_info(decon);
		break;
	}

	if ((decon->pdata->psr_mode != DECON_VIDEO_MODE) &&
		((decon->pdata->out_type == DECON_OUT_DSI) ||
		(decon->pdata->out_type == DECON_OUT_EDP))) {
		ret = decon_config_eint_for_te(pdev, decon);
		if (ret)
			goto fail_psr_thread;

		ret = decon_register_lpd_work(decon);
		if (ret)
			goto fail_psr_thread;

	}

	decon->ion_client = ion_client_create(ion_exynos, device_name);
	if (IS_ERR(decon->ion_client)) {
		decon_err("failed to ion_client_create\n");
		goto fail_psr_thread;
	}

	decon->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(decon->pinctrl)) {
		decon_warn("failed to get decon-%d pinctrl\n", decon->id);
		decon->pinctrl = NULL;
	} else {
		decon->decon_te_on = pinctrl_lookup_state(decon->pinctrl, "decon_te_on");
		if (IS_ERR(decon->decon_te_on)) {
			decon_err("failed to get decon_te_on pin state\n");
			decon->decon_te_on = NULL;
		}
		decon->decon_te_off = pinctrl_lookup_state(decon->pinctrl, "decon_te_off");
		if (IS_ERR(decon->decon_te_off)) {
			decon_err("failed to get decon_te_off pin state\n");
			decon->decon_te_off = NULL;
		}
	}

#ifdef CONFIG_DECON_EVENT_LOG
	snprintf(debug_name, MAX_NAME_SIZE, "event%d", decon->id);
	atomic_set(&decon->disp_ss_log_idx, -1);
	decon->debug_event = debugfs_create_file(debug_name, 0444,
						decon->debug_root,
						decon, &decon_event_fops);
#endif

	/* register internal and external DECON as entity */
	ret = decon_register_entity(decon);
	if (ret)
		goto fail_psr_thread;

	md = (struct exynos_md *)module_name_to_driver_data(MDEV_MODULE_NAME);
	if (!md) {
		decon_err("failed to get output media device\n");
		goto fail_entity;
	}

	decon->mdev = md;

	/* mapping SYSTEM registers */
	ret = decon_get_disp_ss_addr(decon);
	if (ret)
		goto fail_entity;

	/* link creation: vpp <-> decon / decon <-> output */
	ret = decon_create_links(decon, md);
	if (ret)
		goto fail_entity;

	ret = decon_register_subdev_nodes(decon, md);
	if (ret)
		goto fail_entity;

	/* configure windows */
	ret = decon_acquire_window(decon);
	if (ret)
		goto fail_entity;

	/* register framebuffer */
	fbinfo = decon->windows[decon->pdata->default_win]->fbinfo;
	ret = register_framebuffer(fbinfo);
	if (ret < 0) {
		decon_err("failed to register framebuffer\n");
		goto fail_entity;
	}

	/* mutex mechanism */
	mutex_init(&decon->output_lock);
	mutex_init(&decon->mutex);

	/* init work thread for update registers */
	mutex_init(&decon->update_regs_list_lock);
	INIT_LIST_HEAD(&decon->update_regs_list);
	init_kthread_worker(&decon->update_regs_worker);

	decon->update_regs_thread = kthread_run(kthread_worker_fn,
			&decon->update_regs_worker, device_name);
	if (IS_ERR(decon->update_regs_thread)) {
		ret = PTR_ERR(decon->update_regs_thread);
		decon->update_regs_thread = NULL;
		decon_err("failed to run update_regs thread\n");
		goto fail_update_thread;
	}
	init_kthread_work(&decon->update_regs_work, decon_update_regs_handler);

	snprintf(device_name, MAX_NAME_SIZE, "decon%d-wb", decon->id);

	if (decon->pdata->out_type == DECON_OUT_DSI) {
		ret = decon_set_lcd_config(decon);
		if (ret) {
			decon_err("failed to set lcd information\n");
			goto fail_update_thread;
		}
	}
	platform_set_drvdata(pdev, decon);
	pm_runtime_enable(dev);

	decon->bts_init_ops = &decon_init_bts_control;

	call_init_ops(decon, bts_add, decon);

	if (!decon->id && decon->pdata->out_type == DECON_OUT_DSI) {
		/* Enable only Decon_F during probe */
#if defined(CONFIG_PM_RUNTIME)
		pm_runtime_get_sync(decon->dev);
#else
		decon_runtime_resume(decon->dev);
#endif
		if (decon->pdata->psr_mode != DECON_VIDEO_MODE) {
			if (decon->pinctrl && decon->decon_te_on) {
				if (pinctrl_select_state(decon->pinctrl, decon->decon_te_on)) {
					decon_err("failed to turn on Decon_TE\n");
					goto fail_update_thread;
				}
			}
		}

		/* DSIM device will use the decon pointer to call the LPD functions */
		dsim = container_of(decon->output_sd, struct dsim_device, sd);
		dsim->decon = (void *)decon;

		decon_to_init_param(decon, &p);
		if (decon_reg_init(decon->id, decon->out_idx, &p) < 0)
			goto decon_init_done;

		memset(&win_regs, 0, sizeof(struct decon_win_config));
		win_regs.wincon = wincon(0x8, 0xFF, 0xFF, 0xFF, DECON_BLENDING_NONE);
		win_regs.wincon |= WIN_CONTROL_EN_F;
		win_regs.start_pos = win_start_pos(0, 0);
		win_regs.end_pos = win_end_pos(0, 0, fbinfo->var.xres, fbinfo->var.yres);
		decon_dbg("xres %d yres %d win_start_pos %x win_end_pos %x\n",
			fbinfo->var.xres, fbinfo->var.yres, win_regs.start_pos,
			win_regs.end_pos);
		win_regs.colormap = 0x00FF00;
		win_regs.pixel_count = fbinfo->var.xres * fbinfo->var.yres;
		win_regs.whole_w = fbinfo->var.xres_virtual;
		win_regs.whole_h = fbinfo->var.yres_virtual;
		win_regs.offset_x = fbinfo->var.xoffset;
		win_regs.offset_y = fbinfo->var.yoffset;
		win_regs.type = decon->default_idma;
		decon_reg_set_window_control(decon->id, win_idx, &win_regs, false);

		decon->vpp_usage_bitmask |= (1 << decon->default_idma);
		decon->vpp_used[decon->default_idma] = true;
		memset(&config, 0, sizeof(struct decon_win_config));
		config.vpp_parm.addr[0] = fbinfo->fix.smem_start;
		config.format = DECON_PIXEL_FORMAT_BGRA_8888;
		config.src.w = fbinfo->var.xres;
		config.src.h = fbinfo->var.yres;
		config.src.f_w = fbinfo->var.xres;
		config.src.f_h = fbinfo->var.yres;
		config.dst.w = config.src.w;
		config.dst.h = config.src.h;
		config.dst.f_w = config.src.f_w;
		config.dst.f_h = config.src.f_h;
		sd = decon->mdev->vpp_sd[decon->default_idma];
		/* Set a default Bandwidth */
		if (v4l2_subdev_call(sd, core, ioctl, VPP_SET_BW, &config))
			decon_err("Failed to VPP_SET_BW VPP-%d\n", decon->default_idma);

		if (v4l2_subdev_call(sd, core, ioctl, VPP_WIN_CONFIG, &config)) {
			decon_err("Failed to config VPP-%d\n", decon->default_idma);
			decon->vpp_usage_bitmask &= ~(1 << decon->default_idma);
			decon->vpp_err_stat[decon->default_idma] = true;
		}

		decon_reg_update_req_window(decon->id, win_idx);

#if defined(CONFIG_EXYNOS_DECON_MDNIE)
		if (!decon->id)
			mdnie_reg_start(decon->lcd_info->xres, decon->lcd_info->yres);
#endif

		decon_to_psr_info(decon, &psr);
		decon_reg_set_int(decon->id, &psr, 1);
		decon_reg_start(decon->id, &psr);

		call_panel_ops(dsim, displayon, dsim);
		decon_wait_for_vsync(decon, VSYNC_TIMEOUT_MSEC);
		if (decon_reg_wait_update_done_and_mask(decon->id, &psr, SHADOW_UPDATE_TIMEOUT)
				< 0)
			decon_err("%s: wait_for_update_timeout\n", __func__);

decon_init_done:

		decon->state = DECON_STATE_INIT;

		/* [W/A] prevent sleep enter during LCD on */
		ret = device_init_wakeup(decon->dev, true);
		if (ret) {
			dev_err(decon->dev, "failed to init wakeup device\n");
			goto fail_update_thread;
		}
		pm_stay_awake(decon->dev);

		if (dev->of_node) {
			of_property_read_u32(dev->of_node, "sw_te_wa",
					&decon->sw_te_wa);
		}
		dev_warn(decon->dev, "pm_stay_awake");
		cam_stat = of_get_child_by_name(decon->dev->of_node, "cam-stat");
		if (!cam_stat) {
			decon_info("No DT node for cam-stat\n");
		} else {
			decon->cam_status[0] = of_iomap(cam_stat, 0);
			if (!decon->cam_status[0])
				decon_info("Failed to get CAM0-STAT Reg\n");

			decon->cam_status[1] = of_iomap(cam_stat, 1);
			if (!decon->cam_status[1])
				decon_info("Failed to get CAM1-STAT Reg\n");
		}
	} else { /* DECON-EXT(only single-dsi) is off at probe */
		decon->state = DECON_STATE_INIT;
	}

	for (i = 0; i < MAX_VPP_SUBDEV; i++)
		decon->vpp_used[i] = false;

	decon->log_cnt = 0;

	decon_info("decon%d registered successfully", decon->id);

	return 0;

fail_update_thread:
	mutex_destroy(&decon->output_lock);
	mutex_destroy(&decon->mutex);
	mutex_destroy(&decon->update_regs_list_lock);

	if (decon->update_regs_thread)
		kthread_stop(decon->update_regs_thread);

fail_entity:
	decon_unregister_entity(decon);

fail_psr_thread:
	decon_f_destroy_psr_thread(decon);

fail_vsync_thread:
	decon_f_destroy_vsync_thread(decon);

fail:
	decon_err("decon probe fail");
	return ret;
}

static int decon_remove(struct platform_device *pdev)
{
	struct decon_device *decon = platform_get_drvdata(pdev);
	int i;

	pm_runtime_disable(&pdev->dev);
	decon_put_clocks(decon);
	unregister_framebuffer(decon->windows[0]->fbinfo);

	if (decon->update_regs_thread)
		kthread_stop(decon->update_regs_thread);

	for (i = 0; i < decon->pdata->max_win; i++)
		decon_release_windows(decon->windows[i]);

	debugfs_remove_recursive(decon->debug_root);
	kfree(decon);

	decon_info("remove sucessful\n");
	return 0;
}

static void decon_shutdown(struct platform_device *pdev)
{
	struct decon_device *decon = platform_get_drvdata(pdev);

	dev_info(decon->dev, "%s + state:%d\n", __func__, decon->state);
	DISP_SS_EVENT_LOG(DISP_EVT_DECON_SHUTDOWN, &decon->sd, ktime_set(0, 0));

	decon_lpd_block_exit(decon);
	/* Unused DECON state is DECON_STATE_INIT */
	if (decon->state == DECON_STATE_ON)
		decon_disable(decon);

	dev_info(decon->dev, "%s -\n", __func__);
	return;
}

static struct platform_driver decon_driver __refdata = {
	.probe		= decon_probe,
	.remove		= decon_remove,
	.shutdown	= decon_shutdown,
	.driver = {
		.name	= DRIVER_NAME,
		.owner	= THIS_MODULE,
		.pm	= &decon_pm_ops,
		.of_match_table = of_match_ptr(decon_device_table),
	}
};

static int exynos_decon_register(void)
{
	platform_driver_register(&decon_driver);

	return 0;
}

static void exynos_decon_unregister(void)
{
	platform_driver_unregister(&decon_driver);
}
late_initcall(exynos_decon_register);
module_exit(exynos_decon_unregister);

MODULE_AUTHOR("meka <v.meka@samsung.com>");
MODULE_DESCRIPTION("Samsung EXYNOS DECON driver");
MODULE_LICENSE("GPL");
