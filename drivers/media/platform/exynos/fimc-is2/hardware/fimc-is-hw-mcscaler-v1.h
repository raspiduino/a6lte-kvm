/*
 * Samsung EXYNOS FIMC-IS (Imaging Subsystem) driver
 *
 * Copyright (C) 2014 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef FIMC_IS_SUBDEV_MCSC_H
#define FIMC_IS_SUBDEV_MCSC_H

#include "fimc-is-hw-control.h"
#include "fimc-is-interface-library.h"
#include "fimc-is-param.h"

#define MCSC_ROUND_UP(x, d) \
	((d) * (((x) + ((d) - 1)) / (d)))

enum mcsc_img_format {
	MCSC_YUV422_1P_YUYV = 0,
	MCSC_YUV422_1P_YVYU,
	MCSC_YUV422_1P_UYVY,
	MCSC_YUV422_1P_VYUY,
	MCSC_YUV422_2P_UFIRST,
	MCSC_YUV422_2P_VFIRST,
	MCSC_YUV422_3P,
	MCSC_YUV420_2P_UFIRST,
	MCSC_YUV420_2P_VFIRST,
	MCSC_YUV420_3P
};

enum mcsc_io_type {
	HW_MCSC_OTF_INPUT,
	HW_MCSC_OTF_OUTPUT,
	HW_MCSC_DMA_INPUT,
	HW_MCSC_DMA_OUTPUT,
};

typedef struct {
	/* Brightness/Contrast control param */
	u32 y_offset;
	u32 y_gain;

	/* Hue/Saturation control param */
	u32 c_gain00;
	u32 c_gain01;
	u32 c_gain10;
	u32 c_gain11;
} scaler_setfile_contents;

struct hw_api_scaler_setfile {
	u32 setfile_version;

	/* contents for Full/Narrow mode
	 * 0 : SCALER_OUTPUT_YUV_RANGE_FULL
	 * 1 : SCALER_OUTPUT_YUV_RANGE_NARROW
	 */
	scaler_setfile_contents contents[2];
};

struct fimc_is_hw_mcsc {
	struct	hw_api_scaler_setfile *setfile;

	u32	img_format;
	bool	conv420_en;
	u32	instance;
};

int fimc_is_hw_mcsc_probe(struct fimc_is_hw_ip *hw_ip, struct fimc_is_interface *itf,
	struct fimc_is_interface_ischain *itfc, int id);
int fimc_is_hw_mcsc_open(struct fimc_is_hw_ip *hw_ip, u32 instance, u32 *size);
int fimc_is_hw_mcsc_init(struct fimc_is_hw_ip *hw_ip, struct fimc_is_group *group,
	bool flag, u32 module_id);
int fimc_is_hw_mcsc_close(struct fimc_is_hw_ip *hw_ip, u32 instance);
int fimc_is_hw_mcsc_enable(struct fimc_is_hw_ip *hw_ip, u32 instance, ulong hw_map);
int fimc_is_hw_mcsc_disable(struct fimc_is_hw_ip *hw_ip, u32 instance, ulong hw_map);
int fimc_is_hw_mcsc_shot(struct fimc_is_hw_ip *hw_ip, struct fimc_is_frame *frame,
	ulong hw_map);

int fimc_is_hw_mcsc_set_param(struct fimc_is_hw_ip *hw_ip, struct is_region *region,
	u32 lindex, u32 hindex, u32 instance, ulong hw_map);
int fimc_is_hw_mcsc_update_param(struct fimc_is_hw_ip *hw_ip,
	struct scp_param *param, u32 lindex, u32 hindex, u32 instance);
int fimc_is_hw_mcsc_frame_ndone(struct fimc_is_hw_ip *hw_ip, struct fimc_is_frame *frame,
	u32 instance, bool late_flag);
int fimc_is_hw_mcsc_reset(struct fimc_is_hw_ip *hw_ip);
int fimc_is_hw_mcsc_load_setfile(struct fimc_is_hw_ip *hw_ip, int index,
	u32 instance, ulong hw_map);
int fimc_is_hw_mcsc_apply_setfile(struct fimc_is_hw_ip *hw_ip, int index,
	u32 instance, ulong hw_map);
int fimc_is_hw_mcsc_delete_setfile(struct fimc_is_hw_ip *hw_ip, u32 instance,
	ulong hw_map);

int fimc_is_hw_mcsc_otf_input(struct fimc_is_hw_ip *hw_ip,
	struct param_otf_input *input, u32 instance);
int fimc_is_hw_mcsc_poly_phase(struct fimc_is_hw_ip *hw_ip, struct scp_param *param,
	struct param_scaler_input_crop *in_crop, u32 instance);
int fimc_is_hw_mcsc_post_chain(struct fimc_is_hw_ip *hw_ip, struct scp_param *param,
	u32 instance);
int fimc_is_hw_mcsc_flip(struct fimc_is_hw_ip *hw_ip, struct scp_param *param,
	struct param_scaler_flip *flip, u32 instance);
int fimc_is_hw_mcsc_otf_output(struct fimc_is_hw_ip *hw_ip, struct scp_param *param,
	struct param_otf_output *otf_output, u32 instance);
int fimc_is_hw_mcsc_dma_output(struct fimc_is_hw_ip *hw_ip, struct scp_param *param,
	struct param_dma_output *dma_output, u32 instance);
int fimc_is_hw_mcsc_output_yuvrange(struct fimc_is_hw_ip *hw_ip, struct scp_param *param,
	struct param_scaler_imageeffect *image_effect, u32 instance);

int fimc_is_hw_mcsc_adjust_img_fmt(u32 format, u32 plane, u32 order, u32 *img_format,
	bool *conv420_flag);
void fimc_is_hw_mcsc_adjust_stride(u32 width, u32 plane, bool conv420_flag,
	u32 *y_stride, u32 *uv_stride);
int fimc_is_hw_mcsc_check_format(enum mcsc_io_type type, u32 format, u32 bit_width,
	u32 width, u32 height);
void fimc_is_hw_mcsc_size_dump(struct fimc_is_hw_ip *hw_ip);

#ifdef DEBUG_HW_SIZE
#define hw_mcsc_check_size(hw_ip, param, instance) \
	fimc_is_hw_mcsc_check_size(hw_ip, param, instance)
#else
#define hw_mcsc_check_size(hw_ip, param, instance)
#endif
#endif
