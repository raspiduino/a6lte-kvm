/*
 * linux/sound/cs35l40.h -- Platform data for CS35L40
 *
 * Copyright (c) 2016 Cirrus Logic Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CS35L40_H
#define __CS35L40_H

struct classh_cfg {
	bool classh_bst_override;
	bool classh_algo_enable;
	int classh_bst_max_limit;
	int classh_mem_depth;
	int classh_release_rate;
	int classh_headroom;
	int classh_wk_fet_delay;
	int classh_wk_fet_thld;
};

struct cs35l40_irq_cfg {
	bool is_present;
	bool irq_pol_inv;
	bool irq_out_en;
	int irq_src_sel;
};

struct cs35l40_platform_data {
	bool sclk_frc;
	bool lrclk_frc;
	bool right_channel;
	bool amp_gain_zc;
	bool dsp_ng_enable;
	int bst_ind;
	int bst_vctrl;
	int bst_ipk;
	int temp_warn_thld;
	int dsp_ng_pcm_thld;
	int dsp_ng_delay;
	unsigned int hw_ng_sel;
	unsigned int hw_ng_delay;
	unsigned int hw_ng_thld;
	unsigned int fixed_rate;
	unsigned int fixed_width;
	unsigned int fixed_wl;
	bool fixed_params;
	struct cs35l40_irq_cfg irq_config1;
	struct cs35l40_irq_cfg irq_config2;
	struct classh_cfg classh_config;
};

#endif /* __CS35L40_H */
