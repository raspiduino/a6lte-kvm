#ifndef __MDNIE_TABLE_A7XE_H__
#define __MDNIE_TABLE_A7XE_H__

/* 2015.11.06 */

/* SCR Position can be different each panel */
static struct mdnie_scr_info scr_info = {
	.index = 1,
	.cr = 131,		/* ASCR_WIDE_CR[7:0] */
	.wr = 149,		/* ASCR_WIDE_WR[7:0] */
	.wg = 151,		/* ASCR_WIDE_WG[7:0] */
	.wb = 153		/* ASCR_WIDE_WB[7:0] */
};

static inline int color_offset_f1(int x, int y)
{
	return ((y << 10) - (((x << 10) * 43) / 40) + (45 << 10)) >> 10;
}
static inline int color_offset_f2(int x, int y)
{
	return ((y << 10) - (((x << 10) * 310) / 297) - (3 << 10)) >> 10;
}
static inline int color_offset_f3(int x, int y)
{
	return ((y << 10) + (((x << 10) * 367) / 84) - (16305 << 10)) >> 10;
}
static inline int color_offset_f4(int x, int y)
{
	return ((y << 10) + (((x << 10) * 333) / 107) - (12396 << 10)) >> 10;
}

/* color coordination order is WR, WG, WB */
static unsigned char coordinate_data_1[] = {
	0xff, 0xff, 0xff, /* dummy */
	0xff, 0xfb, 0xfb, /* Tune_1 */
	0xff, 0xfc, 0xff, /* Tune_2 */
	0xfb, 0xfa, 0xff, /* Tune_3 */
	0xff, 0xfe, 0xfc, /* Tune_4 */
	0xff, 0xff, 0xff, /* Tune_5 */
	0xfb, 0xfc, 0xff, /* Tune_6 */
	0xfd, 0xff, 0xfa, /* Tune_7 */
	0xfc, 0xff, 0xfc, /* Tune_8 */
	0xfb, 0xff, 0xff, /* Tune_9 */
};

static unsigned char coordinate_data_2[] = {
	0xff, 0xff, 0xff, /* dummy */
	0xff, 0xf6, 0xec, /* Tune_1 */
	0xff, 0xf6, 0xef, /* Tune_2 */
	0xff, 0xf8, 0xf3, /* Tune_3 */
	0xff, 0xf8, 0xec, /* Tune_4 */
	0xff, 0xf9, 0xef, /* Tune_5 */
	0xff, 0xfb, 0xf3, /* Tune_6 */
	0xff, 0xfb, 0xec, /* Tune_7 */
	0xff, 0xfc, 0xef, /* Tune_8 */
	0xff, 0xfd, 0xf3, /* Tune_9 */
};

static unsigned char *coordinate_data[MODE_MAX] = {
	coordinate_data_1,
	coordinate_data_2,
	coordinate_data_2,
	coordinate_data_1,
	coordinate_data_1,
	coordinate_data_1,
};

static inline int get_hbm_index(int idx)
{
	int i = 0;
	int idx_list[] = {
		40000	/* idx < 40000: HBM_OFF */
				/* idx >= 40000: HBM_ON */
	};

	while (i < ARRAY_SIZE(idx_list)) {
		if (idx < idx_list[i])
			break;
		i++;
	}

	return i;
}

static unsigned char GRAYSCALE_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0xb3, /* ascr_Cr */
	0x4c, /* ascr_Rr */
	0xb3, /* ascr_Cg */
	0x4c, /* ascr_Rg */
	0xb3, /* ascr_Cb */
	0x4c, /* ascr_Rb */
	0x69, /* ascr_Mr */
	0x96, /* ascr_Gr */
	0x69, /* ascr_Mg */
	0x96, /* ascr_Gg */
	0x69, /* ascr_Mb */
	0x96, /* ascr_Gb */
	0xe2, /* ascr_Yr */
	0x1d, /* ascr_Br */
	0xe2, /* ascr_Yg */
	0x1d, /* ascr_Bg */
	0xe2, /* ascr_Yb */
	0x1d, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char GRAYSCALE_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char GRAYSCALE_NEGATIVE_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x4c, /* ascr_Cr */
	0xb3, /* ascr_Rr */
	0x4c, /* ascr_Cg */
	0xb3, /* ascr_Rg */
	0x4c, /* ascr_Cb */
	0xb3, /* ascr_Rb */
	0x96, /* ascr_Mr */
	0x69, /* ascr_Gr */
	0x96, /* ascr_Mg */
	0x69, /* ascr_Gg */
	0x96, /* ascr_Mb */
	0x69, /* ascr_Gb */
	0x1d, /* ascr_Yr */
	0xe2, /* ascr_Br */
	0x1d, /* ascr_Yg */
	0xe2, /* ascr_Bg */
	0x1d, /* ascr_Yb */
	0xe2, /* ascr_Bb */
	0x00, /* ascr_Wr */
	0xff, /* ascr_Kr */
	0x00, /* ascr_Wg */
	0xff, /* ascr_Kg */
	0x00, /* ascr_Wb */
	0xff, /* ascr_Kb */
	/* end */
};

static unsigned char GRAYSCALE_NEGATIVE_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

////////////////// UI /// /////////////////////
static unsigned char SCREEN_CURTAIN_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0x00, /* ascr_Rr */
	0x00, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0x00, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0x00, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0x00, /* ascr_Gg */
	0x00, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0x00, /* ascr_Yr */
	0x00, /* ascr_Br */
	0x00, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0x00, /* ascr_Bb */
	0x00, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0x00, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0x00, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char SCREEN_CURTAIN_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char STANDARD_UI_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_UI_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_UI_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_UI_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_UI_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x03, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_UI_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_UI_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_UI_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_UI_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_UI_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

////////////////// GALLERY /////////////////////
static unsigned char STANDARD_GALLERY_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_GALLERY_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_GALLERY_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_GALLERY_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_GALLERY_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x07, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_GALLERY_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_GALLERY_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_GALLERY_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_GALLERY_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x0c, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x36, /* ascr_skin_Rg */
	0x43, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xe0, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xf6, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xd8, /* ascr_Mr */
	0x3b, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xd9, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x14, /* ascr_Br */
	0xf9, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_GALLERY_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

////////////////// VIDEO /////////////////////
static unsigned char STANDARD_VIDEO_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0x40,
	0x00, /* de_maxminus 11 */
	0x40,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_VIDEO_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_VIDEO_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0x40,
	0x00, /* de_maxminus 11 */
	0x40,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_VIDEO_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_VIDEO_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x07, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0x40,
	0x00, /* de_maxminus 11 */
	0x40,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_VIDEO_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_VIDEO_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_VIDEO_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_VIDEO_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x0f, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0x40,
	0x00, /* de_maxminus 11 */
	0x40,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_VIDEO_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

////////////////// VT /////////////////////
static unsigned char STANDARD_VT_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_VT_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_VT_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_VT_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_VT_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x07, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_VT_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_VT_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_VT_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char BYPASS_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char BYPASS_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x00, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_VT_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x0c, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_VT_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

////////////////// CAMERA /////////////////////
static unsigned char STANDARD_CAMERA_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_CAMERA_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_CAMERA_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_CAMERA_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_CAMERA_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x03, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_CAMERA_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_CAMERA_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_CAMERA_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x00, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_CAMERA_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x36, /* ascr_skin_Rg */
	0x43, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xe0, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xf6, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xd8, /* ascr_Mr */
	0x3b, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xd9, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x14, /* ascr_Br */
	0xf9, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_CAMERA_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NEGATIVE_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0xff, /* ascr_Cr */
	0x00, /* ascr_Rr */
	0x00, /* ascr_Cg */
	0xff, /* ascr_Rg */
	0x00, /* ascr_Cb */
	0xff, /* ascr_Rb */
	0x00, /* ascr_Mr */
	0xff, /* ascr_Gr */
	0xff, /* ascr_Mg */
	0x00, /* ascr_Gg */
	0x00, /* ascr_Mb */
	0xff, /* ascr_Gb */
	0x00, /* ascr_Yr */
	0xff, /* ascr_Br */
	0x00, /* ascr_Yg */
	0xff, /* ascr_Bg */
	0xff, /* ascr_Yb */
	0x00, /* ascr_Bb */
	0x00, /* ascr_Wr */
	0xff, /* ascr_Kr */
	0x00, /* ascr_Wg */
	0xff, /* ascr_Kg */
	0x00, /* ascr_Wb */
	0xff, /* ascr_Kb */
	/* end */
};

static unsigned char NEGATIVE_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char COLOR_BLIND_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char COLOR_BLIND_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char LIGHT_NOTIFICATION_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x66, //ascr_Cr
	0xff, //ascr_Rr
	0xf9, //ascr_Cg
	0x60, //ascr_Rg
	0xac, //ascr_Cb
	0x13, //ascr_Rb
	0xff, //ascr_Mr
	0x66, //ascr_Gr
	0x60, //ascr_Mg
	0xf9, //ascr_Gg
	0xac, //ascr_Mb
	0x13, //ascr_Gb
	0xff, //ascr_Yr
	0x66, //ascr_Br
	0xf9, //ascr_Yg
	0x60, //ascr_Bg
	0x13, //ascr_Yb
	0xac, //ascr_Bb
	0xff, //ascr_Wr
	0x66, //ascr_Kr
	0xf9, //ascr_Wg
	0x60, //ascr_Kg
	0xac, //ascr_Wb
	0x13, //ascr_Kb
	/* end */
};

static unsigned char LIGHT_NOTIFICATION_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

////////////////// BROWSER /////////////////////
static unsigned char STANDARD_BROWSER_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_BROWSER_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_BROWSER_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_BROWSER_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_BROWSER_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x03, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_BROWSER_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_BROWSER_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_BROWSER_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_BROWSER_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x17, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x27, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x59,
	0x0b,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x34,
	0x83,
	0xff, /* ascr_skin_Rr */
	0x5c, /* ascr_skin_Rg */
	0x70, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf8, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_BROWSER_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

////////////////// eBOOK /////////////////////
static unsigned char DYNAMIC_EBOOK_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x03, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_EBOOK_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char STANDARD_EBOOK_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_EBOOK_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_EBOOK_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_EBOOK_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_EBOOK_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_EBOOK_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_EBOOK_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xf5, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xe4, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_EBOOK_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_EMAIL_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xf8, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xec, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_EMAIL_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

////////////////// DMB /////////////////////
static unsigned char STANDARD_DMB_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, //ascr_Cr
	0xf6, //ascr_Rr
	0xf1, //ascr_Cg
	0x30, //ascr_Rg
	0xe6, //ascr_Cb
	0x30, //ascr_Rb
	0xfe, //ascr_Mr
	0x00, //ascr_Gr
	0x4a, //ascr_Mg
	0xf0, //ascr_Gg
	0xe8, //ascr_Mb
	0x30, //ascr_Gb
	0xef, //ascr_Yr
	0x2e, //ascr_Br
	0xef, //ascr_Yg
	0x36, //ascr_Bg
	0x47, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char STANDARD_DMB_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char NATURAL_DMB_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x10,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x40, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x9b, //ascr_Cr
	0xd0, //ascr_Rr
	0xf2, //ascr_Cg
	0x29, //ascr_Rg
	0xe9, //ascr_Cb
	0x27, //ascr_Rb
	0xde, //ascr_Mr
	0x8e, //ascr_Gr
	0x48, //ascr_Mg
	0xe3, //ascr_Gg
	0xe0, //ascr_Mb
	0x50, //ascr_Gb
	0xf3, //ascr_Yr
	0x2e, //ascr_Br
	0xec, //ascr_Yg
	0x34, //ascr_Bg
	0x5a, //ascr_Yb
	0xd8, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xef, //ascr_Wb
	0x00, //ascr_Kb
	/* end */
};

static unsigned char NATURAL_DMB_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char DYNAMIC_DMB_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x07, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x20,
	0x00, /* curve_1_b */
	0x14, /* curve_1_a */
	0x00, /* curve_2_b */
	0x14, /* curve_2_a */
	0x00, /* curve_3_b */
	0x14, /* curve_3_a */
	0x00, /* curve_4_b */
	0x14, /* curve_4_a */
	0x03, /* curve_5_b */
	0x9a, /* curve_5_a */
	0x03, /* curve_6_b */
	0x9a, /* curve_6_a */
	0x03, /* curve_7_b */
	0x9a, /* curve_7_a */
	0x03, /* curve_8_b */
	0x9a, /* curve_8_a */
	0x07, /* curve_9_b */
	0x9e, /* curve_9_a */
	0x07, /* curve10_b */
	0x9e, /* curve10_a */
	0x07, /* curve11_b */
	0x9e, /* curve11_a */
	0x07, /* curve12_b */
	0x9e, /* curve12_a */
	0x0a, /* curve13_b */
	0xa0, /* curve13_a */
	0x0a, /* curve14_b */
	0xa0, /* curve14_a */
	0x0a, /* curve15_b */
	0xa0, /* curve15_a */
	0x0a, /* curve16_b */
	0xa0, /* curve16_a */
	0x16, /* curve17_b */
	0xa6, /* curve17_a */
	0x16, /* curve18_b */
	0xa6, /* curve18_a */
	0x16, /* curve19_b */
	0xa6, /* curve19_a */
	0x16, /* curve20_b */
	0xa6, /* curve20_a */
	0x05, /* curve21_b */
	0x21, /* curve21_a */
	0x0b, /* curve22_b */
	0x20, /* curve22_a */
	0x87, /* curve23_b */
	0x0f, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x37, /* ascr_dist_up */
	0x29, /* ascr_dist_down */
	0x19, /* ascr_dist_right */
	0x47, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x25,
	0x3d,
	0x00, /* ascr_div_down */
	0x31,
	0xf4,
	0x00, /* ascr_div_right */
	0x51,
	0xec,
	0x00, /* ascr_div_left */
	0x1c,
	0xd8,
	0xff, /* ascr_skin_Rr */
	0x64, /* ascr_skin_Rg */
	0x78, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xff, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xff, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf4, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char DYNAMIC_DMB_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char MOVIE_DMB_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x00, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x00,
	0x07, /* de_maxplus 11 */
	0xff,
	0x07, /* de_maxminus 11 */
	0xff,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x02, /* curve_5_b */
	0x1b, /* curve_5_a */
	0x02, /* curve_6_b */
	0x1b, /* curve_6_a */
	0x02, /* curve_7_b */
	0x1b, /* curve_7_a */
	0x02, /* curve_8_b */
	0x1b, /* curve_8_a */
	0x09, /* curve_9_b */
	0xa6, /* curve_9_a */
	0x09, /* curve10_b */
	0xa6, /* curve10_a */
	0x09, /* curve11_b */
	0xa6, /* curve11_a */
	0x09, /* curve12_b */
	0xa6, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x67, /* ascr_skin_cb */
	0xa9, /* ascr_skin_cr */
	0x0c, /* ascr_dist_up */
	0x0c, /* ascr_dist_down */
	0x0c, /* ascr_dist_right */
	0x0c, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0xaa,
	0xab,
	0x00, /* ascr_div_down */
	0xaa,
	0xab,
	0x00, /* ascr_div_right */
	0xaa,
	0xab,
	0x00, /* ascr_div_left */
	0xaa,
	0xab,
	0xd5, /* ascr_skin_Rr */
	0x2c, /* ascr_skin_Rg */
	0x2a, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf5, /* ascr_skin_Yg */
	0x63, /* ascr_skin_Yb */
	0xfe, /* ascr_skin_Mr */
	0x4a, /* ascr_skin_Mg */
	0xff, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xf9, /* ascr_skin_Wg */
	0xf8, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xff, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xff, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xff, /* ascr_Mr */
	0x00, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xff, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x00, /* ascr_Br */
	0xff, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char MOVIE_DMB_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x30, /* ascr algo lce 10 10 10 */
};

static unsigned char AUTO_DMB_1[] = {
	0xEC,
	0x98, /* lce_on gain 0 00 0000 */
	0x24, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xb3, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x03, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x0c, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x28,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x01,
	0x00, /* fa_step_n 10 */
	0x01,
	0x00, /* fa_max_de_gain 10 */
	0x28,
	0x00, /* fa_pcl_ppi 14 */
	0x01,
	0x28, /* fa_os_cnt_10_co */
	0x3c, /* fa_os_cnt_20_co */
	0xa9, /* fa_skin_cr */
	0x67, /* fa_skin_cb */
	0x27, /* fa_dist_left */
	0x19, /* fa_dist_right */
	0x29, /* fa_dist_down */
	0x17, /* fa_dist_up */
	0x01, /* fa_div_dist_left */
	0xa4,
	0x02, /* fa_div_dist_right */
	0x8f,
	0x01, /* fa_div_dist_down */
	0x90,
	0x02, /* fa_div_dist_up */
	0xc8,
	0x20, /* fa_px_min_weight */
	0x20, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x00,
	0x00, /* curve_1_b */
	0x20, /* curve_1_a */
	0x00, /* curve_2_b */
	0x20, /* curve_2_a */
	0x00, /* curve_3_b */
	0x20, /* curve_3_a */
	0x00, /* curve_4_b */
	0x20, /* curve_4_a */
	0x00, /* curve_5_b */
	0x20, /* curve_5_a */
	0x00, /* curve_6_b */
	0x20, /* curve_6_a */
	0x00, /* curve_7_b */
	0x20, /* curve_7_a */
	0x00, /* curve_8_b */
	0x20, /* curve_8_a */
	0x00, /* curve_9_b */
	0x20, /* curve_9_a */
	0x00, /* curve10_b */
	0x20, /* curve10_a */
	0x00, /* curve11_b */
	0x20, /* curve11_a */
	0x00, /* curve12_b */
	0x20, /* curve12_a */
	0x00, /* curve13_b */
	0x20, /* curve13_a */
	0x00, /* curve14_b */
	0x20, /* curve14_a */
	0x00, /* curve15_b */
	0x20, /* curve15_a */
	0x00, /* curve16_b */
	0x20, /* curve16_a */
	0x00, /* curve17_b */
	0x20, /* curve17_a */
	0x00, /* curve18_b */
	0x20, /* curve18_a */
	0x00, /* curve19_b */
	0x20, /* curve19_a */
	0x00, /* curve20_b */
	0x20, /* curve20_a */
	0x00, /* curve21_b */
	0x20, /* curve21_a */
	0x00, /* curve22_b */
	0x20, /* curve22_a */
	0x00, /* curve23_b */
	0x20, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x30, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xe0, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xf6, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xd8, /* ascr_Mr */
	0x3b, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xd9, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x14, /* ascr_Br */
	0xf9, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char AUTO_DMB_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3c, /* ascr algo lce 10 10 10 */
};

static unsigned char LOCAL_CE_1[] = {
	0xEC,
	0x86, /* lce_on gain 0 00 0000 */
	0x0c, /* lce_color_gain 00 0000 */
	0x00, /* lce_scene_trans 0000 */
	0xf0, /* lce_illum_gain */
	0x01, /* lce_ref_offset 9 */
	0x0e,
	0x01, /* lce_ref_gain 9 */
	0x00,
	0x66, /* lce_block_size h v 000 000 */
	0x17, /* lce_black reduct_slope 0 0000 */
	0x00, /* lce_dark_th 000 */
	0x96, /* lce_min_ref_offset */
	0x04, /* nr fa de cs gamma 0 0000 */
	0xff, /* nr_mask_th */
	0x00, /* de_gain 10 */
	0x30,
	0x00, /* de_maxplus 11 */
	0xa0,
	0x00, /* de_maxminus 11 */
	0xa0,
	0x14, /* fa_edge_th */
	0x00, /* fa_step_p 10 */
	0x0a,
	0x00, /* fa_step_n 10 */
	0x32,
	0x01, /* fa_max_de_gain 10 */
	0xf4,
	0x0b, /* fa_pcl_ppi 14 */
	0x8a,
	0x20, /* fa_os_cnt_10_co */
	0x2d, /* fa_os_cnt_20_co */
	0x6e, /* fa_skin_cr */
	0x99, /* fa_skin_cb */
	0x1b, /* fa_dist_left */
	0x17, /* fa_dist_right */
	0x14, /* fa_dist_down */
	0x1e, /* fa_dist_up */
	0x02, /* fa_div_dist_left */
	0x5f,
	0x02, /* fa_div_dist_right */
	0xc8,
	0x03, /* fa_div_dist_down */
	0x33,
	0x02, /* fa_div_dist_up */
	0x22,
	0x10, /* fa_px_min_weight */
	0x10, /* fa_fr_min_weight */
	0x07, /* fa_skin_zone_w */
	0x07, /* fa_skin_zone_h */
	0x01, /* cs_gain 10 */
	0x40,
	0x00, /* curve_1_b */
	0x6b, /* curve_1_a */
	0x03, /* curve_2_b */
	0x48, /* curve_2_a */
	0x08, /* curve_3_b */
	0x32, /* curve_3_a */
	0x08, /* curve_4_b */
	0x32, /* curve_4_a */
	0x08, /* curve_5_b */
	0x32, /* curve_5_a */
	0x08, /* curve_6_b */
	0x32, /* curve_6_a */
	0x08, /* curve_7_b */
	0x32, /* curve_7_a */
	0x10, /* curve_8_b */
	0x28, /* curve_8_a */
	0x10, /* curve_9_b */
	0x28, /* curve_9_a */
	0x10, /* curve10_b */
	0x28, /* curve10_a */
	0x10, /* curve11_b */
	0x28, /* curve11_a */
	0x10, /* curve12_b */
	0x28, /* curve12_a */
	0x19, /* curve13_b */
	0x22, /* curve13_a */
	0x19, /* curve14_b */
	0x22, /* curve14_a */
	0x19, /* curve15_b */
	0x22, /* curve15_a */
	0x19, /* curve16_b */
	0x22, /* curve16_a */
	0x19, /* curve17_b */
	0x22, /* curve17_a */
	0x19, /* curve18_b */
	0x22, /* curve18_a */
	0x23, /* curve19_b */
	0x1e, /* curve19_a */
	0x2e, /* curve20_b */
	0x1b, /* curve20_a */
	0x33, /* curve21_b */
	0x1a, /* curve21_a */
	0x40, /* curve22_b */
	0x18, /* curve22_a */
	0x48, /* curve23_b */
	0x17, /* curve23_a */
	0x00, /* curve24_b */
	0xFF, /* curve24_a */
	0x00, /* linear_on ascr_skin_on strength 0 0 00000 */
	0x6a, /* ascr_skin_cb */
	0x9a, /* ascr_skin_cr */
	0x25, /* ascr_dist_up */
	0x1a, /* ascr_dist_down */
	0x16, /* ascr_dist_right */
	0x2a, /* ascr_dist_left */
	0x00, /* ascr_div_up 20 */
	0x37,
	0x5a,
	0x00, /* ascr_div_down */
	0x4e,
	0xc5,
	0x00, /* ascr_div_right */
	0x5d,
	0x17,
	0x00, /* ascr_div_left */
	0x30,
	0xc3,
	0xff, /* ascr_skin_Rr */
	0x38, /* ascr_skin_Rg */
	0x48, /* ascr_skin_Rb */
	0xff, /* ascr_skin_Yr */
	0xf0, /* ascr_skin_Yg */
	0x00, /* ascr_skin_Yb */
	0xd8, /* ascr_skin_Mr */
	0x00, /* ascr_skin_Mg */
	0xd9, /* ascr_skin_Mb */
	0xff, /* ascr_skin_Wr */
	0xff, /* ascr_skin_Wg */
	0xff, /* ascr_skin_Wb */
	0x00, /* ascr_Cr */
	0xe0, /* ascr_Rr */
	0xff, /* ascr_Cg */
	0x00, /* ascr_Rg */
	0xf6, /* ascr_Cb */
	0x00, /* ascr_Rb */
	0xd8, /* ascr_Mr */
	0x3b, /* ascr_Gr */
	0x00, /* ascr_Mg */
	0xff, /* ascr_Gg */
	0xd9, /* ascr_Mb */
	0x00, /* ascr_Gb */
	0xff, /* ascr_Yr */
	0x14, /* ascr_Br */
	0xf9, /* ascr_Yg */
	0x00, /* ascr_Bg */
	0x00, /* ascr_Yb */
	0xff, /* ascr_Bb */
	0xff, /* ascr_Wr */
	0x00, /* ascr_Kr */
	0xff, /* ascr_Wg */
	0x00, /* ascr_Kg */
	0xff, /* ascr_Wb */
	0x00, /* ascr_Kb */
	/* end */
};

static unsigned char LOCAL_CE_2[] = {
	/* start */
	0xEB,
	0x01, /* mdnie_en */
	0x00, /* data_width mask 00 0000 */
	0x3f, /* ascr algo lce 10 10 10 */
};


static unsigned char LEVEL_UNLOCK[] = {
	0xF0,
	0x5A, 0x5A
};

static unsigned char LEVEL_LOCK[] = {
	0xF0,
	0xA5, 0xA5
};

#define MDNIE_SET(id)	\
{							\
	.name		= #id,				\
	.update_flag	= {0, 1, 2, 0},			\
	.seq		= {				\
		{	.cmd = LEVEL_UNLOCK,	.len = ARRAY_SIZE(LEVEL_UNLOCK),	.sleep = 0,},	\
		{	.cmd = id##_1,		.len = ARRAY_SIZE(id##_1),		.sleep = 0,},	\
		{	.cmd = id##_2,		.len = ARRAY_SIZE(id##_2),		.sleep = 0,},	\
		{	.cmd = LEVEL_LOCK,	.len = ARRAY_SIZE(LEVEL_LOCK),		.sleep = 0,},	\
	}	\
}

static struct mdnie_table bypass_table[BYPASS_MAX] = {
	[BYPASS_ON] = MDNIE_SET(BYPASS)
};

static struct mdnie_table light_notification_table[LIGHT_NOTIFICATION_MAX] = {
	[LIGHT_NOTIFICATION_ON] = MDNIE_SET(LIGHT_NOTIFICATION)
};

static struct mdnie_table accessibility_table[ACCESSIBILITY_MAX] = {
	[NEGATIVE] = MDNIE_SET(NEGATIVE),
	MDNIE_SET(COLOR_BLIND),
	MDNIE_SET(SCREEN_CURTAIN),
	MDNIE_SET(GRAYSCALE),
	MDNIE_SET(GRAYSCALE_NEGATIVE)
};

static struct mdnie_table hbm_table[HBM_MAX] = {
	[HBM_ON] = MDNIE_SET(LOCAL_CE)
};

static struct mdnie_table dmb_table[MODE_MAX] = {
	MDNIE_SET(DYNAMIC_DMB),
	MDNIE_SET(STANDARD_DMB),
	MDNIE_SET(NATURAL_DMB),
	MDNIE_SET(MOVIE_DMB),
	MDNIE_SET(AUTO_DMB),
	MDNIE_SET(AUTO_EBOOK)
};

static struct mdnie_table main_table[SCENARIO_MAX][MODE_MAX] = {
	{
		MDNIE_SET(DYNAMIC_UI),
		MDNIE_SET(STANDARD_UI),
		MDNIE_SET(NATURAL_UI),
		MDNIE_SET(MOVIE_UI),
		MDNIE_SET(AUTO_UI),
		MDNIE_SET(AUTO_EBOOK)
	}, {
		MDNIE_SET(DYNAMIC_VIDEO),
		MDNIE_SET(STANDARD_VIDEO),
		MDNIE_SET(NATURAL_VIDEO),
		MDNIE_SET(MOVIE_VIDEO),
		MDNIE_SET(AUTO_VIDEO),
		MDNIE_SET(AUTO_EBOOK)
	},
	[CAMERA_MODE] = {
		MDNIE_SET(DYNAMIC_CAMERA),
		MDNIE_SET(STANDARD_CAMERA),
		MDNIE_SET(NATURAL_CAMERA),
		MDNIE_SET(MOVIE_CAMERA),
		MDNIE_SET(AUTO_CAMERA),
		MDNIE_SET(AUTO_EBOOK)
	},
	[GALLERY_MODE] = {
		MDNIE_SET(DYNAMIC_GALLERY),
		MDNIE_SET(STANDARD_GALLERY),
		MDNIE_SET(NATURAL_GALLERY),
		MDNIE_SET(MOVIE_GALLERY),
		MDNIE_SET(AUTO_GALLERY),
		MDNIE_SET(AUTO_EBOOK)
	}, {
		MDNIE_SET(DYNAMIC_VT),
		MDNIE_SET(STANDARD_VT),
		MDNIE_SET(NATURAL_VT),
		MDNIE_SET(MOVIE_VT),
		MDNIE_SET(AUTO_VT),
		MDNIE_SET(AUTO_EBOOK)
	}, {
		MDNIE_SET(DYNAMIC_BROWSER),
		MDNIE_SET(STANDARD_BROWSER),
		MDNIE_SET(NATURAL_BROWSER),
		MDNIE_SET(MOVIE_BROWSER),
		MDNIE_SET(AUTO_BROWSER),
		MDNIE_SET(AUTO_EBOOK)
	}, {
		MDNIE_SET(DYNAMIC_EBOOK),
		MDNIE_SET(STANDARD_EBOOK),
		MDNIE_SET(NATURAL_EBOOK),
		MDNIE_SET(MOVIE_EBOOK),
		MDNIE_SET(AUTO_EBOOK),
		MDNIE_SET(AUTO_EBOOK)
	}, {
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EBOOK)
	}
};

#undef MDNIE_SET

static struct mdnie_tune tune_info = {
	.bypass_table = bypass_table,
	.accessibility_table = accessibility_table,
	.light_notification_table = light_notification_table,
	.hbm_table = hbm_table,
	.dmb_table = dmb_table,
	.main_table = main_table,

	.coordinate_table = coordinate_data,
	.scr_info = &scr_info,
	.get_hbm_index = get_hbm_index,
	.color_offset = {NULL, color_offset_f1, color_offset_f2, color_offset_f3, color_offset_f4}
};

#endif
