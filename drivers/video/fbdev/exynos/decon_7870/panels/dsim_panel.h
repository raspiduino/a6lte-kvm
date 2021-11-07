/*
 * Copyright (c) Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __DSIM_PANEL__
#define __DSIM_PANEL__


extern unsigned int lcdtype;

extern struct mipi_dsim_lcd_driver *mipi_lcd_driver;

#if defined(CONFIG_PANEL_EA8064G_DYNAMIC)
extern struct mipi_dsim_lcd_driver ea8064g_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E3FA3_J7XE)
extern struct mipi_dsim_lcd_driver s6e3fa3_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_EA8061S_J7XE)
extern struct mipi_dsim_lcd_driver ea8061_mipi_lcd_driver;
extern struct mipi_dsim_lcd_driver ea8061s_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_LTL101AL06)
extern struct mipi_dsim_lcd_driver ltl101al06_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6D7AA0)
extern struct mipi_dsim_lcd_driver s6d7aa0_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_HX8279D)
extern struct mipi_dsim_lcd_driver hx8279d_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6D7AA0_BV055HDM)
extern struct mipi_dsim_lcd_driver s6d7aa0_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E3AA2_AMS474KF09)
extern struct mipi_dsim_lcd_driver s6e3aa2_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_TD4300)
extern struct mipi_dsim_lcd_driver td4300_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E3AA2_A3Y17)
extern struct mipi_dsim_lcd_driver s6e3aa2_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E8AA5X01)
extern struct mipi_dsim_lcd_driver s6e8aa5x01_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_TD4100_J7POP)
extern struct mipi_dsim_lcd_driver td4100_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E3FA3_J7Y17)
extern struct mipi_dsim_lcd_driver s6e3fa3_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_EA8061S_J7VE)
extern struct mipi_dsim_lcd_driver ea8061_mipi_lcd_driver;
extern struct mipi_dsim_lcd_driver ea8061s_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6D7AA0_GTACTIVE2)
extern struct mipi_dsim_lcd_driver s6d7aa0_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6D78A0_GPPIRIS)
extern struct mipi_dsim_lcd_driver s6d78a0_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6D7AT0B_J7TOP)
extern struct mipi_dsim_lcd_driver s6d7at0b_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E8AA5X01_A6LTE)
extern struct mipi_dsim_lcd_driver s6e8aa5x01_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6E8AA5X01_J6Y18)
extern struct mipi_dsim_lcd_driver s6e8aa5x01_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_S6D7AT0B_M10LTE)
extern struct mipi_dsim_lcd_driver s6d7at0b_mipi_lcd_driver;
#elif defined(CONFIG_PANEL_TD4101_A2CORELTE)
extern struct mipi_dsim_lcd_driver td4101_mipi_lcd_driver;
#endif

extern int dsim_panel_ops_init(struct dsim_device *dsim);
extern int register_lcd_driver(struct mipi_dsim_lcd_driver *drv);

#endif
