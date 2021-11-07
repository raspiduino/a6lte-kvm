/*
 *  Copyright (C) 2010, Imagis Technology Co. Ltd. All Rights Reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#ifndef __IST30XXC_H__
#define __IST30XXC_H__

#ifdef USE_TSP_TA_CALLBACKS
#include <linux/input/tsp_ta_callback.h>
#endif

#if defined(CONFIG_VBUS_NOTIFIER) || defined(CONFIG_MUIC_NOTIFIER)
#include <linux/muic/muic.h>
#include <linux/muic/muic_notifier.h>
#include <linux/vbus_notifier.h>
#endif

#ifdef CONFIG_INPUT_BOOSTER
#include <linux/input/input_booster.h>
#endif

extern unsigned int lcdtype;

#define USE_OPEN_CLOSE

/*
 * Support F/W ver : IST30xxC v1.0.0.0
 * Support IC : IST3026C, IST3032C
 * Release : 2015.01.05 by Hoony
 */

#define IMAGIS_DD_VERSION		("2.0.0.0")

#define IMAGIS_IST3026C			(1) /* 3026C */
#define IMAGIS_IST3032C			(2) /* 3032C */
#define IMAGIS_IST3038C			(3) /* 3038C */
#define IMAGIS_IST3044C			(4) /* 3044C */
#define IMAGIS_IST3048C			(5) /* 3048C */

#if defined(CONFIG_TOUCHSCREEN_IST3026C)
#define IMAGIS_TSP_IC			IMAGIS_IST3026C
#elif defined(CONFIG_TOUCHSCREEN_IST3032C)
#define IMAGIS_TSP_IC			IMAGIS_IST3032C
#endif

/* SEC defined [*/
#define FIRMWARE_PATH_LENGTH		64
#define FIRMWARE_PATH			"tsp_imagis/"
/* SEC defined ] */

#define TSP_CHIP_VENDOR			("IMAGIS")

#define IMAGIS_PROTOCOL_A		(0xA)
#define IMAGIS_PROTOCOL_B		(0xB)
#define IMAGIS_PROTOCOL_TYPE		IMAGIS_PROTOCOL_B

#define IST30XXC_DEFAULT_CHIP_ID	(0x300C)
#define IST3048C_DEFAULT_CHIP_ID	(0x3048)
#if (IMAGIS_TSP_IC == IMAGIS_IST3026C)
#define TSP_CHIP_NAME			("IST3026C")
#define IST30XX_CHIP_ID			(0x026C)
#define IST30XX_NODE_TOTAL_NUM		(16 * 16)
#elif (IMAGIS_TSP_IC == IMAGIS_IST3032C)
#define TSP_CHIP_NAME			("IST3032C")
#define IST30XX_CHIP_ID			(0x032C)
#define IST30XX_NODE_TOTAL_NUM		(16 * 16)
#elif (IMAGIS_TSP_IC == IMAGIS_IST3038C)
#define TSP_CHIP_NAME			("IST3038C")
#define IST30XX_CHIP_ID			(0x038C)
#define IST30XX_NODE_TOTAL_NUM		(24 * 24)
#elif (IMAGIS_TSP_IC == IMAGIS_IST3044C)
#define TSP_CHIP_NAME			("IST3044C")
#define IST30XX_CHIP_ID			(0x044C)
#define IST30XX_NODE_TOTAL_NUM		(24 * 24)
#elif (IMAGIS_TSP_IC == IMAGIS_IST3048C)
#define TSP_CHIP_NAME			("IST3048C")
#define IST30XX_CHIP_ID			(0x048C)
#define IST30XX_NODE_TOTAL_NUM		(24 * 24)
#else
#define TSP_CHIP_NAME			("IST30XXC")
#define IST30XX_CHIP_ID			(0x300C)
#define IST30XX_NODE_TOTAL_NUM		(24 * 24)
#endif

/* IST30XX FUNCTION ENABLE & DISABLE */
#define IST30XX_INTERNAL_BIN		(1)
#define IST30XX_CHECK_CALIB		(0)
#if IST30XX_INTERNAL_BIN
#if defined(CONFIG_TOUCHSCREEN_IST3026C)	//novel
#define IST30XX_MULTIPLE_TSP		(1)
#endif
#define IST30XX_UPDATE_BY_WORKQUEUE	(0)
#define IST30XX_UPDATE_DELAY		(3 * HZ)
#endif

#define IST30XX_EVENT_MODE		(1)
#if IST30XX_EVENT_MODE
#define IST30XX_NOISE_MODE		(1)
#define IST30XX_TRACKING_MODE		(1)
#define IST30XX_ALGORITHM_MODE		(1)
#else
#define IST30XX_NOISE_MODE		(0) /* fixed */
#define IST30XX_TRACKING_MODE		(0) /* fixed */
#define IST30XX_ALGORITHM_MODE		(0) /* fixed */
#endif

#define IST30XX_TA_RESET		(1)

#if defined(CONFIG_TOUCHSCREEN_IST3026C) || defined(CONFIG_TOUCHSCREEN_IST3032C)
#define IST30XX_USE_KEY			(0)
#else
#define IST30XX_USE_KEY			(1)
#endif

#define IST30XX_DEBUG			(1)
#define IST30XX_CMCS_TEST		(1)
#define IST30XX_GESTURE			(0)
#define IST30XX_STATUS_DEBUG		(0)

#define SEC_FACTORY_MODE		(1)
/* IST30XX FUNCTION ENABLE & DISABLE */

#define IST30XX_ADDR_LEN		(4)
#define IST30XX_DATA_LEN		(4)

#define IST30XX_MAX_MT_FINGERS		(10)
#define IST30XX_MAX_KEYS		(5)

#define IST30XX_MAX_X			(480) /* LCD Resolution */
#define IST30XX_MAX_Y			(800) /* LCD Resolution */
#define IST30XX_MAX_W			(15)

#define IST30XX_EXCEPT_MASK		(0xFFFFFF00)
#define IST30XX_EXCEPT_VALUE		(0xE11CE900)
#define IST30XX_MAX_EXCEPT_SIZE		(2)

#define IST30XX_JIG_TOUCH		(0xC0)
#define IST30XX_ENABLE			(1)
#define IST30XX_DISABLE			(0)

/* retry count */
#define IST30XX_MAX_RETRY_CNT		(3)

/* Local */
#define TSP_LOCAL_EU			(0)
#define TSP_LOCAL_EEU			(1)
#define TSP_LOCAL_TD			(11)
#define TSP_LOCAL_CMCC			(12)
#define TSP_LOCAL_CU			(13)
#define TSP_LOCAL_SPRD			(14)
#define TSP_LOCAL_CTC			(15)
#define TSP_LOCAL_INDIA			(21)
#define TSP_LOCAL_SWASIA		(22)
#define TSP_LOCAL_NA			(31)
#define TSP_LOCAL_LA			(32)
#define TSP_LOCAL_CODE			TSP_LOCAL_EU

/* Factory Test for Reliability Test Group */
enum ist30xx_reliability_commands {
	TEST_RAW_ALL_DATA = 0,
	TEST_CM_ALL_DATA,
	TEST_CS_ALL_DATA,
	TEST_SLOPE0_ALL_DATA,
	TEST_SLOPE1_ALL_DATA,
};

/* Debug message */
#define DEV_ERR				(1)
#define DEV_WARN			(2)
#define DEV_INFO			(3)
#define DEV_NOTI			(4)
#define DEV_DEBUG			(5)
#define DEV_VERB			(6)

#define IST30XX_DEBUG_TAG		"[ TSP ]"
#define IST30XX_DEBUG_LEVEL		DEV_NOTI

#ifdef CONFIG_SEC_DEBUG_TSP_LOG
#include <linux/sec_debug.h>
#endif

#ifdef CONFIG_SEC_DEBUG_TSP_LOG
#define tsp_err(fmt, ...)	\
({	\
	if (IST30XX_DEBUG_LEVEL<DEV_ERR)	\
		tsp_printk(DEV_ERR, fmt, ## __VA_ARGS__);	\
	else{	\
		tsp_printk(DEV_ERR, fmt, ## __VA_ARGS__);	\
		sec_debug_tsp_log(fmt, ## __VA_ARGS__);	\
	}	\
})
#define tsp_warn(fmt, ...)	\
({	\
	if (IST30XX_DEBUG_LEVEL<DEV_WARN)		\
		tsp_printk(DEV_WARN, fmt, ## __VA_ARGS__);	\
	else{	\
		tsp_printk(DEV_WARN, fmt, ## __VA_ARGS__);	\
		sec_debug_tsp_log(fmt, ## __VA_ARGS__);	\
	}	\
})
#define tsp_info(fmt, ...)	\
({	\
	if (IST30XX_DEBUG_LEVEL<DEV_INFO)		\
		tsp_printk(DEV_INFO, fmt, ## __VA_ARGS__);	\
	else{	\
		tsp_printk(DEV_INFO, fmt, ## __VA_ARGS__);	\
		sec_debug_tsp_log(fmt, ## __VA_ARGS__);	\
	}	\
})
#define tsp_noti(fmt, ...)	\
({	\
	if (IST30XX_DEBUG_LEVEL<DEV_NOTI)		\
		tsp_printk(DEV_NOTI, fmt, ## __VA_ARGS__);	\
	else{	\
		tsp_printk(DEV_NOTI, fmt, ## __VA_ARGS__);	\
		sec_debug_tsp_log(fmt, ## __VA_ARGS__);	\
	}	\
})
#define tsp_debug(fmt, ...)	\
({	\
	if (IST30XX_DEBUG_LEVEL<DEV_DEBUG)		\
		tsp_printk(DEV_DEBUG, fmt, ## __VA_ARGS__);	\
	else{	\
		tsp_printk(DEV_DEBUG, fmt, ## __VA_ARGS__);	\
		sec_debug_tsp_log(fmt, ## __VA_ARGS__);	\
	}	\
})
#define tsp_verb(fmt, ...)	\
({	\
	if (IST30XX_DEBUG_LEVEL<DEV_VERB)		\
		tsp_printk(DEV_VERB, fmt, ## __VA_ARGS__);	\
	else{	\
		tsp_printk(DEV_VERB, fmt, ## __VA_ARGS__);	\
		sec_debug_tsp_log(fmt, ## __VA_ARGS__);	\
	}	\
})
#else
#define tsp_err(fmt, ...)		tsp_printk(DEV_ERR, fmt, ## __VA_ARGS__)
#define tsp_warn(fmt, ...)		tsp_printk(DEV_WARN, fmt, ## __VA_ARGS__)
#define tsp_info(fmt, ...)		tsp_printk(DEV_INFO, fmt, ## __VA_ARGS__)
#define tsp_noti(fmt, ...)		tsp_printk(DEV_NOTI, fmt, ## __VA_ARGS__)
#define tsp_debug(fmt, ...)		tsp_printk(DEV_DEBUG, fmt, ## __VA_ARGS__)
#define tsp_verb(fmt, ...)		tsp_printk(DEV_VERB, fmt, ## __VA_ARGS__)
#endif

/* i2c setting */
/* I2C Device info */
#define IST30XX_DEV_NAME		"IST30XX"
#define IST30XX_DEV_ID			(0xA0 >> 1)

/* I2C Mode */
#define I2C_BURST_MODE			(1)
#define I2C_MONOPOLY_MODE		(0)

/* I2C transfer msg number */
#define WRITE_CMD_MSG_LEN		(1)
#define READ_CMD_MSG_LEN		(2)

/* I2C address/Data length */
#define IST30XX_ADDR_LEN		(4) /* bytes */
#define IST30XX_DATA_LEN		(4) /* bytes */

/* I2C transaction size */
#define I2C_MAX_WRITE_SIZE		(0x0100) /* bytes */
#define I2C_MAX_READ_SIZE		(0x0080) /* bytes */

/* I2C access mode */
#define IST30XX_DIRECT_ACCESS		(1 << 31)
#define IST30XX_BURST_ACCESS		(1 << 27)
#define IST30XX_HIB_ACCESS		(0x800B << 16)
#define IST30XX_DA_ADDR(n)		(n | IST30XX_DIRECT_ACCESS)
#define IST30XX_BA_ADDR(n)		(n | IST30XX_BURST_ACCESS)
#define IST30XX_HA_ADDR(n)		(n | IST30XX_HIB_ACCESS)

/* register */
/* Info register */
#define IST30XX_REG_CHIPID		IST30XX_DA_ADDR(0x40001000)
#define IST30XX_REG_TSPTYPE		IST30XX_DA_ADDR(0x40002010)
/* SEC defined [ */
#define IST30XX_REG_XY_RES		IST30XX_DA_ADDR(0x40)
#define IST30XX_REG_XY_SWAP		IST30XX_DA_ADDR(0x5C)
/* SEC defined ] */

/* HIB register */
#define IST30XX_HIB_BASE		(0x30000100)
#define IST30XX_HIB_TOUCH_STATUS	IST30XX_HA_ADDR(IST30XX_HIB_BASE | 0x00)
#define IST30XX_HIB_INTR_MSG		IST30XX_HA_ADDR(IST30XX_HIB_BASE | 0x04)
#define IST30XX_HIB_COORD		IST30XX_HA_ADDR(IST30XX_HIB_BASE | 0x08)
#define IST30XX_HIB_CMD			IST30XX_HA_ADDR(IST30XX_HIB_BASE | 0x3C)
#define IST30XX_HIB_RW_STATUS		IST30XX_HA_ADDR(IST30XX_HIB_BASE | 0x40)

/* interrupt macro */
#define IST30XX_INTR_STATUS		(0x00000C00)
#define CHECK_INTR_STATUS(n)		(((n & IST30XX_INTR_STATUS) == IST30XX_INTR_STATUS) ? 1 : 0)
#define PARSE_FINGER_CNT(n)		((n >> 12) & 0xF)
#define PARSE_KEY_CNT(n)		((n >> 21) & 0x7)
/* Finger status: [9:0] */
#define PARSE_FINGER_STATUS(n)		(n & 0x3FF)
/* Key status: [20:16] */
#define PARSE_KEY_STATUS(n)		((n >> 16) & 0x1F)
#define PRESSED_FINGER(s, id)		((s & (1 << (id - 1))) ? true : false)
#define PRESSED_KEY(s, id)		((s & (1 << (16 + id - 1))) ? true : false)

#define IST30XX_MAX_CMD_SIZE		(0x20)
#define IST30XX_CMD_ADDR(n)		(n * 4)
#define IST30XX_CMD_VALUE(n)		(n / 4)
enum ist30xx_read_commands {
	eHCOM_GET_CHIP_ID		= IST30XX_CMD_ADDR(0x00),
	eHCOM_GET_VER_MAIN		= IST30XX_CMD_ADDR(0x01),
	eHCOM_GET_VER_FW		= IST30XX_CMD_ADDR(0x02),
	eHCOM_GET_VER_CORE		= IST30XX_CMD_ADDR(0x03),
	eHCOM_GET_VER_TEST		= IST30XX_CMD_ADDR(0x04),
	eHCOM_GET_CRC32			= IST30XX_CMD_ADDR(0x05),
	eHCOM_GET_CRC32_ALL		= IST30XX_CMD_ADDR(0x06),
	eHCOM_GET_CAL_RESULT		= IST30XX_CMD_ADDR(0x07),
	eHCOM_GET_TSP_VENDOR		= IST30XX_CMD_ADDR(0x08),

	eHCOM_GET_LCD_INFO		= IST30XX_CMD_ADDR(0x10),
	eHCOM_GET_TSP_INFO		= IST30XX_CMD_ADDR(0x11),
	eHCOM_GET_KEY_INFO_0		= IST30XX_CMD_ADDR(0x12),
	eHCOM_GET_KEY_INFO_1		= IST30XX_CMD_ADDR(0x13),
	eHCOM_GET_KEY_INFO_2		= IST30XX_CMD_ADDR(0x14),
	eHCOM_GET_SCR_INFO		= IST30XX_CMD_ADDR(0x15),
	eHCOM_GET_GTX_INFO		= IST30XX_CMD_ADDR(0x16),
	eHCOM_GET_SWAP_INFO		= IST30XX_CMD_ADDR(0x17),
	eHCOM_GET_FINGER_INFO		= IST30XX_CMD_ADDR(0x18),
	eHCOM_GET_BASELINE		= IST30XX_CMD_ADDR(0x19),
	eHCOM_GET_TOUCH_TH		= IST30XX_CMD_ADDR(0x1A),

	eHCOM_GET_ZVALUE_BASE		= IST30XX_CMD_ADDR(0x1C),
	eHCOM_GET_CDC_BASE		= IST30XX_CMD_ADDR(0x1D),
	eHCOM_GET_ALGO_BASE		= IST30XX_CMD_ADDR(0x1E),
	eHCOM_GET_COM_CHECKSUM		= IST30XX_CMD_ADDR(0x1F),
};

enum ist30xx_write_commands {
	eHCOM_FW_START			= 0x01,
	eHCOM_FW_HOLD			= 0x02,

	eHCOM_CP_CORRECT_EN		= 0x10,
	eHCOM_WDT_EN			= 0x11,
	eHCOM_GESTURE_EN		= 0x12,
	eHCOM_SCALE_EN			= 0x13,
	eHCOM_NEW_POSITION_DIS		= 0x14,
	eHCOM_SLEEP_MODE_EN		= 0x15,

	eHCOM_SET_TIME_ACTIVE		= 0x20,
	eHCOM_SET_TIME_IDLE		= 0x21,
	eHCOM_SET_MODE_SPECIAL		= 0x22,
	eHCOM_SET_LOCAL_MODEL		= 0x23,

	eHCOM_RUN_RAMCODE		= 0x30,
	eHCOM_RUN_CAL_AUTO		= 0x31,
	eHCOM_RUN_CAL_PARAM		= 0x32,

	eHCOM_SET_JIG_MODE		= 0x80,
	eHCOM_SET_JIG_SENSITI		= 0x81,

	eHCOM_DEFAULT			= 0xFF,
};

typedef union {
	struct {
		u32 y:12;
		u32 x:12;
		u32 area:4;
		u32 id:4;
	} bit_field;
	u32 full_field;
} finger_info;

struct ist30xx_status {
	int power;
	int update;
	int update_result;
	int calib;
	int calib_msg;
	u32 cmcs;
	bool event_mode;
	bool noise_mode;
};

struct ist30xx_version {
	u32 main_ver;
	u32 fw_ver;
	u32 core_ver;
	u32 test_ver;
};

struct ist30xx_fw {
	struct ist30xx_version prev;
	struct ist30xx_version cur;
	struct ist30xx_version bin;
	u32 index;
	u32 size;
	u32 chksum;
	u32 buf_size;
	u8 *buf;
};

#define IST30XX_TAG_MAGIC		"ISTV2TAG"
struct ist30xx_tags {
	char magic1[8];
	u32 rom_base;
	u32 ram_base;
	u32 reserved0;
	u32 reserved1;

	u32 fw_addr;
	u32 fw_size;
	u32 cfg_addr;
	u32 cfg_size;
	u32 sensor_addr;
	u32 sensor_size;
	u32 cp_addr;
	u32 cp_size;
	u32 flag_addr;
	u32 flag_size;
	u32 reserved2;
	u32 reserved3;

	u32 zvalue_base;
	u32 algo_base;
	u32 raw_base;
	u32 filter_base;
	u32 reserved4;
	u32 reserved5;

	u32 chksum;
	u32 chksum_all;
	u32 reserved6;
	u32 reserved7;

	u8 day;
	u8 month;
	u16 year;
	u8 hour;
	u8 min;
	u8 sec;
	u8 reserved8;
	char magic2[8];
};

struct ist30xx_platform_data {
	int max_x;
	int max_y;
	int max_w;
	int irq_flag;
	int avdd_volt;
	struct regulator *avdd_regulator;
};

struct CH_NUM {
	u8 tx;
	u8 rx;
};

struct GTX_INFO {
	u8 num;
	u8 ch_num[4];
};

struct TSP_NODE_BUF {
	u16 raw[IST30XX_NODE_TOTAL_NUM];
	u16 base[IST30XX_NODE_TOTAL_NUM];
	u16 filter[IST30XX_NODE_TOTAL_NUM];
	u16 min_raw;
	u16 max_raw;
	u16 min_base;
	u16 max_base;
	u16 len;
};

struct TSP_DIRECTION {
	bool swap_xy;
	bool flip_x;
	bool flip_y;
};

typedef struct _TSP_INFO {
	struct CH_NUM ch_num;
	struct CH_NUM screen;
	struct GTX_INFO	gtx;
	struct TSP_DIRECTION dir;
	struct TSP_NODE_BUF node;
	int height;
	int width;
	int finger_num;
	u16 baseline;
} TSP_INFO;

typedef struct _TKEY_INFO {
	int key_num;
	bool enable;
	struct CH_NUM ch_num[IST30XX_MAX_KEYS];
	u16 baseline;
} TKEY_INFO;

#if SEC_FACTORY_MODE
#include "ist30xxc_sec.h"
#endif

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif

struct ist30xx_dt_data {
	int irq_gpio;
	int touch_en_gpio;
	const char *tsp_vdd_name;
	struct regulator *tsp_power;
	int fw_bin;
	int octa_hw;
	const char *ic_version;
	const char *project_name;
	char fw_path[FIRMWARE_PATH_LENGTH];
	char cmcs_path[FIRMWARE_PATH_LENGTH];
	const char *regulator_avdd;
};

struct ist30xx_data {
	struct i2c_client *client;
	struct input_dev *input_dev;
	struct ist30xx_dt_data *dt_data;
	struct ist30xx_platform_data *pdata;
	TSP_INFO tsp_info;
	TKEY_INFO tkey_info;
#ifdef CONFIG_HAS_EARLYSUSPEND
	struct early_suspend early_suspend;
#endif
	struct ist30xx_status status;
	struct ist30xx_fw fw;
	struct ist30xx_tags tags;
	struct pinctrl *pinctrl;
#if SEC_FACTORY_MODE
	struct sec_factory sec;
#endif
	u32 chip_id;
	u32 tsp_type;
	u32 max_fingers;
	u32 max_keys;
	u32 t_status;
	finger_info fingers[IST30XX_MAX_MT_FINGERS];
	u32 lx[IST30XX_MAX_MT_FINGERS];
	u32 ly[IST30XX_MAX_MT_FINGERS];
	volatile bool irq_working;
	u32 irq_enabled;
	bool initialized;
	u32 noise_mode;
	u32 debug_mode;
	u32 jig_mode;
	u32 z_values[IST30XX_MAX_MT_FINGERS];
	int report_rate;
	int idle_rate;
#if IST30XX_GESTURE
	bool suspend;
	bool gesture;
#endif
	int touch_pressed_num;
#ifdef CONFIG_INPUT_BOOSTER
	struct input_booster *tsp_booster;
#endif
	int scan_count;
	int scan_retry;
	int max_scan_retry;
	int irq_err_cnt;
	int max_irq_err_cnt;
	/* SEC defined [*/
	u16 max_x;
	u16 max_y;
	bool track_enable;
	/* SEC defined ]*/
	struct delayed_work     work_reset_check;
	struct delayed_work     work_noise_protect;
	struct delayed_work     work_debug_algorithm;
#if IST30XX_INTERNAL_BIN
#if IST30XX_UPDATE_BY_WORKQUEUE
	struct delayed_work     work_fw_update;
#endif
#endif
	bool touch_stopped;
#ifdef USE_TSP_TA_CALLBACKS
	struct tsp_callbacks	callbacks;
#endif
#ifdef CONFIG_MUIC_NOTIFIER
	struct notifier_block muic_nb;
#endif
#ifdef CONFIG_VBUS_NOTIFIER
	struct notifier_block vbus_nb;
#endif
	int lcd_id;

};

extern struct mutex ist30xx_mutex;
extern int ist30xx_dbg_level;
extern unsigned int system_rev;

void tsp_printk(int level, const char *fmt, ...);
int ist30xx_intr_wait(struct ist30xx_data *data, long ms);

void ist30xx_enable_irq(struct ist30xx_data *data);
void ist30xx_disable_irq(struct ist30xx_data *data);
void ist30xx_set_ta_mode(bool charging);
void ist30xx_set_edge_mode(int mode);
void ist30xx_set_cover_mode(int mode);
void ist30xx_start(struct ist30xx_data *data);
int ist30xx_get_ver_info(struct ist30xx_data *data);

int ist30xx_read_reg(struct i2c_client *client, u32 reg, u32 *buf);
int ist30xx_read_cmd(struct ist30xx_data *data, u32 cmd, u32 *buf);
int ist30xx_write_cmd(struct i2c_client *client, u32 cmd, u32 val);
int ist30xx_read_buf(struct i2c_client *client, u32 cmd, u32 *buf, u16 len);
int ist30xx_write_buf(struct i2c_client *client, u32 cmd, u32 *buf, u16 len);
int ist30xx_burst_read(struct i2c_client *client, u32 addr,
		u32 *buf32, u16 len, bool bit_en);
int ist30xx_burst_write(struct i2c_client *client, u32 addr,
		u32 *buf32, u16 len);

int ist30xx_cmd_start_scan(struct ist30xx_data *data);
int ist30xx_cmd_calibrate(struct i2c_client *client);
int ist30xx_cmd_check_calib(struct i2c_client *client);
int ist30xx_cmd_update(struct i2c_client *client, int cmd);
int ist30xx_cmd_hold(struct ist30xx_data *data, int enable);

int ist30xx_power_on(struct ist30xx_data *data, bool download);
int ist30xx_power_off(struct ist30xx_data *data);
int ist30xx_reset(struct ist30xx_data *data, bool download);

int ist30xx_internal_suspend(struct ist30xx_data *data);
int ist30xx_internal_resume(struct ist30xx_data *data);

int ist30xx_init_system(struct ist30xx_data *data);

extern struct class *ist30xx_class;
#if SEC_FACTORY_MODE
extern struct class *sec_class;
extern int sec_touch_sysfs(struct ist30xx_data *data);
extern int sec_fac_cmd_init(struct ist30xx_data *data);
extern void sec_fac_cmd_remove(struct ist30xx_data *data);
extern void sec_touch_sysfs_remove(struct ist30xx_data *data);

#endif

#endif /* __IST30XXC_H__ */
