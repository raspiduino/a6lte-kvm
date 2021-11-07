/*
 *  Copyright (C) 2010,Imagis Technology Co. Ltd. All Rights Reserved.
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

#include <linux/mutex.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/stat.h>
#include <linux/err.h>
#include "ist30xxh.h"
#include "ist30xxh_update.h"
#include "ist30xxh_misc.h"
#ifdef IST30XX_USE_CMCS
#include "ist30xxh_cmcs.h"
#endif

#ifdef SEC_FACTORY_MODE

#include <linux/sec_sysfs.h>

#define COMMAND_LENGTH      (64)
#define FACTORY_BUF_SIZE    PAGE_SIZE
#define BUILT_IN            (0)
#define UMS                 (1)

#define CMD_STATE_WAITING   (0)
#define CMD_STATE_RUNNING   (1)
#define CMD_STATE_OK        (2)
#define CMD_STATE_FAIL      (3)
#define CMD_STATE_NA        (4)

#define TSP_NODE_DEBUG      (0)

#define TSP_CH_UNUSED       (0)
#define TSP_CH_SCREEN       (1)
#define TSP_CH_GTX          (2)
#define TSP_CH_KEY          (3)
#define TSP_CH_UNKNOWN      (-1)

#define TSP_CMD(name, func) .cmd_name = name, .cmd_func = func
struct tsp_cmd {
    struct list_head    list;
    const char *        cmd_name;
    void            (*cmd_func)(void *dev_data);
};

u32 ist30xx_get_fw_ver(struct ist30xx_data *data)
{
    u32 ver = 0;
    int ret = 0;

    ret = ist30xx_read_cmd(data, eHCOM_GET_VER_FW, &ver);
    if (unlikely(ret)) {
        ist30xx_reset(data, false);
        ist30xx_start(data);
        tsp_info("%s(), ret=%d\n", __func__, ret);
        return ver;
    }

    tsp_debug("Reg addr: %x, ver: %x\n", eHCOM_GET_VER_FW, ver);

    return ver;
}

u32 ist30xx_get_fw_chksum(struct ist30xx_data *data)
{
    u32 chksum = 0;
    int ret = 0;

    ret = ist30xx_read_cmd(data, eHCOM_GET_CRC32, &chksum);
    if (unlikely(ret)) {
        ist30xx_reset(data, false);
        ist30xx_start(data);
        tsp_info("%s(), ret=%d\n", __func__, ret);
        return 0;
    }

    tsp_debug("Reg addr: %x, chksum: %x\n", eHCOM_GET_CRC32, chksum);

    return chksum;
}

#define KEY_SENSITIVITY_OFFSET  0x04
u32 key_sensitivity = 0;
int ist30xx_get_key_sensitivity(struct ist30xx_data *data, int id)
{
    u32 addr = IST30XX_DA_ADDR(data->algorithm_addr) + KEY_SENSITIVITY_OFFSET;
    u32 val = 0;
    int ret = 0;

    if (unlikely(id >= data->tkey_info.key_num))
        return 0;

    if (ist30xx_intr_wait(data, 30) < 0)
        return 0;

    ret = ist30xx_read_cmd(data, addr, &val);
    if (ret) {
        ist30xx_reset(data, false);
        ist30xx_start(data);
        tsp_info("%s(), ret=%d\n", __func__, ret);
        return 0;
    }

    if ((val & 0xFFF) == 0xFFF)
        return (key_sensitivity >> (16 * id)) & 0xFFFF;

    key_sensitivity = val;

    tsp_debug("Reg addr: %x, val: %8x\n", addr, val);

    val >>= (16 * id);

    return (int)(val & 0xFFFF);
}


/* Factory CMD function */
static void set_default_result(struct sec_factory *sec)
{
    char delim = ':';

    memset(sec->cmd_result, 0, sec->cmd_result_length);
    memcpy(sec->cmd_result, sec->cmd, strlen(sec->cmd));
    strncat(sec->cmd_result, &delim, CMD_STATE_RUNNING);
}

static void set_cmd_result(struct sec_factory *sec, char *buf, int len)
{
    strncat(sec->cmd_result, buf, len);
}

static void not_support_cmd(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);
    snprintf(buf, sizeof(buf), "%s", "NA");
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));

    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = false;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_NA;
    dev_info(&data->client->dev, "%s: \"%s(%ld)\"\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
    return;
}

static void get_chip_vendor(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);
    snprintf(buf, sizeof(buf), "%s", TSP_CHIP_VENDOR);
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void get_chip_name(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);
    snprintf(buf, sizeof(buf), "%s", TSP_CHIP_NAME);
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void get_chip_id(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);
    snprintf(buf, sizeof(buf), "%#02x", data->chip_id);
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}
#include <linux/uaccess.h>
#define MAX_FW_PATH 255
const u8 fbuf[IST30XX_ROM_TOTAL_SIZE + sizeof(struct ist30xx_tags)];
static void fw_update(void *dev_data)
{
    int ret;
    char buf[16] = { 0 };
    mm_segment_t old_fs = {0};
    struct file *fp = NULL;
    long fsize = 0, nread = 0;
    char fw_path[MAX_FW_PATH + 1];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);
#ifdef PAT_CONTROL
    data->status.update_keystring = 1;
#endif
    tsp_info("%s(), %d\n", __func__, sec->cmd_param[0]);

    switch (sec->cmd_param[0]) {
    case BUILT_IN:
        sec->cmd_state = CMD_STATE_OK;
        ret = ist30xx_fw_recovery(data);
        if (ret < 0)
            sec->cmd_state = CMD_STATE_FAIL;
        break;
    case UMS:
        sec->cmd_state = CMD_STATE_OK;
        old_fs = get_fs();
        set_fs(get_ds());

        snprintf(fw_path, MAX_FW_PATH, "/sdcard/%s", IST30XX_FW_NAME);
        fp = filp_open(fw_path, O_RDONLY, 0);
        if (IS_ERR(fp)) {
            tsp_warn("%s(), file %s open error:%d\n", __func__, fw_path,
                    IS_ERR(fp));
            sec->cmd_state= CMD_STATE_FAIL;
            set_fs(old_fs);
            break;
        }

        fsize = fp->f_path.dentry->d_inode->i_size;
        if (fsize != data->fw.buf_size) {
            tsp_warn("%s(), invalid fw size!!\n", __func__);
            sec->cmd_state = CMD_STATE_FAIL;
            set_fs(old_fs);
            break;
        }

        nread = vfs_read(fp, (char __user *)fbuf, fsize, &fp->f_pos);
        if (nread != fsize) {
            tsp_warn("%s(), failed to read fw\n", __func__);
            sec->cmd_state = CMD_STATE_FAIL;
            filp_close(fp, NULL);
            set_fs(old_fs);
            break;
        }

        filp_close(fp, current->files);
        set_fs(old_fs);
        tsp_info("%s(), ums fw is loaded!!\n", __func__);

        ret = ist30xx_get_update_info(data, fbuf, fsize);
        if (ret) {
            sec->cmd_state = CMD_STATE_FAIL;
            break;
        }
        data->fw.bin.main_ver = ist30xx_parse_ver(data, FLAG_MAIN, fbuf);
        data->fw.bin.fw_ver = ist30xx_parse_ver(data, FLAG_FW, fbuf);
        data->fw.bin.test_ver = ist30xx_parse_ver(data, FLAG_TEST, fbuf);
        data->fw.bin.core_ver = ist30xx_parse_ver(data, FLAG_CORE, fbuf);

        mutex_lock(&data->lock);
        ret = ist30xx_fw_update(data, fbuf, fsize);
        if (ret) {
            sec->cmd_state = CMD_STATE_FAIL;
            mutex_unlock(&data->lock);
            break;
        }
        ist30xx_print_info(data);
#ifndef IST30XX_UPDATE_NO_CAL
        ist30xx_calibrate(data, 1);
#endif
        mutex_unlock(&data->lock);
        ist30xx_start(data);
        break;

    default:
        tsp_warn("%s(), Invalid fw file type!\n", __func__);
        break;
    }

    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%s", "OK");
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

#ifdef PAT_CONTROL
    data->status.update_keystring = 0;
#endif
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
}

static void get_fw_ver_bin(void *dev_data)
{
    u32 ver = 0;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    ver = ist30xx_parse_ver(data, FLAG_FW, data->fw.buf);
    snprintf(buf, sizeof(buf), "IM%06X", ver);
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}
static void get_config_ver(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    char buff[255] = { 0 };

    set_default_result(sec);

    snprintf(buff, sizeof(buff), "%s_%s", TSP_CHIP_VENDOR, TSP_CHIP_NAME);

    set_cmd_result(sec, buff, strnlen(buff, sizeof(buff)));
    sec->cmd_state = CMD_STATE_OK;
    tsp_info("%s(): %s(%d)\n", __func__, buff,
             strnlen(buff, sizeof(buff)));
}
static void get_checksum_data(void *dev_data)
{
    char buf[16] = {0};
    u32 chksum = 0;
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->status.power == 1) {
        chksum = ist30xx_get_fw_chksum(data);
        if (chksum == 0) {
            tsp_info("%s(), Failed get the checksum data \n", __func__);
            snprintf(buf, sizeof(buf), "%s", "NG");
            set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
            sec->cmd_state = CMD_STATE_FAIL;
            return;
        }
    }

    snprintf(buf, sizeof(buf), "0x%06X", chksum);

    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void get_fw_ver_ic(void *dev_data)
{
    u32 ver = 0;
    char msg[8];
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->status.power == 1) {
        ver = ist30xx_get_fw_ver(data);
        snprintf(buf, sizeof(buf), "IM%06X", ver);
    } else {
        snprintf(buf, sizeof(buf), "IM%06X", data->fw.cur.fw_ver);
    }

    if (data->fw.cur.test_ver > 0) {
        sprintf(msg, "(T%X)", data->fw.cur.test_ver);
        strcat(buf, msg);
    }

    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void dead_zone_enable(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    tsp_info("%s(), %d\n", __func__, sec->cmd_param[0]);

    switch (sec->cmd_param[0]) {
    case 0:
        sec->cmd_state = CMD_STATE_OK;
        tsp_info("%s(), Set Edge Mode\n", __func__);
        ist30xx_set_edge_mode(1);
        break;
    case 1:
        sec->cmd_state = CMD_STATE_OK;
        tsp_info("%s(), Unset Edge Mode\n", __func__);
        ist30xx_set_edge_mode(0);
        break;
    default:
        tsp_info("%s(), Invalid Argument\n", __func__);
        break;
    }
    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%s", "OK");
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void spay_enable(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    tsp_info("%s(), %d\n", __func__, sec->cmd_param[0]);
/*
    if (data->suspend) {
        tsp_err("%s(), error currently suspend\n", __func__);
        goto err;
    }
*/
    switch (sec->cmd_param[0]) {
    case 0:
        sec->cmd_state = CMD_STATE_OK;
        tsp_info("%s(), Unset SPAY Mode\n", __func__);
        data->spay = false;
        break;
    case 1:
        sec->cmd_state = CMD_STATE_OK;
        tsp_info("%s(), Set SPAY Mode\n", __func__);
        data->spay = true;
        break;
    default:
        tsp_info("%s(), Invalid Argument\n", __func__);
        break;
    }

    if (data->spay) {
        data->g_reg.b.ctrl |= IST30XX_GETURE_CTRL_SPAY;
        data->g_reg.b.setting |= IST30XX_GETURE_SET_SPAY;
    } else {
        data->g_reg.b.ctrl &= ~IST30XX_GETURE_CTRL_SPAY;
        data->g_reg.b.setting &= ~IST30XX_GETURE_SET_SPAY;
    }

/*err:*/
    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%s", "OK");
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));

    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = false;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_WAITING;
}

static void aod_enable(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    tsp_info("%s(), %d\n", __func__, sec->cmd_param[0]);
/*
    if (data->suspend) {
        tsp_err("%s(), error currently suspend\n", __func__);
        goto err;
    }
*/
    switch (sec->cmd_param[0]) {
    case 0:
        sec->cmd_state = CMD_STATE_OK;
        tsp_info("%s(), Unset AOD Mode\n", __func__);
        data->aod = false;
        break;
    case 1:
        sec->cmd_state = CMD_STATE_OK;
        tsp_info("%s(), Set AOD Mode\n", __func__);
        data->aod = true;
        break;
    default:
        tsp_info("%s(), Invalid Argument\n", __func__);
        break;
    }

    if (data->aod) {
        data->g_reg.b.ctrl |= IST30XX_GETURE_CTRL_AOD;
        data->g_reg.b.setting |= IST30XX_GETURE_SET_AOD;
    } else {
        data->g_reg.b.ctrl &= ~IST30XX_GETURE_CTRL_AOD;
        data->g_reg.b.setting &= ~IST30XX_GETURE_SET_AOD;
    }

/*err:*/
    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%s", "OK");
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));

    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = false;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_WAITING;
}

static void set_aod_rect(void *dev_data)
{
    int ret;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    tsp_info("%s(), w:%d, h:%d, x:%d, y:%d\n", __func__, sec->cmd_param[0],
            sec->cmd_param[1], sec->cmd_param[2], sec->cmd_param[3]);

    if (!data->suspend) {
        tsp_err("%s(), error currently is not a suspend status\n", __func__);
        goto err;
    }

    if (!data->aod) {
        tsp_err("%s(), error currently unset aod\n", __func__);
        goto err;
    }

    if (data->aod && data->suspend) {
        ist30xx_disable_irq(data);
        ist30xx_intr_wait(data, 30);
        mutex_lock(&data->aod_lock);
        data->g_reg.b.w = sec->cmd_param[0];
        data->g_reg.b.h = sec->cmd_param[1];
        data->g_reg.b.x = sec->cmd_param[2];
        data->g_reg.b.y = sec->cmd_param[3];
        ret = ist30xx_burst_write(data->client, IST30XX_HIB_GESTURE_REG,
                data->g_reg.full, sizeof(data->g_reg.full) / IST30XX_DATA_LEN);
        ist30xx_enable_irq(data);
        data->status.noise_mode = false;
        mutex_unlock(&data->aod_lock);
        if (ret) {
            tsp_err("%s(), fail to write gesture regmap\n", __func__);
            goto err;
        }
        ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD,
            (eHCOM_NOTIRY_G_REGMAP << 16) | IST30XX_ENABLE);
        if (ret) {
            tsp_err("%s(), fail to write notify packet.\n", __func__);
            goto err;
        }
    }

    sec->cmd_state = CMD_STATE_OK;

err:
    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%s", "OK");
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));

    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = false;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_WAITING;
}

static void get_aod_rect(void *dev_data)
{
    char buf[32] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    snprintf(buf, sizeof(buf), "%d,%d,%d,%d", data->g_reg.b.w, data->g_reg.b.h,
            data->g_reg.b.x, data->g_reg.b.y);
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));

    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = false;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_WAITING;
}

static void get_threshold(void *dev_data)
{
    int ret = 0;
    u32 val = 0;
    char buf[16] = { 0 };
    int threshold;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    ret = ist30xx_read_cmd(data, eHCOM_GET_TOUCH_TH, &val);
    if (unlikely(ret)) {
        ist30xx_reset(data, false);
        ist30xx_start(data);
        tsp_info("%s(), ret=%d\n", __func__, ret);
        val = 0;
    }

    set_default_result(sec);

    threshold = (int)(val & 0xFFFF);

    snprintf(buf, sizeof(buf), "%d", threshold);
    tsp_info("%s(), %s\n", __func__, buf);

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    sec->cmd_state = CMD_STATE_OK;
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void get_scr_x_num(void *dev_data)
{
    int val = -1;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->tsp_info.dir.swap_xy)
        val = data->tsp_info.screen.tx;
    else
        val = data->tsp_info.screen.rx;

    if (val >= 0) {
        snprintf(buf, sizeof(buf), "%u", val);
        sec->cmd_state = CMD_STATE_OK;
        dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
                strnlen(buf, sizeof(buf)));
    } else {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
        dev_info(&data->client->dev,
                "%s: fail to read num of x (%d).\n", __func__, val);
    }
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), %s\n", __func__, buf);
}

static void get_scr_y_num(void *dev_data)
{
    int val = -1;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->tsp_info.dir.swap_xy)
        val = data->tsp_info.screen.rx;
    else
        val = data->tsp_info.screen.tx;

    if (val >= 0) {
        snprintf(buf, sizeof(buf), "%u", val);
        sec->cmd_state = CMD_STATE_OK;
        dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
                strnlen(buf, sizeof(buf)));
    } else {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
        dev_info(&data->client->dev,
                "%s: fail to read num of y (%d).\n", __func__, val);
    }
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), %s\n", __func__, buf);
}

static void get_all_x_num(void *dev_data)
{
    int val = -1;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->tsp_info.dir.swap_xy)
        val = data->tsp_info.ch_num.tx;
    else
        val = data->tsp_info.ch_num.rx;

    if (val >= 0) {
        snprintf(buf, sizeof(buf), "%u", val);
        sec->cmd_state = CMD_STATE_OK;
        dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
                strnlen(buf, sizeof(buf)));
    } else {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
        dev_info(&data->client->dev,
                "%s: fail to read all num of x (%d).\n", __func__, val);
    }
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), %s\n", __func__, buf);
}

static void get_all_y_num(void *dev_data)
{
    int val = -1;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->tsp_info.dir.swap_xy)
        val = data->tsp_info.ch_num.rx;
    else
        val = data->tsp_info.ch_num.tx;

    if (val >= 0) {
        snprintf(buf, sizeof(buf), "%u", val);
        sec->cmd_state = CMD_STATE_OK;
        dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
                strnlen(buf, sizeof(buf)));
    } else {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
        dev_info(&data->client->dev,
                "%s: fail to read all num of y (%d).\n", __func__, val);
    }
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), %s\n", __func__, buf);
}

int check_tsp_channel(void *dev_data, int width, int height)
{
    int node = -EPERM;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    if (data->tsp_info.dir.swap_xy) {
        if ((sec->cmd_param[0] < 0) || (sec->cmd_param[0] >= height) ||
                (sec->cmd_param[1] < 0) || (sec->cmd_param[1] >= width)) {
            tsp_info("%s: parameter error: %u,%u\n",
                    __func__, sec->cmd_param[0], sec->cmd_param[1]);
        } else {
            node = sec->cmd_param[1] + sec->cmd_param[0] * width;
            tsp_info("%s: node = %d\n", __func__, node);
        }
    } else {
        if ((sec->cmd_param[0] < 0) || (sec->cmd_param[0] >= width) ||
                (sec->cmd_param[1] < 0) || (sec->cmd_param[1] >= height)) {
            tsp_info("%s: parameter error: %u,%u\n",
                    __func__, sec->cmd_param[0], sec->cmd_param[1]);
        } else {
            node = sec->cmd_param[0] + sec->cmd_param[1] * width;
            tsp_info("%s: node = %d\n", __func__, node);
        }
    }

    return node;
}

static u16 cal_cp_value[IST30XX_MAX_NODE_NUM];
static u16 cal_self_cp_value[IST30XX_MAX_SELF_NODE_NUM];
static u16 miscal_cp_value[IST30XX_MAX_NODE_NUM];
static u16 miscal_self_cp_value[IST30XX_MAX_SELF_NODE_NUM];
static u16 miscal_maxgap_value[IST30XX_MAX_NODE_NUM];
static u16 miscal_self_maxgap_value[IST30XX_MAX_SELF_NODE_NUM];
void get_cp_array(void *dev_data)
{
    int i, ret;
    int count = 0;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    mutex_lock(&data->lock);
    ret = ist30xx_read_cp_node(data, &tsp->node, true, false);
    if (ret) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cp read fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);
    ist30xx_parse_cp_node(data, &tsp->node, true);

    ret = parse_cp_node(data, &tsp->node, cal_cp_value, cal_self_cp_value,
            TSP_CDC_ALL, true);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cp parse fail!\n", __func__);
        return;
    }

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx * tsp->ch_num.tx; i++) {
        count += snprintf(msg, msg_len, "%d,", cal_cp_value[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

void get_self_cp_array(void *dev_data)
{
    int i, ret;
    int count = 0;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    mutex_lock(&data->lock);
    ret = ist30xx_read_cp_node(data, &tsp->node, true, false);
    if (ret) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp self cp read fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);
    ist30xx_parse_cp_node(data, &tsp->node, true);

    ret = parse_cp_node(data, &tsp->node, cal_cp_value, cal_self_cp_value,
            TSP_CDC_ALL, true);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp self cp parse fail!\n", __func__);
        return;
    }

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx + tsp->ch_num.tx; i++) {
        count += snprintf(msg, msg_len, "%d,", cal_self_cp_value[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

extern int calib_ms_delay;
int ist30xx_miscalib_wait(struct ist30xx_data *data)
{
    int cnt = calib_ms_delay;

    memset(data->status.miscalib_msg, 0, sizeof(u32) * IST30XX_MAX_CALIB_SIZE);
    while (cnt-- > 0) {
        ist30xx_delay(100);

        if (data->status.miscalib_msg[0] && data->status.miscalib_msg[1]) {
            tsp_info("SLF Calibration status : %d, Max gap : %d - (%08x)\n",
                    CALIB_TO_STATUS(data->status.miscalib_msg[0]),
                    CALIB_TO_GAP(data->status.miscalib_msg[0]),
                    data->status.miscalib_msg[0]);

            tsp_info("MTL Calibration status : %d, Max gap : %d - (%08x)\n",
                    CALIB_TO_STATUS(data->status.miscalib_msg[1]),
                    CALIB_TO_GAP(data->status.miscalib_msg[1]),
                    data->status.miscalib_msg[1]);

            if ((CALIB_TO_STATUS(data->status.miscalib_msg[0]) == 0) &&
                    (CALIB_TO_STATUS(data->status.miscalib_msg[1]) == 0))
                return 0;  // Calibrate success
            else
                return -EAGAIN;
        }
    }
    tsp_warn("Calibration time out\n");

    return -EPERM;
}

int ist30xx_miscalibrate(struct ist30xx_data *data, int wait_cnt)
{
    int ret = -ENOEXEC;

    tsp_info("*** Miscalibrate %ds ***\n", calib_ms_delay / 10);

    data->status.miscalib = 1;
    ist30xx_disable_irq(data);    

    while (1) {
        ret = ist30xx_cmd_miscalibrate(data);
        if (unlikely(ret))
            continue;

        ist30xx_enable_irq(data);
        ret = ist30xx_miscalib_wait(data);
        if (likely(!ret))
            break;

        ist30xx_disable_irq(data);

        if (--wait_cnt == 0)
            break;

        ist30xx_reset(data, false);
    }

    data->status.miscalib = 0;

    return ret;
}

/*
## Mis Cal result ##
FD : spec out
F5 : miscal parse fail
F4 : miscal cp read fail
F3 : miscalibration fail
F2 : tsp cp parse fail
F1 : tsp cp read fail
F0 : initial value in function
00 : pass
*/
void run_miscalibration(void *dev_data)
{
	int i;
	int ret = 0;
	int val, max_val = 0;
	char buf[16] = { 0 };
	char mis_cal_data = 0xF0;

	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;
	TSP_INFO *tsp = &data->tsp_info;

	set_default_result(sec);

	mutex_lock(&data->lock);
	ret = ist30xx_read_cp_node(data, &tsp->node, true, true);
	if (ret) {
		mutex_unlock(&data->lock);
		sec->cmd_state = CMD_STATE_FAIL;
		tsp_warn("%s(), tsp cp read fail!\n", __func__);
		mis_cal_data = 0xF1;
		goto cmd_result;
	}
	ist30xx_parse_cp_node(data, &tsp->node, true);

	ret = parse_cp_node(data, &tsp->node, cal_cp_value, cal_self_cp_value,
						TSP_CDC_ALL, true);
	if (ret) {
		mutex_unlock(&data->lock);
		sec->cmd_state = CMD_STATE_FAIL;
		tsp_warn("%s(), tsp cp parse fail!\n", __func__);
		mis_cal_data = 0xF2;
		goto cmd_result;
	}

	ist30xx_reset(data, false);
	ret = ist30xx_miscalibrate(data, 1);
	if (ret) {
		ist30xx_disable_irq(data);
		ist30xx_reset(data, false);
		ist30xx_start(data);
		ist30xx_enable_irq(data);
		mutex_unlock(&data->lock);
		sec->cmd_state = CMD_STATE_FAIL;
		tsp_warn("%s(), miscalibration fail!\n", __func__);
		mis_cal_data = 0xF3;
		goto cmd_result;
	}

	ret = ist30xx_read_cp_node(data, &tsp->node, false, true);
	ist30xx_disable_irq(data);
	ist30xx_reset(data, false);
	ist30xx_start(data);
	ist30xx_enable_irq(data);
	mutex_unlock(&data->lock);
	if (ret) {        
		sec->cmd_state = CMD_STATE_FAIL;
		tsp_warn("%s(), miscal cp read fail!\n", __func__);
		mis_cal_data = 0xF4;
		goto cmd_result;
	}   

	ist30xx_parse_cp_node(data, &tsp->node, false);

	ret = parse_cp_node(data, &tsp->node, miscal_cp_value, miscal_self_cp_value,
						TSP_CDC_ALL, false);
	if (ret) {
		sec->cmd_state = CMD_STATE_FAIL;
		tsp_warn("%s(), miscal parse fail!\n", __func__);
		mis_cal_data = 0xF5;
		goto cmd_result;
	}    

	val = cal_cp_value[0] - miscal_cp_value[0];
	if (val < 0)
		val *= -1;
	max_val = val;
	tsp_verb("Miscal MTL\n");
	for (i = 0; i < tsp->screen.rx * tsp->screen.tx; i++) {
		val = cal_cp_value[i] - miscal_cp_value[i];
		if (val < 0)
			val *= -1;
		miscal_maxgap_value[i] = val;
		max_val = max(max_val, val);
		tsp_verb(" [%d] |%d - %d| = %d\n", i, cal_cp_value[i],
		miscal_cp_value[i], miscal_maxgap_value[i]);
	}

	tsp_verb("Miscal SLF\n");
	for (i = 0; i < tsp->ch_num.rx + tsp->ch_num.tx; i++) {
		val = cal_self_cp_value[i] - miscal_self_cp_value[i];
		if (val < 0)
			val *= -1;
		miscal_self_maxgap_value[i] = val;
		tsp_verb(" [%d] |%d - %d| = %d\n", i, cal_self_cp_value[i],
		miscal_self_cp_value[i], miscal_self_maxgap_value[i]);
	}

	if (max_val > SEC_MISCAL_SPEC) {
		sec->cmd_state = CMD_STATE_FAIL;
		mis_cal_data = 0xFD;
	} else {
		sec->cmd_state = CMD_STATE_OK;
		mis_cal_data = 0x00;
	}
cmd_result:
	snprintf(buf, sizeof(buf), "%02X,%d,0,0", mis_cal_data, max_val);

	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	tsp_info("%s(), %s, (%ld)\n", __func__, buf, max_val);
}

void get_miscalibration_value(void *dev_data)
{
	int idx = 0;
	char buf[16] = { 0 };

	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;
	TSP_INFO *tsp = &data->tsp_info;

	set_default_result(sec);

	idx = check_tsp_channel(data, tsp->screen.rx, tsp->screen.tx);
	if (idx < 0) { // Parameter parsing fail
		snprintf(buf, sizeof(buf), "%s", "NG");
		sec->cmd_state = CMD_STATE_FAIL;
	} else {
		snprintf(buf, sizeof(buf), "%d", miscal_maxgap_value[idx]);
		sec->cmd_state = CMD_STATE_OK;
	}

	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	tsp_info("%s(), [%d][%d]: %s\n", __func__,
				sec->cmd_param[0], sec->cmd_param[1], buf);
	dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
	strnlen(buf, sizeof(buf)));
}

static u16 node_value[IST30XX_MAX_NODE_NUM];
static u16 self_node_value[IST30XX_MAX_SELF_NODE_NUM];
static u16 key_node_value[IST30XX_MAX_KEYS];
void get_cdc_array(void *dev_data)
{
    int i, ret;
    int count = 0;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];
    u8 flag = NODE_FLAG_CDC;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    mutex_lock(&data->lock);
    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node read fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, node_value, self_node_value,
            TSP_CDC_ALL);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node parse fail!\n", __func__);
        return;
    }

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx * tsp->ch_num.tx; i++) {
        count += snprintf(msg, msg_len, "%d,", node_value[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

void get_self_cdc_array(void *dev_data)
{
    int i, ret;
    int count = 0;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];
    u8 flag = NODE_FLAG_CDC;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    mutex_lock(&data->lock);
    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp self cdc read fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, node_value, self_node_value,
            TSP_CDC_ALL);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp self cdc parse fail!\n", __func__);
        return;
    }

    buf = kmalloc(IST30XX_MAX_SELF_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx + tsp->ch_num.tx; i++) {
        count += snprintf(msg, msg_len, "%d,", self_node_value[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

void run_cdc_read(void *dev_data)
{
    int i;
    int ret = 0;
    int min_val, max_val;
    char buf[16] = { 0 };
    u8 flag = NODE_FLAG_CDC;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node read fail!\n", __func__);
        return;
    }
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, node_value, self_node_value,
            TSP_CDC_SCREEN);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node parse fail!\n", __func__);
        return;
    }

    min_val = max_val = node_value[0];
    for (i = 0; i < tsp->screen.rx * tsp->screen.tx; i++) {
        max_val = max(max_val, (int)node_value[i]);
        min_val = min(min_val, (int)node_value[i]);
    }

    snprintf(buf, sizeof(buf), "%d,%d", min_val, max_val);
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void run_self_cdc_read(void *dev_data)
{
    int i;
    int ret = 0;
    int min_val, max_val;
    char buf[16] = { 0 };
    u8 flag = NODE_FLAG_CDC;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node read fail!\n", __func__);
        return;
    }
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, node_value, self_node_value,
            TSP_CDC_SCREEN);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node parse fail!\n", __func__);
        return;
    }

    min_val = max_val = self_node_value[0];
    for (i = 0; i < tsp->ch_num.rx + tsp->ch_num.tx; i++) {
        max_val = max(max_val, (int)self_node_value[i]);
        min_val = min(min_val, (int)self_node_value[i]);
    }

    snprintf(buf, sizeof(buf), "%d,%d", min_val, max_val);
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void run_cdc_read_key(void *dev_data)
{
    int ret = 0;
    char buf[16] = { 0 };
    u8 flag = NODE_FLAG_CDC;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp key node read fail!\n", __func__);
        return;
    }
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, key_node_value,
            self_node_value, TSP_CDC_KEY);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp key node parse fail!", __func__);
        return;
    }

    snprintf(buf, sizeof(buf), "%d,%d", key_node_value[0], key_node_value[1]);
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_cdc_value(void *dev_data)
{
    int idx = 0;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    idx = check_tsp_channel(data, tsp->screen.rx, tsp->screen.tx);
    if (idx < 0) { // Parameter parsing fail
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
    } else {
        snprintf(buf, sizeof(buf), "%d", node_value[idx]);
        sec->cmd_state = CMD_STATE_OK;
    }

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), [%d][%d]: %s\n", __func__,
            sec->cmd_param[0], sec->cmd_param[1], buf);
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_self_cdc_value(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    if ((sec->cmd_param[0] < 0) ||
            (sec->cmd_param[0] >= (tsp->ch_num.rx + tsp->ch_num.tx))) {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
    } else {
        snprintf(buf, sizeof(buf), "%d", self_node_value[sec->cmd_param[0]]);
        sec->cmd_state = CMD_STATE_OK;
    }

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), [%d]: %s\n", __func__, sec->cmd_param[0], buf);
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_rx_self_cdc_value(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    if ((sec->cmd_param[1] < 0) ||
            (sec->cmd_param[1] >= (tsp->ch_num.rx))) {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
    } else {
        snprintf(buf, sizeof(buf), "%d", self_node_value[sec->cmd_param[1]+tsp->ch_num.tx]);
        sec->cmd_state = CMD_STATE_OK;
    }

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), [%d]: %s\n", __func__, sec->cmd_param[1], buf);
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_tx_self_cdc_value(void *dev_data)
{
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    if ((sec->cmd_param[0] < 0) ||
            (sec->cmd_param[0] >= (tsp->ch_num.tx))) {
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
    } else {
        snprintf(buf, sizeof(buf), "%d", self_node_value[sec->cmd_param[0]]);
        sec->cmd_state = CMD_STATE_OK;
    }

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), [%d]: %s\n", __func__, sec->cmd_param[0], buf);
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_cdc_all_data(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;
    int i;
    int ret;
    u8 flag = NODE_FLAG_CDC;
    char *cdc_buffer;
    char temp[10];

    set_default_result(sec);

    cdc_buffer = kzalloc(sec->cmd_result_length, GFP_KERNEL);
    if (!cdc_buffer) {
        tsp_err("%s: failed to allication memory\n", __func__);
        goto out_cdc_all_data;
    }

    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node read fail!\n", __func__);
        goto err_read_data;
    }
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, node_value, self_node_value,
            TSP_CDC_SCREEN);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node parse fail!\n", __func__);
        goto err_read_data;
    }

    for (i = 0; i < tsp->screen.rx * tsp->screen.tx; i++) {
        snprintf(temp, 10, "%d,", node_value[i]);
        strncat(cdc_buffer, temp, 10);
    }

    set_cmd_result(sec, cdc_buffer, sec->cmd_result_length);

    sec->cmd_state = CMD_STATE_OK;

    kfree(cdc_buffer);
    return;

err_read_data:
    kfree(cdc_buffer);
out_cdc_all_data:
    sec->cmd_state = CMD_STATE_FAIL;
}

void get_self_cdc_all_data(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;
    int i;
    int ret;
    u8 flag = NODE_FLAG_CDC;
    char *cdc_buffer;
    char temp[10];

    set_default_result(sec);

    cdc_buffer = kzalloc(sec->cmd_result_length, GFP_KERNEL);
    if (!cdc_buffer) {
        tsp_err("%s: failed to allication memory\n", __func__);
        goto out_cdc_all_data;
    }

    ret = ist30xx_read_touch_node(data, flag, &tsp->node);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node read fail!\n", __func__);
        goto err_read_data;
    }
    ist30xx_parse_touch_node(data, &tsp->node);

    ret = parse_tsp_node(data, flag, &tsp->node, node_value, self_node_value,
            TSP_CDC_ALL);
    if (ret) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp node parse fail!\n", __func__);
        goto err_read_data;
    }

    for (i = 0; i < tsp->ch_num.rx + tsp->ch_num.tx; i++) {
        snprintf(temp, 10, "%d,", self_node_value[i]);
        strncat(cdc_buffer, temp, 10);
    }

    set_cmd_result(sec, cdc_buffer, sec->cmd_result_length);

    sec->cmd_state = CMD_STATE_OK;

    kfree(cdc_buffer);
    return;

err_read_data:
    kfree(cdc_buffer);
out_cdc_all_data:
    sec->cmd_state = CMD_STATE_FAIL;
}

#ifdef IST30XX_USE_CMCS
extern u8 *ts_cmcs_bin;
extern u32 ts_cmcs_bin_size;
extern CMCS_BIN_INFO *ts_cmcs;
extern CMCS_BUF *ts_cmcs_buf;
int get_read_all_data(struct ist30xx_data *data, u8 flag)
{
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    int ii;
    int count = 0;
    int type;
    char *buffer;
    char *temp;
    int ret;
    u32 cmcs_flag = 0;

    if ((ts_cmcs_bin == NULL) || (ts_cmcs_bin_size == 0)) {
        tsp_err("%s: cmcs binary is NULL!\n", __func__);
        goto cm_err_out;
    }

    ret = ist30xx_get_cmcs_info(ts_cmcs_bin, ts_cmcs_bin_size);
    if (unlikely(ret)) {
        tsp_err("%s: tsp get cmcs infomation fail!\n", __func__);
        goto cm_err_out;
    }

    if ((flag == TEST_CM_ALL_DATA) || (flag == TEST_SLOPE0_ALL_DATA) ||
            (flag == TEST_SLOPE1_ALL_DATA))
        cmcs_flag = CMCS_FLAG_CM;
    else if (flag == TEST_CS_ALL_DATA)
        cmcs_flag = CMCS_FLAG_CS;

    mutex_lock(&data->lock);
    ret = ist30xx_cmcs_test(data, ts_cmcs_bin, ts_cmcs_bin_size, cmcs_flag);
    if (unlikely(ret)) {
        mutex_unlock(&data->lock);
        tsp_err("%s: tsp cmcs test fail!\n", __func__);
        goto cm_err_out;
    }
    mutex_unlock(&data->lock);

    buffer = kzalloc(sec->cmd_result_length, GFP_KERNEL);
    if (!buffer) {
        tsp_err("%s: failed to buffer alloc\n", __func__);
        goto cm_err_out;
    }

    temp = kzalloc(10, GFP_KERNEL);
    if (!temp) {
        tsp_err("%s: failed to temp alloc\n", __func__);
        goto cm_err_alloc_out;
    }

    for (ii = 0; ii < tsp->ch_num.rx * tsp->ch_num.tx; ii++) {
        type = check_tsp_type(data, ii / tsp->ch_num.rx, ii % tsp->ch_num.rx);
        if ((type == TSP_CH_UNKNOWN) || (type == TSP_CH_UNUSED)) {
            count += snprintf(temp, 10, "%d,", 0);
        } else {
            switch (flag) {
            case TEST_CM_ALL_DATA:
                count += snprintf(temp, 10, "%d,", ts_cmcs_buf->cm[ii]);
                break;
            case TEST_SLOPE0_ALL_DATA:
                count += snprintf(temp, 10, "%d,", ts_cmcs_buf->slope0[ii]);
                break;
            case TEST_SLOPE1_ALL_DATA:
                count += snprintf(temp, 10, "%d,", ts_cmcs_buf->slope1[ii]);
                break;
            case TEST_CS_ALL_DATA:
                count += snprintf(temp, 10, "%d,", ts_cmcs_buf->cs[ii]);
                break;
            }
        }
        strncat(buffer, temp, 10);
    }

    set_cmd_result(sec, buffer, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buffer, count);
    kfree(buffer);
    kfree(temp);
    return 0;

cm_err_alloc_out:
    kfree(buffer);
cm_err_out:
    sec->cmd_state = CMD_STATE_FAIL;
    set_cmd_result(sec, "NULL", sec->cmd_result_length);
    return -1;
}

void get_cm_all_data(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    int ret;

    set_default_result(sec);

    ret = get_read_all_data(data, TEST_CM_ALL_DATA);
    if (ret < 0)
        sec->cmd_state = CMD_STATE_FAIL;
    else
        sec->cmd_state = CMD_STATE_OK;
}

void get_slope0_all_data(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    int ret;

    set_default_result(sec);

    ret = get_read_all_data(data, TEST_SLOPE0_ALL_DATA);
    if (ret < 0)
        sec->cmd_state = CMD_STATE_FAIL;
    else
        sec->cmd_state = CMD_STATE_OK;
}

void get_slope1_all_data(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    int ret;

    set_default_result(sec);

    ret = get_read_all_data(data, TEST_SLOPE1_ALL_DATA);
    if (ret < 0)
        sec->cmd_state = CMD_STATE_FAIL;
    else
        sec->cmd_state = CMD_STATE_OK;
}

void get_cs_all_data(void *dev_data)
{
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    int ret;

    set_default_result(sec);

    ret = get_read_all_data(data, TEST_CS_ALL_DATA);
    if (ret < 0)
        sec->cmd_state = CMD_STATE_FAIL;
    else
        sec->cmd_state = CMD_STATE_OK;
}

void run_hvdd_test(void *dev_data)
{
    int ret = 0;
    char buf[16] = { 0 };
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if ((ts_cmcs_bin == NULL) || (ts_cmcs_bin_size == 0)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), Binary is not correct!\n", __func__);
        goto hvdd_end;
    }

    ret = ist30xx_get_cmcs_info(ts_cmcs_bin, ts_cmcs_bin_size);
    if (unlikely(ret)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp get cmcs infomation fail!\n", __func__);
        goto hvdd_end;
    }

    mutex_lock(&data->lock);
    ret = ist30xx_cmcs_test(data, ts_cmcs_bin, ts_cmcs_bin_size,
            CMCS_FLAG_HVDD);
    if (unlikely(ret)) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cmcs test fail!\n", __func__);
        goto hvdd_end;
    }else {
        sec->cmd_state = CMD_STATE_OK;
    }
    mutex_unlock(&data->lock);

hvdd_end:
    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%s", "OK");
    else
        snprintf(buf, sizeof(buf), "%s", "NG");
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void run_cm_test(void *dev_data)
{
    int i, j;
    int ret = 0;
    char buf[16] = { 0 };
    int type, idx;
    int min_val, max_val;
    int avg_sum, avg_val;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    if ((ts_cmcs_bin == NULL) || (ts_cmcs_bin_size == 0)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), Binary is not correct!\n", __func__);
        return;
    }

    ret = ist30xx_get_cmcs_info(ts_cmcs_bin, ts_cmcs_bin_size);
    if (unlikely(ret)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp get cmcs infomation fail!\n", __func__);
        return;
    }

    mutex_lock(&data->lock);
    ret = ist30xx_cmcs_test(data, ts_cmcs_bin, ts_cmcs_bin_size, CMCS_FLAG_CM);
    if (unlikely(ret)) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cmcs test fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);

    avg_sum = 0;
    min_val = max_val = ts_cmcs_buf->cm[0];
    for (i = 0; i < tsp->ch_num.tx; i++) {
        for (j = 0; j < tsp->ch_num.rx; j++) {
            idx = (i * tsp->ch_num.rx) + j;
            type = check_tsp_type(data, i, j);

            if ((type == TSP_CH_SCREEN) || (type == TSP_CH_GTX)) {
                max_val = max(max_val, (int)ts_cmcs_buf->cm[idx]);
                min_val = min(min_val, (int)ts_cmcs_buf->cm[idx]);
                avg_sum += (int)ts_cmcs_buf->cm[idx];
            }
        }
    }

    avg_val = avg_sum / (tsp->ch_num.tx * tsp->ch_num.rx);

    snprintf(buf, sizeof(buf), "%d,%d,%d", min_val, max_val, avg_val);
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void run_cm_test_key(void *dev_data)
{
    int i, j;
    int ret = 0;
    char buf[16] = { 0 };
    int type, idx;
    int cm_key[IST30XX_MAX_KEYS] = { 0 };
    int key_count = 0;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    if ((ts_cmcs_bin == NULL) || (ts_cmcs_bin_size == 0)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), Binary is not correct!\n", __func__);
        return;
    }

    ret = ist30xx_get_cmcs_info(ts_cmcs_bin, ts_cmcs_bin_size);
    if (unlikely(ret)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp get cmcs infomation fail!\n", __func__);
        return;
    }

    mutex_lock(&data->lock);
    ret = ist30xx_cmcs_test(data, ts_cmcs_bin, ts_cmcs_bin_size, CMCS_FLAG_CM);
    if (unlikely(ret)) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cmcs test fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);

    for (i = 0; i < tsp->ch_num.tx; i++) {
        for (j = 0; j < tsp->ch_num.rx; j++) {
            idx = (i * tsp->ch_num.rx) + j;
            type = check_tsp_type(data, i, j);

            if (type == TSP_CH_KEY)
                cm_key[key_count++] = (int)ts_cmcs_buf->cm[idx];
        }
    }

    snprintf(buf, sizeof(buf), "%d,%d", cm_key[0], cm_key[1]);
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_cm_value(void *dev_data)
{
    int idx = 0;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    idx = check_tsp_channel(data, tsp->ch_num.rx, tsp->ch_num.tx);
    if (idx < 0) { // Parameter parsing fail
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
    } else {
        snprintf(buf, sizeof(buf), "%d", ts_cmcs_buf->cm[idx]);
        sec->cmd_state = CMD_STATE_OK;
    }

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), [%d][%d]: %s\n", __func__,
            sec->cmd_param[0], sec->cmd_param[1], buf);
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void run_cmjit_test(void *dev_data)
{
    int i, j;
    int ret = 0;
    char buf[16] = { 0 };
    int type, idx;
    int min_val, max_val;

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    if ((ts_cmcs_bin == NULL) || (ts_cmcs_bin_size == 0)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), Binary is not correct!\n", __func__);
        return;
    }

    ret = ist30xx_get_cmcs_info(ts_cmcs_bin, ts_cmcs_bin_size);
    if (unlikely(ret)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp get cmcs infomation fail!\n", __func__);
        return;
    }

    mutex_lock(&data->lock);
    ret = ist30xx_cmcs_test(data, ts_cmcs_bin, ts_cmcs_bin_size,
            CMCS_FLAG_CMJIT);
    if (unlikely(ret)) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cmcs test fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);

    min_val = max_val = ts_cmcs_buf->cm_jit[0];
    for (i = 0; i < tsp->ch_num.tx; i++) {
        for (j = 0; j < tsp->ch_num.rx; j++) {
            idx = (i * tsp->ch_num.rx) + j;
            type = check_tsp_type(data, i, j);

            if ((type == TSP_CH_SCREEN) || (type == TSP_CH_GTX)) {
                max_val = max(max_val, (int)ts_cmcs_buf->cm_jit[idx]);
                min_val = min(min_val, (int)ts_cmcs_buf->cm_jit[idx]);
            }
        }
    }

    snprintf(buf, sizeof(buf), "%d,%d", min_val, max_val);
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_cmjit_value(void *dev_data)
{
    int idx = 0;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    idx = check_tsp_channel(data, tsp->ch_num.rx, tsp->ch_num.tx);
    if (idx < 0) { // Parameter parsing fail
        snprintf(buf, sizeof(buf), "%s", "NG");
        sec->cmd_state = CMD_STATE_FAIL;
    } else {
        snprintf(buf, sizeof(buf), "%d", ts_cmcs_buf->cm_jit[idx]);
        sec->cmd_state = CMD_STATE_OK;
    }

    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    tsp_info("%s(), [%d][%d]: %s\n", __func__,
            sec->cmd_param[0], sec->cmd_param[1], buf);
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void run_cmcs_test(void *dev_data)
{
    int ret = 0;
    char buf[16] = { 0 };

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if ((ts_cmcs_bin == NULL) || (ts_cmcs_bin_size == 0)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), Binary is not correct!\n", __func__);
        return;
    }

    ret = ist30xx_get_cmcs_info(ts_cmcs_bin, ts_cmcs_bin_size);
    if (unlikely(ret)) {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp get cmcs infomation fail!\n", __func__);
        return;
    }

    mutex_lock(&data->lock);
    ret = ist30xx_cmcs_test(data, ts_cmcs_bin, ts_cmcs_bin_size, CMCS_FLAG_CM);
    if (unlikely(ret)) {
        mutex_unlock(&data->lock);
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_warn("%s(), tsp cmcs test fail!\n", __func__);
        return;
    }
    mutex_unlock(&data->lock);

    snprintf(buf, sizeof(buf), "%s", "OK");
    tsp_info("%s(), %s\n", __func__, buf);

    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__, buf,
            strnlen(buf, sizeof(buf)));
}

void get_cm_array(void *dev_data)
{
    int i;
    int count = 0;
    int type;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx * tsp->ch_num.tx; i++) {
        type = check_tsp_type(data, i / tsp->ch_num.rx, i % tsp->ch_num.rx);
        if ((type == TSP_CH_UNKNOWN) || (type == TSP_CH_UNUSED))
            count += snprintf(msg, msg_len, "%d,", 0);
        else
            count += snprintf(msg, msg_len, "%d,", ts_cmcs_buf->cm[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

void get_slope0_array(void *dev_data)
{
    int i;
    int count = 0;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx * tsp->ch_num.tx; i++) {
        count += snprintf(msg, msg_len, "%d,", ts_cmcs_buf->slope0[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

void get_slope1_array(void *dev_data)
{
    int i;
    int count = 0;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx * tsp->ch_num.tx; i++) {
        count += snprintf(msg, msg_len, "%d,", ts_cmcs_buf->slope1[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}

void get_cs_array(void *dev_data)
{
    int i;
    int count = 0;
    int type;
    char *buf;
    const int msg_len = 16;
    char msg[msg_len];

    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    TSP_INFO *tsp = &data->tsp_info;

    set_default_result(sec);

    buf = kmalloc(IST30XX_MAX_NODE_NUM * 5, GFP_KERNEL);
    if (!buf) {
        tsp_info("%s: Couldn't Allocate memory\n", __func__);
        return;
    }
    memset(buf, 0, IST30XX_MAX_NODE_NUM * 5);

    for (i = 0; i < tsp->ch_num.rx * tsp->ch_num.tx; i++) {
        type = check_tsp_type(data, i / tsp->ch_num.rx, i % tsp->ch_num.rx);
        if ((type == TSP_CH_UNKNOWN) || (type == TSP_CH_UNUSED))
            count += snprintf(msg, msg_len, "%d,", 0);
        else
            count += snprintf(msg, msg_len, "%d,", ts_cmcs_buf->cs[i]);
        strncat(buf, msg, msg_len);
    }

    printk("\n");
    tsp_info("%s: %d\n", __func__, count - 1);
    sec->cmd_state = CMD_STATE_OK;
    set_cmd_result(sec, buf, count - 1);
    dev_info(&data->client->dev, "%s: %s(%d)\n", __func__, buf, count);
    kfree(buf);
}
#endif

void run_force_calibration(void *dev_data)
{
	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;
	int ret = 0;
	char buf[16] = { 0 };
#ifdef PAT_CONTROL
	u16 pdata_pat_function;
#endif

	set_default_result(sec);

	if(data->touch_pressed_num != 0){
		tsp_info("%s: return (finger cnt %d)\n", __func__, data->touch_pressed_num);
		sec->cmd_state = CMD_STATE_FAIL;
		snprintf(buf, sizeof(buf), "%s", "NG");
		set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
		return;
	}

	mutex_lock(&data->lock);
	ist30xx_reset(data, false);

#ifdef PAT_CONTROL
	tsp_info("%s: pat_function=%d afe_base=%04X cal_count=%X tune_fix_ver=%04X\n", 
				__func__, data->dt_data->pat_function, data->dt_data->afe_base, data->cal_count, data->tune_fix_ver);
	pdata_pat_function = data->dt_data->pat_function;
	data->dt_data->pat_function = PAT_CONTROL_FORCE_CMD;
#endif
	
	ret = ist30xx_calibrate(data, 1);
#ifdef PAT_CONTROL
	data->dt_data->pat_function = pdata_pat_function;
#endif
	if (ret) {
		mutex_unlock(&data->lock);
		sec->cmd_state = CMD_STATE_FAIL;
		snprintf(buf, sizeof(buf), "%s", "NG");
		set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
		tsp_warn("%s(), tsp calibration fail!\n", __func__);
		return;
	}
	mutex_unlock(&data->lock);

	snprintf(buf, sizeof(buf), "%s", "OK");
	tsp_info("%s(), %s\n", __func__, buf);

	sec->cmd_state = CMD_STATE_OK;
	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	dev_info(&data->client->dev, "%s: %s(%ld)\n",
				__func__, buf, strnlen(buf, sizeof(buf)));
}

void get_force_calibration(void *dev_data)
{
    int ret = 0;
	char buf[16] = { 0 };
    u32 calib_msg;

	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;

	set_default_result(sec);

    ret = ist30xx_read_cmd(data, eHCOM_GET_SLF_CAL_RESULT, &calib_msg);
    if (unlikely(ret)) {
        mutex_lock(&data->lock);
        ist30xx_reset(data, false);
        ist30xx_start(data);
        mutex_unlock(&data->lock);
        tsp_warn("Error Read SLF Calibration Result\n");
        snprintf(buf, sizeof(buf), "%s", "NG");
        goto err;        
    }

    if (((calib_msg & CALIB_MSG_MASK) != CALIB_MSG_VALID) ||
                (CALIB_TO_STATUS(calib_msg) != 0)) {
        snprintf(buf, sizeof(buf), "%s", "NG");
        goto err;
    }

    ret = ist30xx_read_cmd(data, eHCOM_GET_CAL_RESULT, &calib_msg);
    if (unlikely(ret)) {
        mutex_lock(&data->lock);
        ist30xx_reset(data, false);
        ist30xx_start(data);
        mutex_unlock(&data->lock);
        tsp_warn("Error Read MTL Calibration Result\n");
        snprintf(buf, sizeof(buf), "%s", "NG");
        goto err;        
    }
    
    if (((calib_msg & CALIB_MSG_MASK) == CALIB_MSG_VALID) &&
                (CALIB_TO_STATUS(calib_msg) == 0)) {
      	sec->cmd_state = CMD_STATE_OK;
        snprintf(buf, sizeof(buf), "%s", "OK");
    } else {
        snprintf(buf, sizeof(buf), "%s", "NG");
    }

err:    
	tsp_info("%s(), %s\n", __func__, buf);
	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	dev_info(&data->client->dev, "%s: %s(%ld)\n",
			__func__, buf, strnlen(buf, sizeof(buf)));
}

#ifdef PAT_CONTROL
void get_pat_information(void *dev_data)
{
	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;
	char buf[16] = { 0 };
	u32 *buf32;
	int ret;
	int len = 1;	//1~32

	set_default_result(sec);

	if (ist30xx_intr_wait(data, 30) < 0){
		tsp_info("%s : intr wait fail", __func__);
	        return;
	}

	buf32 = kzalloc(len * sizeof(u32), GFP_KERNEL);
	if (unlikely(!buf32)) {
		tsp_err("failed to allocate %s\n", __func__);
		return;
	}
	ret = ist30xx_read_sec_info(data, PAT_CAL_COUNT_FIX_VERSION, buf32, len);
	if (unlikely(ret)) {
		tsp_err("sec info read fail\n");
		kfree(buf32);
		return;
	}

	tsp_info("%s : [%2d]:%08X\n", __func__, len, buf32[0]);

	data->cal_count = ((buf32[0] & 0xff0000)>>16);
	data->tune_fix_ver = buf32[0] & 0xFFff;

	tsp_info("%s : P%02XT%04X", __func__, data->cal_count, data->tune_fix_ver);

	snprintf(buf, sizeof(buf), "P%02XT%04X", data->cal_count, data->tune_fix_ver);

	kfree(buf32);

	sec->cmd_state = CMD_STATE_OK;
	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	dev_info(&data->client->dev, "%s: %s(%ld)\n",
				__func__, buf, strnlen(buf, sizeof(buf)));
}

/* FACTORY TEST RESULT SAVING FUNCTION
 * bit 3 ~ 0 : OCTA Assy
 * bit 7 ~ 4 : OCTA module
 * param[0] : OCTA module(1) / OCTA Assy(2)
 * param[1] : TEST NONE(0) / TEST FAIL(1) / TEST PASS(2) : 2 bit
 */
static void get_tsp_test_result(void *dev_data)
{
	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;
	char buf[50] = { 0 };
	u32 *buf32;
	int ret;
	int len = 1;	//1~32
	
	set_default_result(sec);

	if (ist30xx_intr_wait(data, 30) < 0){
		tsp_info("%s : intr wait fail", __func__);
	        return;
	}

	buf32 = kzalloc(len * sizeof(u32), GFP_KERNEL);
	if (unlikely(!buf32)) {
		tsp_err("failed to allocate %s\n", __func__);
		return;
	}
	ret = ist30xx_read_sec_info(data, PAT_TSP_TEST_DATA, buf32, len);
	if (unlikely(ret)) {
		tsp_err("sec info read fail\n");
		kfree(buf32);
		return;
	}

	tsp_info("%s : [%2d]:%08X\n", __func__, len, buf32[0]);

	data->test_result.data[0] = buf32[0] & 0xff;
	kfree(buf32);
	
	tsp_info("%s : %X", __func__, data->test_result.data[0]);

	if (data->test_result.data[0] == 0xFF) {
		tsp_info("%s: clear factory_result as zero\n", __func__);
		data->test_result.data[0] = 0;
	}

	snprintf(buf, sizeof(buf), "M:%s, M:%d, A:%s, A:%d",
			data->test_result.module_result == 0 ? "NONE" :
				data->test_result.module_result == 1 ? "FAIL" : "PASS",
			data->test_result.module_count,
			data->test_result.assy_result == 0 ? "NONE" :
				data->test_result.assy_result == 1 ? "FAIL" : "PASS",
			data->test_result.assy_count);

	sec->cmd_state = CMD_STATE_OK;
	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	dev_info(&data->client->dev, "%s: %s(%ld)\n",
				__func__, buf, strnlen(buf, sizeof(buf)));
}

static void set_tsp_test_result(void *dev_data)
{
	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;
	char buf[16] = { 0 };
	u32 *buf32;
	u32 temp = 0;	
	int ret;
	int len = 1;	//1~32

	set_default_result(sec);

	if (ist30xx_intr_wait(data, 30) < 0){
		tsp_info("%s : intr wait fail", __func__);
	        return;
	}

	buf32 = kzalloc(len * sizeof(u32), GFP_KERNEL);
	if (unlikely(!buf32)) {
		tsp_err("failed to allocate %s\n", __func__);
		return;
	}
	ret = ist30xx_read_sec_info(data, PAT_TSP_TEST_DATA, buf32, len);
	if (unlikely(ret)) {
		tsp_err("sec info read fail\n");
		kfree(buf32);
		return;
	}

	tsp_info("%s : [%2d]:%08X\n", __func__, len, buf32[0]);

	data->test_result.data[0] = buf32[0] & 0xff;
	kfree(buf32);

	tsp_info("%s : %X", __func__, data->test_result.data[0]);

	if (data->test_result.data[0] == 0xFF) {
		tsp_info("%s: clear factory_result as zero\n", __func__);
		data->test_result.data[0] = 0;
	}

	if (sec->cmd_param[0] == TEST_OCTA_ASSAY) {
		data->test_result.assy_result = sec->cmd_param[1];
		if (data->test_result.assy_count < 3)
			data->test_result.assy_count++;

	} else if (sec->cmd_param[0] == TEST_OCTA_MODULE) {
		data->test_result.module_result = sec->cmd_param[1];
		if (data->test_result.module_count < 3)
			data->test_result.module_count++;
	}

	tsp_info("%s: [0x%X] M:%s, M:%d, A:%s, A:%d\n",
				__func__, data->test_result.data[0],
				data->test_result.module_result == 0 ? "NONE" :
					data->test_result.module_result == 1 ? "FAIL" : "PASS",
				data->test_result.module_count,
				data->test_result.assy_result == 0 ? "NONE" :
					data->test_result.assy_result == 1 ? "FAIL" : "PASS",
				data->test_result.assy_count);

	temp = data->test_result.data[0];

	ist30xx_write_sec_info(data, PAT_TSP_TEST_DATA, &temp, 1);

	snprintf(buf, sizeof(buf), "OK");

	sec->cmd_state = CMD_STATE_OK;
	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	dev_info(&data->client->dev, "%s: %s(%ld)\n",
				__func__, buf, strnlen(buf, sizeof(buf)));
}

#ifndef CONFIG_SAMSUNG_PRODUCT_SHIP
void ist30xx_read_sec_info_all(void *dev_data)
{
	int ret = 0;
	char buf[16] = { 0 };
	u32 *buf32;
	int len = 32;	//4~32 (0~32)
	int i;

	struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
	struct sec_factory *sec = (struct sec_factory *)&data->sec;

	set_default_result(sec);

	if (ist30xx_intr_wait(data, 30) < 0){
		tsp_info("%s : intr wait fail", __func__);
	        return;
	}

	buf32 = kzalloc(len * sizeof(u32), GFP_KERNEL);
	if (unlikely(!buf32)) {
		tsp_err("failed to allocate %s\n", __func__);
		return;
	}
	ret = ist30xx_read_sec_info(data, 0, buf32, len);
	if (unlikely(ret)) {
		tsp_err("sec info read fail\n");
	}

	for( i=len-1 ; i>0 ; i-=4) {
		tsp_info("%s : [%2d]:%08X %08X %08X %08X\n",
					__func__, i, buf32[i], buf32[i-1], buf32[i-2], buf32[i-3]);
	}

	kfree(buf32);

	snprintf(buf, sizeof(buf), "%s", "OK");
	tsp_info("%s(), %s\n", __func__, buf);

	mutex_lock(&sec->cmd_lock);
	sec->cmd_is_running = false;
	mutex_unlock(&sec->cmd_lock);

	sec->cmd_state = CMD_STATE_OK;
	set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
	dev_info(&data->client->dev, "%s: %s(%ld)\n",
				__func__, buf, strnlen(buf, sizeof(buf)));
}
#endif
#endif

static void check_ic_mode(void *dev_data)
{
    int ret = 0;
    char buf[16] = {0};
    u32 status = 0;
    u8 mode = TOUCH_STATUS_NORMAL_MODE;
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->status.power == 1) {
        ret = ist30xx_read_reg(data->client, IST30XX_HIB_TOUCH_STATUS, &status);
        if (unlikely(ret)) {
            tsp_err("%s(), Failed get the touch status data \n", __func__);
            sec->cmd_state = CMD_STATE_FAIL;
        } else {
            if ((status & TOUCH_STATUS_MASK) == TOUCH_STATUS_MAGIC) {
                if (GET_NOISE_MODE(status))
                    mode |= TOUCH_STATUS_NOISE_MODE;
                if (GET_WET_MODE(status))
                    mode |= TOUCH_STATUS_WET_MODE;
                sec->cmd_state = CMD_STATE_OK;
            } else {
                tsp_err("%s(), invalid touch status \n", __func__);
                sec->cmd_state = CMD_STATE_FAIL;
            }
        }
    } else {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_err("%s(), error currently power off \n", __func__);
    }

    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%d", mode);
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

    tsp_info("%s(), %s\n", __func__, buf);
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

static void get_wet_mode(void *dev_data)
{
    int ret = 0;
    char buf[16] = {0};
    u32 status = 0;
    u8 mode = TOUCH_STATUS_NORMAL_MODE;
    struct ist30xx_data *data = (struct ist30xx_data *)dev_data;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    set_default_result(sec);

    if (data->status.power == 1) {
        ret = ist30xx_read_reg(data->client, IST30XX_HIB_TOUCH_STATUS, &status);
        if (unlikely(ret)) {
            tsp_err("%s(), Failed get the touch status data \n", __func__);
            sec->cmd_state = CMD_STATE_FAIL;
        } else {
            if ((status & TOUCH_STATUS_MASK) == TOUCH_STATUS_MAGIC) {
                if (GET_WET_MODE(status))
                    mode = true;
                sec->cmd_state = CMD_STATE_OK;
            } else {
                tsp_err("%s(), invalid touch status \n", __func__);
                sec->cmd_state = CMD_STATE_FAIL;
            }
        }
    } else {
        sec->cmd_state = CMD_STATE_FAIL;
        tsp_err("%s(), error currently power off \n", __func__);
    }

    if (sec->cmd_state == CMD_STATE_OK)
        snprintf(buf, sizeof(buf), "%d", mode);
    else
        snprintf(buf, sizeof(buf), "%s", "NG");

    tsp_info("%s(), %s\n", __func__, buf);
    set_cmd_result(sec, buf, strnlen(buf, sizeof(buf)));
    dev_info(&data->client->dev, "%s: %s(%ld)\n", __func__,
            buf, strnlen(buf, sizeof(buf)));
}

/* sysfs: /sys/class/sec/tsp/close_tsp_test */
static ssize_t show_close_tsp_test(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    return snprintf(buf, FACTORY_BUF_SIZE, "%u\n", 0);
}

/* sysfs: /sys/class/sec/tsp/cmd */
static ssize_t store_cmd(struct device *dev, struct device_attribute
        *devattr, const char *buf, size_t count)
{
    struct ist30xx_data *data = dev_get_drvdata(dev);
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    struct i2c_client *client = data->client;

    char *cur, *start, *end;
    char msg[SEC_CMD_STR_LEN] = { 0 };
    int len, i;
    struct tsp_cmd *tsp_cmd_ptr = NULL;
    char delim = ',';
    bool cmd_found = false;
    int param_cnt = 0;
    int ret;

    if (sec->cmd_is_running == true) {
        dev_err(&client->dev, "tsp_cmd: other cmd is running.\n");
        tsp_err("tsp_cmd: other cmd is running.\n");
        goto err_out;
    }

    if (strlen(buf) >= SEC_CMD_STR_LEN) {
        tsp_err("%s: cmd length(strlen(buf)) is over (%s,%d)!!\n", __func__, buf, (int)strlen(buf));
        goto err_out;
    }

    if (count >= (unsigned int)SEC_CMD_STR_LEN) {
        tsp_err("%s: cmd length(count)) is over (%s,%d)!!\n", __func__, buf, (unsigned int)count);
        goto err_out;
    }

    /* check lock  */
    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = true;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_RUNNING;

    for (i = 0; i < ARRAY_SIZE(sec->cmd_param); i++)
        sec->cmd_param[i] = 0;

    len = (int)count;
    if (*(buf + len - 1) == '\n')
        len--;
    memset(sec->cmd, 0, ARRAY_SIZE(sec->cmd));
    memcpy(sec->cmd, buf, len);

    cur = strchr(buf, (int)delim);
    if (cur)
        memcpy(msg, buf, cur - buf);
    else
        memcpy(msg, buf, len);
    /* find command */
    list_for_each_entry(tsp_cmd_ptr, &sec->cmd_list_head, list) {
        if (!strcmp(msg, tsp_cmd_ptr->cmd_name)) {
            cmd_found = true;
            break;
        }
    }

    /* set not_support_cmd */
    if (!cmd_found) {
        list_for_each_entry(tsp_cmd_ptr, &sec->cmd_list_head, list) {
            if (!strcmp("not_support_cmd", tsp_cmd_ptr->cmd_name))
                break;
        }
    }

    /* parsing parameters */
    if (cur && cmd_found) {
        cur++;
        start = cur;
        memset(msg, 0, ARRAY_SIZE(msg));
        do {
            if (*cur == delim || cur - buf == len) {
                end = cur;
                memcpy(msg, start, end - start);
                *(msg + strlen(msg)) = '\0';
                ret = kstrtoint(msg, 10, \
                        sec->cmd_param + param_cnt);
                start = cur + 1;
                memset(msg, 0, ARRAY_SIZE(msg));
                param_cnt++;
            }
            cur++;
        } while ((cur - buf <= len) && (param_cnt < SEC_CMD_PARAM_NUM));
    }
    tsp_info("SEC CMD = %s\n", tsp_cmd_ptr->cmd_name);

    for (i = 0; i < param_cnt; i++)
        tsp_info("SEC CMD Param %d= %d\n", i, sec->cmd_param[i]);

    tsp_cmd_ptr->cmd_func(data);

err_out:
    return count;
}

/* sysfs: /sys/class/sec/tsp/cmd_status */
static ssize_t show_cmd_status(struct device *dev,
        struct device_attribute *devattr, char *buf)
{
    struct ist30xx_data *data = dev_get_drvdata(dev);
    struct sec_factory *sec = (struct sec_factory *)&data->sec;
    char msg[16] = { 0 };

    dev_info(&data->client->dev, "tsp cmd: status:%d\n", sec->cmd_state);

    if (sec->cmd_state == CMD_STATE_WAITING)
        snprintf(msg, sizeof(msg), "WAITING");
    else if (sec->cmd_state == CMD_STATE_RUNNING)
        snprintf(msg, sizeof(msg), "RUNNING");
    else if (sec->cmd_state == CMD_STATE_OK)
        snprintf(msg, sizeof(msg), "OK");
    else if (sec->cmd_state == CMD_STATE_FAIL)
        snprintf(msg, sizeof(msg), "FAIL");
    else if (sec->cmd_state == CMD_STATE_NA)
        snprintf(msg, sizeof(msg), "NOT_APPLICABLE");

    return snprintf(buf, FACTORY_BUF_SIZE, "%s\n", msg);
}

/* sysfs: /sys/class/sec/tsp/cmd_result */
static ssize_t show_cmd_result(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
    struct ist30xx_data *data = dev_get_drvdata(dev);
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    dev_info(&data->client->dev, "tsp cmd: result: %s\n", sec->cmd_result);

    mutex_lock(&sec->cmd_lock);
    sec->cmd_is_running = false;
    mutex_unlock(&sec->cmd_lock);

    sec->cmd_state = CMD_STATE_WAITING;

    return snprintf(buf, FACTORY_BUF_SIZE, "%s\n", sec->cmd_result);
}

/* sysfs: /sys/class/sec/sec_touchkey/touchkey_recent */
static ssize_t recent_sensitivity_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int sensitivity = 0;
    struct ist30xx_data *data = dev_get_drvdata(dev);

    sensitivity = ist30xx_get_key_sensitivity(data, 0);

    tsp_info("%s(), %d\n", __func__, sensitivity);

    return sprintf(buf, "%d", sensitivity);
}

/* sysfs: /sys/class/sec/sec_touchkey/touchkey_back */
static ssize_t back_sensitivity_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int sensitivity = 0;
    struct ist30xx_data *data = dev_get_drvdata(dev);

    sensitivity = ist30xx_get_key_sensitivity(data, 1);

    tsp_info("%s(), %d\n", __func__, sensitivity);

    return sprintf(buf, "%d", sensitivity);
}

/* sysfs: /sys/class/sec/sec_touchkey/touchkey_threshold */
static ssize_t touchkey_threshold_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int ret = 0;
    u32 val = 0;
    int threshold = 0;
    struct ist30xx_data *data = dev_get_drvdata(dev);

    ret = ist30xx_read_cmd(data, eHCOM_GET_TOUCH_TH, &val);
    if (unlikely(ret)) {
        ist30xx_reset(data, false);
        ist30xx_start(data);
        val = 0;
    }

    threshold = (int)((val >> 16) & 0xFFFF);

    tsp_info("%s(), %d (ret=%d)\n", __func__, threshold, ret);

    return sprintf(buf, "%d", threshold);
}

struct tsp_cmd tsp_cmds[] = {
	{ TSP_CMD("get_chip_vendor", get_chip_vendor), },
	{ TSP_CMD("get_chip_name", get_chip_name), },
	{ TSP_CMD("get_chip_id", get_chip_id), },
	{ TSP_CMD("fw_update", fw_update), },
	{ TSP_CMD("get_fw_ver_bin", get_fw_ver_bin), },
	{ TSP_CMD("get_fw_ver_ic", get_fw_ver_ic), },
	{ TSP_CMD("get_threshold", get_threshold), },
	{ TSP_CMD("get_checksum_data", get_checksum_data), },
	{ TSP_CMD("get_x_num", get_scr_x_num), },
	{ TSP_CMD("get_y_num", get_scr_y_num), },
	{ TSP_CMD("get_all_x_num", get_all_x_num), },
	{ TSP_CMD("get_all_y_num", get_all_y_num), },
	{ TSP_CMD("dead_zone_enable", dead_zone_enable), },
	{ TSP_CMD("clear_cover_mode", not_support_cmd), },
	{ TSP_CMD("glove_mode", not_support_cmd), },
	{ TSP_CMD("hover_enable", not_support_cmd), },
	{ TSP_CMD("spay_enable", spay_enable), },
	{ TSP_CMD("aod_enable", aod_enable), },
	{ TSP_CMD("set_aod_rect", set_aod_rect), },
	{ TSP_CMD("get_aod_rect", get_aod_rect), },
	{ TSP_CMD("get_cp_array", get_cp_array), },
	{ TSP_CMD("get_self_cp_array", get_self_cp_array), },
	{ TSP_CMD("run_reference_read", run_cdc_read), },
	{ TSP_CMD("get_reference", get_cdc_value), },
	{ TSP_CMD("run_self_reference_read", run_self_cdc_read), },
	{ TSP_CMD("get_self_reference", get_self_cdc_value), },
	{ TSP_CMD("get_rx_self_reference", get_rx_self_cdc_value), },
	{ TSP_CMD("get_tx_self_reference", get_tx_self_cdc_value), },
	{ TSP_CMD("run_reference_read_key", run_cdc_read_key), },
	{ TSP_CMD("run_cdc_read", run_cdc_read), },
	{ TSP_CMD("run_self_cdc_read", run_self_cdc_read), },
	{ TSP_CMD("run_cdc_read_key", run_cdc_read_key), },
	{ TSP_CMD("get_cdc_value", get_cdc_value), },
	{ TSP_CMD("get_cdc_all_data", get_cdc_all_data), },
	{ TSP_CMD("get_self_cdc_all_data", get_self_cdc_all_data), },
	{ TSP_CMD("get_cdc_array", get_cdc_array), },
	{ TSP_CMD("get_self_cdc_array", get_self_cdc_array), },
#ifdef IST30XX_USE_CMCS
	{ TSP_CMD("get_cm_all_data", get_cm_all_data), },
	{ TSP_CMD("get_slope0_all_data", get_slope0_all_data), },
	{ TSP_CMD("get_slope1_all_data", get_slope1_all_data), },
	{ TSP_CMD("get_cs_all_data", get_cs_all_data), },
	{ TSP_CMD("run_cm_test", run_cm_test), },
	{ TSP_CMD("get_cm_value", get_cm_value), },
	{ TSP_CMD("run_cm_test_key", run_cm_test_key), },
	{ TSP_CMD("run_jitter_read", run_cmjit_test), },
	{ TSP_CMD("get_jitter", get_cmjit_value), },
	{ TSP_CMD("run_cmcs_test", run_cmcs_test), },
	{ TSP_CMD("get_cm_array", get_cm_array), },
	{ TSP_CMD("get_slope0_array", get_slope0_array), },
	{ TSP_CMD("get_slope1_array", get_slope1_array), },
	{ TSP_CMD("get_cs_array", get_cs_array), },
	{ TSP_CMD("get_cs0_array", get_cs_array), },
	{ TSP_CMD("get_cs1_array", get_cs_array), },
	{ TSP_CMD("run_hvdd_test", run_hvdd_test), },
#endif
	{ TSP_CMD("get_config_ver", get_config_ver), },
	{ TSP_CMD("run_force_calibration", run_force_calibration), },
	{ TSP_CMD("get_force_calibration", get_force_calibration), },
	{ TSP_CMD("run_mis_cal_read", run_miscalibration), },
	{ TSP_CMD("get_mis_cal", get_miscalibration_value), },
#ifdef PAT_CONTROL
	{ TSP_CMD("get_pat_information", get_pat_information),},
	{ TSP_CMD("get_tsp_test_result", get_tsp_test_result),},
	{ TSP_CMD("set_tsp_test_result", set_tsp_test_result),},
#ifndef CONFIG_SAMSUNG_PRODUCT_SHIP
	{TSP_CMD("ium_read", ist30xx_read_sec_info_all),},
#endif
#endif
	{ TSP_CMD("check_ic_mode", check_ic_mode),},
	{ TSP_CMD("get_wet_mode", get_wet_mode),},
	{ TSP_CMD("not_support_cmd", not_support_cmd), },
};

/* sysfs: /sys/class/sec/tsp/cmd_list */
static ssize_t show_cmd_list(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
    char *buffer;
    char *temp;
    unsigned int ii = 0;
    int ret;

    buffer = kzalloc(FACTORY_BUF_SIZE, GFP_KERNEL);
    if (!buffer)
        goto err_alloc;

    temp = kzalloc(COMMAND_LENGTH, GFP_KERNEL);
    if (!temp)
        goto err_alloc_tmp;

    snprintf(buffer, COMMAND_LENGTH, "++factory command list++\n");

    if (!tsp_cmds[ii].cmd_name)
        goto err_cmd;

    while (strncmp(tsp_cmds[ii].cmd_name, "not_support_cmd", 16) != 0) {
        snprintf(temp, COMMAND_LENGTH, "%s\n", tsp_cmds[ii].cmd_name);
        strncat(buffer, temp, COMMAND_LENGTH);
        ii++;
    }

    ret = snprintf(buf, PAGE_SIZE, "%s\n", buffer);

    tsp_info("%s(%d)\n", buffer, ii);

    kfree(buffer);
    kfree(temp);

    return ret;
err_cmd:
    kfree(temp);
err_alloc_tmp:
    kfree(buffer);
err_alloc:
    return snprintf(buf, PAGE_SIZE, "NULL\n");
}

static ssize_t scrub_position_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);
	char buff[256] = { 0 };

	tsp_info("%s: scrub_id: %d, X:%d, Y:%d \n", __func__,
				data->scrub_id, data->scrub_x, data->scrub_y);

	snprintf(buff, sizeof(buff), "%d %d %d", data->scrub_id, data->scrub_x, data->scrub_y);

	data->scrub_id = 0;
	return snprintf(buf, PAGE_SIZE, "%s", buff);
}

static ssize_t read_ito_check_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);

	tsp_info("%s: %02X%02X%02X%02X\n", __func__,
				data->ito_test[0], data->ito_test[1],
				data->ito_test[2], data->ito_test[3]);

	return snprintf(buf, PAGE_SIZE, "%02X%02X%02X%02X",
					data->ito_test[0], data->ito_test[1],
					data->ito_test[2], data->ito_test[3]);
}

static ssize_t read_raw_check_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	tsp_info("%s\n", __func__);
	return snprintf(buf, PAGE_SIZE, "OK");
}

static ssize_t read_multi_count_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);
	char buffer[256]= { 0 };

	tsp_info("%s: %d\n", __func__, data->multi_count);
	snprintf(buffer, sizeof(buffer), "%d", data->multi_count);
	data->multi_count = 0;

	return snprintf(buf, PAGE_SIZE, "%s\n", buffer);
}

static ssize_t clear_multi_count_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);

	data->multi_count = 0;
	tsp_info("%s: clear\n", __func__);

	return count;
}

static ssize_t read_wet_mode_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);
	char buffer[256]= { 0 };

	tsp_info("%s: %d\n", __func__, data->wet_count);
	snprintf(buffer, sizeof(buffer), "%d", data->wet_count);
	data->wet_count = 0;

	return snprintf(buf, PAGE_SIZE, "%s\n", buffer);
}

static ssize_t read_comm_err_count_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);
	char buffer[256]= { 0 };

	tsp_info("%s: %d\n", __func__, data->comm_err_count);
	snprintf(buffer, sizeof(buffer), "%d", data->comm_err_count);
	data->comm_err_count = 0;

	return snprintf(buf, PAGE_SIZE, "%s\n", buffer);
}

static ssize_t clear_comm_err_count_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);

	data->comm_err_count = 0;
	tsp_info("%s: clear\n", __func__);

	return count;
}


static ssize_t read_module_id_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	struct ist30xx_data *data = dev_get_drvdata(dev);

	tsp_info("%s\n", __func__);

	return snprintf(buf, PAGE_SIZE, "IM%04X%02X%02X%02X",
		(data->fw.cur.fw_ver & 0xffff), data->test_result.data[0],
		data->cal_count, (data->tune_fix_ver & 0xff));
}

static ssize_t read_vendor_show(struct device *dev, struct device_attribute
        *devattr, char *buf)
{
	tsp_info("%s\n", __func__);

	return snprintf(buf, PAGE_SIZE, "IMAGIS");
}

/* sysfs - touchkey */
static DEVICE_ATTR(touchkey_menu, S_IRUGO, recent_sensitivity_show, NULL);
static DEVICE_ATTR(touchkey_recent, S_IRUGO, recent_sensitivity_show, NULL);
static DEVICE_ATTR(touchkey_back, S_IRUGO, back_sensitivity_show, NULL);
static DEVICE_ATTR(touchkey_threshold, S_IRUGO, touchkey_threshold_show, NULL);

/* sysfs - tsp */
static DEVICE_ATTR(close_tsp_test, S_IRUGO, show_close_tsp_test, NULL);
static DEVICE_ATTR(cmd, S_IWUSR | S_IWGRP, NULL, store_cmd);
static DEVICE_ATTR(cmd_status, S_IRUGO, show_cmd_status, NULL);
static DEVICE_ATTR(cmd_result, S_IRUGO, show_cmd_result, NULL);
static DEVICE_ATTR(cmd_list, S_IRUGO, show_cmd_list, NULL);
static DEVICE_ATTR(scrub_pos, S_IRUGO, scrub_position_show, NULL);

static DEVICE_ATTR(ito_check, S_IRUGO, read_ito_check_show, NULL);
static DEVICE_ATTR(raw_check, S_IRUGO, read_raw_check_show, NULL);
static DEVICE_ATTR(multi_count, S_IRUGO | S_IWUSR | S_IWGRP, read_multi_count_show, clear_multi_count_store);
static DEVICE_ATTR(wet_mode, S_IRUGO, read_wet_mode_show, NULL);
static DEVICE_ATTR(comm_err_count, S_IRUGO | S_IWUSR | S_IWGRP, read_comm_err_count_show, clear_comm_err_count_store);
static DEVICE_ATTR(module_id, S_IRUGO, read_module_id_show, NULL);
static DEVICE_ATTR(vendor, S_IRUGO, read_vendor_show, NULL);

static struct attribute *sec_tkey_attributes[] = {
    &dev_attr_touchkey_menu.attr,
    &dev_attr_touchkey_recent.attr,
    &dev_attr_touchkey_back.attr,
    &dev_attr_touchkey_threshold.attr,
    NULL,
};

static struct attribute *sec_touch_facotry_attributes[] = {
    &dev_attr_close_tsp_test.attr,
    &dev_attr_cmd.attr,
    &dev_attr_cmd_status.attr,
    &dev_attr_cmd_result.attr,
    &dev_attr_cmd_list.attr,
    &dev_attr_scrub_pos.attr,
    &dev_attr_ito_check.attr,
    &dev_attr_raw_check.attr,
    &dev_attr_multi_count.attr,
    &dev_attr_wet_mode.attr,
    &dev_attr_comm_err_count.attr,
    &dev_attr_module_id.attr,
    &dev_attr_vendor.attr,
    NULL,
};

static struct attribute_group sec_tkey_attr_group = {
    .attrs = sec_tkey_attributes,
};

static struct attribute_group sec_touch_factory_attr_group = {
    .attrs = sec_touch_facotry_attributes,
};

struct device *sec_touchkey;
struct device *sec_fac_dev;

int sec_touch_sysfs(struct ist30xx_data *data)
{
    int ret;

#ifdef IST30XX_USE_KEY
    /* /sys/class/sec/sec_touchkey */
	sec_touchkey = sec_device_create(data, "sec_touchkey");
    if (IS_ERR(sec_touchkey)) {
        tsp_err("Failed to create device (%s)!\n", "sec_touchkey");
        goto err_sec_touchkey;
    }
    /* /sys/class/sec/sec_touchkey/... */
    if (sysfs_create_group(&sec_touchkey->kobj, &sec_tkey_attr_group)) {
        tsp_err("Failed to create sysfs group(%s)!\n", "sec_touchkey");
        goto err_sec_touchkey_attr;
    }
#endif

    /* /sys/class/sec/tsp */
	sec_fac_dev = sec_device_create(data, "tsp");
    if (IS_ERR(sec_fac_dev)) {
        tsp_err("Failed to create device (%s)!\n", "tsp");
        goto err_sec_fac_dev;
    }
    ret = sysfs_create_link(&sec_fac_dev->kobj, &data->input_dev->dev.kobj,
            "input");
    if (ret < 0)
        tsp_err("%s: Failed to create input symbolic link\n", __func__);
    /* /sys/class/sec/tsp/... */
    if (sysfs_create_group(&sec_fac_dev->kobj, &sec_touch_factory_attr_group)) {
        tsp_err("Failed to create sysfs group(%s)!\n", "tsp");
        goto err_sec_fac_dev_attr;
    }

    return 0;

#ifdef IST30XX_USE_KEY
err_sec_fac_dev_attr:
    sec_device_destroy(2);
err_sec_fac_dev:
err_sec_touchkey_attr:
    sec_device_destroy(1);
err_sec_touchkey:
#else
err_sec_fac_dev_attr:
    sec_device_destroy(1);
err_sec_fac_dev:
#endif

    return -ENODEV;
}
EXPORT_SYMBOL(sec_touch_sysfs);

int sec_fac_cmd_init(struct ist30xx_data *data)
{
    int i;
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    INIT_LIST_HEAD(&sec->cmd_list_head);
    for (i = 0; i < ARRAY_SIZE(tsp_cmds); i++)
        list_add_tail(&tsp_cmds[i].list, &sec->cmd_list_head);

    sec->cmd_result_length = IST30XX_MAX_NODE_NUM *
            (sizeof(u32) / sizeof(char) + 1);
    sec->cmd_result = kzalloc(sec->cmd_result_length, GFP_KERNEL);
    if (!sec->cmd_result) {
        tsp_err("%s: cmd_result is not allocated memory\n", __func__);
        return -ENOMEM;
    }

    tsp_info("%s: cmd_result lenght is %d\n", __func__, sec->cmd_result_length);

    mutex_init(&sec->cmd_lock);
    sec->cmd_is_running = false;

    return 0;
}
EXPORT_SYMBOL(sec_fac_cmd_init);

void sec_touch_sysfs_remove(struct ist30xx_data *data)
{
    sysfs_remove_link(&sec_fac_dev->kobj, "input");
    sysfs_remove_group(&sec_fac_dev->kobj, &sec_touch_factory_attr_group);
    sysfs_remove_group(&sec_touchkey->kobj, &sec_tkey_attr_group);
    sec_device_destroy(2);
    sec_device_destroy(1);
}
EXPORT_SYMBOL(sec_touch_sysfs_remove);

void sec_fac_cmd_remove(struct ist30xx_data *data)
{
    struct sec_factory *sec = (struct sec_factory *)&data->sec;

    list_del(&sec->cmd_list_head);
    mutex_destroy(&sec->cmd_lock);
}
EXPORT_SYMBOL(sec_fac_cmd_remove);
#endif
