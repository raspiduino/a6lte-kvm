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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <asm/unaligned.h>

#include <asm/io.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/machine.h>

#include "ist30xxh.h"
#include "ist30xxh_update.h"

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
#include <linux/trustedui.h>
#endif

/******************************************************************************
 * Return value of Error
 * EPERM  : 1 (Operation not permitted)
 * ENOENT : 2 (No such file or directory)
 * EIO    : 5 (I/O error)
 * ENXIO  : 6 (No such device or address)
 * EINVAL : 22 (Invalid argument)
 *****************************************************************************/
int ist30xx_cmd_gesture(struct ist30xx_data *data, u16 value)
{
    int ret = -EIO;

#ifdef CONFIG_TOUCHSCREEN_IMAGIS_LPM_NO_RESET
    if (value == IST30XX_ENABLE) {
        data->g_reg.b.evt = 0;
        data->g_reg.b.evt_x = 0;
        data->g_reg.b.evt_y = 0;

        ret = ist30xx_write_cmd(data, IST30XX_HIB_INTR_MSG, IST30XX_LPM_VALUE);
        if (ret)
            tsp_err("fail to write LPM magic value.\n");

        ret = ist30xx_burst_write(data->client, IST30XX_HIB_GESTURE_REG,
                data->g_reg.full, sizeof(data->g_reg.full) / IST30XX_DATA_LEN);
        if (ret) {
            tsp_err("fail to write gesture reg map.\n");
            return ret;
        }
    }

    ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD,
            (eHCOM_GESTURE_EN << 16) | (value & 0xFFFF));
    if (ret) {
        tsp_err("fail to write gesture command.\n");
    } else {
        if (value == IST30XX_ENABLE) {
            tsp_info("%s, spay : %d, aod : %d\n", __func__,
                    (data->g_reg.b.ctrl & IST30XX_GETURE_CTRL_SPAY) ? 1 : 0,
                    (data->g_reg.b.ctrl & IST30XX_GETURE_CTRL_AOD) ? 1 : 0);
        } else {
            tsp_info("%s, normal mode\n", __func__);
        }
    }
#else
    data->g_reg.b.evt = 0;
    data->g_reg.b.evt_x = 0;
    data->g_reg.b.evt_y = 0;

    ret = ist30xx_burst_write(data->client, IST30XX_HIB_GESTURE_REG,
            data->g_reg.full, sizeof(data->g_reg.full) / IST30XX_DATA_LEN);
    if (ret) {
        tsp_err("fail to write gesture reg map.\n");
        return ret;
    }

    ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD,
            (eHCOM_GESTURE_EN << 16) | (value & 0xFFFF));
    if (ret)
        tsp_err("fail to write gesture mode.\n");
	else
        tsp_info("%s, spay : %d, aod : %d\n", __func__,
                (value & IST30XX_SPAY) ? 1 : 0, (value & IST30XX_AOD) ? 1 : 0);
#endif

    return ret;
}

int ist30xx_cmd_start_scan(struct ist30xx_data *data)
{
    int ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD,
            (eHCOM_FW_START << 16) | (IST30XX_ENABLE & 0xFFFF));

    data->status.noise_mode = true;

    return ret;
}

int ist30xx_cmd_calibrate(struct ist30xx_data *data)
{
    int ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD,
            (eHCOM_RUN_CAL_AUTO << 16));

    tsp_info("%s\n", __func__);

    return ret;
}

int ist30xx_cmd_miscalibrate(struct ist30xx_data *data)
{
    int ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD,
            (eHCOM_RUN_MISCAL_AUTO << 16));

    tsp_info("%s\n", __func__);

    return ret;
}

int ist30xx_cmd_hold(struct ist30xx_data *data, int enable)
{
    int ret;

    if (!data->initialized || (data->status.update == 1))
        return 0;

    ret = ist30xx_write_cmd(data, IST30XX_HIB_CMD, 
            (eHCOM_FW_HOLD << 16) | (enable & 0xFFFF));
    tsp_info("%s: FW HOLDE %s\n", __func__, enable ? "Enable" : "Disable");

    return ret;
}

int ist30xx_i2c_transfer(struct i2c_adapter *adap, struct i2c_msg *msgs,
             int msg_num, u8 *cmd_buf)
{
    int ret = 0;
    int idx = msg_num - 1;
    int size = msgs[idx].len;
    u8 *msg_buf = NULL;
    u8 *pbuf = NULL;
    int trans_size, max_size = 0;

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if (TRUSTEDUI_MODE_INPUT_SECURED & trustedui_get_current_mode()) {
		tsp_err("%s TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EIO;
	}
#endif

    if (msg_num == WRITE_CMD_MSG_LEN)
        max_size = I2C_MAX_WRITE_SIZE;
    else if (msg_num == READ_CMD_MSG_LEN)
        max_size = I2C_MAX_READ_SIZE;

    if (unlikely(max_size == 0)) {
        tsp_err("%s() : transaction size(%d)\n", __func__, max_size);
        return -EINVAL;
    }

    if (msg_num == WRITE_CMD_MSG_LEN) {
        msg_buf = kmalloc(max_size + IST30XX_ADDR_LEN, GFP_KERNEL);
        if (!msg_buf)
            return -ENOMEM;
        memcpy(msg_buf, cmd_buf, IST30XX_ADDR_LEN);
        pbuf = msgs[idx].buf;
    }

    while (size > 0) {
        trans_size = (size >= max_size ? max_size : size);

        msgs[idx].len = trans_size;
        if (msg_num == WRITE_CMD_MSG_LEN) {
            memcpy(&msg_buf[IST30XX_ADDR_LEN], pbuf, trans_size);
            msgs[idx].buf = msg_buf;
            msgs[idx].len += IST30XX_ADDR_LEN;
        }
        ret = i2c_transfer(adap, msgs, msg_num);
        if (unlikely(ret != msg_num)) {
            tsp_err("%s() : i2c_transfer failed(%d), num=%d\n",
                __func__, ret, msg_num);
            break;
        }

        if (msg_num == WRITE_CMD_MSG_LEN)
            pbuf += trans_size;
        else
            msgs[idx].buf += trans_size;

        size -= trans_size;
    }

    if (msg_num == WRITE_CMD_MSG_LEN)
        kfree(msg_buf);

    return ret;
}

int ist30xx_read_buf(struct i2c_client *client, u32 cmd, u32 *buf, u16 len)
{
    struct ist30xx_data *data = i2c_get_clientdata(client);
    int ret, i;
    u32 le_reg = cpu_to_be32(cmd);

    struct i2c_msg msg[READ_CMD_MSG_LEN] = {
        {
            .addr = client->addr,
            .flags = 0,
            .len = IST30XX_ADDR_LEN,
            .buf = (u8 *)&le_reg,
        },
        {
            .addr = client->addr,
            .flags = I2C_M_RD,
            .len = len * IST30XX_DATA_LEN,
            .buf = (u8 *)buf,
        },
    };

    ret = ist30xx_i2c_transfer(client->adapter, msg, READ_CMD_MSG_LEN, NULL);
    if (unlikely(ret != READ_CMD_MSG_LEN)){
        data->comm_err_count++;
        return -EIO;
    }

    for (i = 0; i < len; i++)
        buf[i] = cpu_to_be32(buf[i]);

    return 0;
}

int ist30xx_write_buf(struct i2c_client *client, u32 cmd, u32 *buf, u16 len)
{
    struct ist30xx_data *data = i2c_get_clientdata(client);
    int i;
    int ret;
    struct i2c_msg msg;
    u8 cmd_buf[IST30XX_ADDR_LEN];
    u8 msg_buf[IST30XX_DATA_LEN * (len + 1)];

    put_unaligned_be32(cmd, cmd_buf);

    if (likely(len > 0)) {
        for (i = 0; i < len; i++)
            put_unaligned_be32(buf[i], msg_buf + (i * IST30XX_DATA_LEN));
    } else {
        /* then add dummy data(4byte) */
        put_unaligned_be32(0, msg_buf);
        len = 1;
    }

    msg.addr = client->addr;
    msg.flags = 0;
    msg.len = len * IST30XX_DATA_LEN;
    msg.buf = msg_buf;

    ret = ist30xx_i2c_transfer(client->adapter, &msg, WRITE_CMD_MSG_LEN,
                   cmd_buf);
    if (unlikely(ret != WRITE_CMD_MSG_LEN)){
        data->comm_err_count++;
        return -EIO;
    }

    return 0;
}

int ist30xx_read_reg(struct i2c_client *client, u32 reg, u32 *buf)
{
    struct ist30xx_data *data = i2c_get_clientdata(client);
    int ret;
    u32 le_reg = cpu_to_be32(reg);

    struct i2c_msg msg[READ_CMD_MSG_LEN] = {
        {
            .addr = client->addr,
            .flags = 0,
            .len = IST30XX_ADDR_LEN,
            .buf = (u8 *)&le_reg,
        },
        {
            .addr = client->addr,
            .flags = I2C_M_RD,
            .len = IST30XX_DATA_LEN,
            .buf = (u8 *)buf,
        },
    };

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if (TRUSTEDUI_MODE_INPUT_SECURED & trustedui_get_current_mode()) {
		tsp_err("%s TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EIO;
	}
#endif

    ret = i2c_transfer(client->adapter, msg, READ_CMD_MSG_LEN);
    if (ret != READ_CMD_MSG_LEN) {
        data->comm_err_count++;
        tsp_err("%s: i2c failed (%d), cmd: %x\n", __func__, ret, reg);
        return -EIO;
    }
    *buf = cpu_to_be32(*buf);

    return 0;
}

int ist30xx_read_cmd(struct ist30xx_data *data, u32 cmd, u32 *buf)
{
    int ret;

    ret = ist30xx_cmd_hold(data, IST30XX_ENABLE);
    if (unlikely(ret))
        return ret;

    ist30xx_read_reg(data->client, IST30XX_DA_ADDR(cmd), buf);

    ret = ist30xx_cmd_hold(data, IST30XX_DISABLE);
    if (unlikely(ret)) {
        ist30xx_reset(data, false);
        return ret;
    }

    return ret;
}

int ist30xx_write_cmd(struct ist30xx_data *data, u32 cmd, u32 val)
{
    int ret;
    u8 msg_buf[IST30XX_ADDR_LEN + IST30XX_DATA_LEN];
    struct i2c_msg msg;

    put_unaligned_be32(cmd, msg_buf);
    put_unaligned_be32(val, msg_buf + IST30XX_ADDR_LEN);

    msg.addr = data->client->addr;
    msg.flags = 0;
    msg.len = IST30XX_ADDR_LEN + IST30XX_DATA_LEN;
    msg.buf = msg_buf;

#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
	if (TRUSTEDUI_MODE_INPUT_SECURED & trustedui_get_current_mode()) {
		tsp_err("%s TSP no accessible from Linux, TUI is enabled!\n", __func__);
		return -EIO;
	}
#endif

    ret = i2c_transfer(data->client->adapter, &msg, WRITE_CMD_MSG_LEN);
    if (ret != WRITE_CMD_MSG_LEN) {
        data->comm_err_count++;
        tsp_err("%s: i2c failed (%d), cmd: %x(%x)\n", __func__, ret, cmd, val);
        return -EIO;
    }

    if ((data->initialized || (data->status.update != 1)) && 
            !data->ignore_delay)
        ist30xx_delay(40);

    return 0;
}

int ist30xx_burst_read(struct i2c_client *client, u32 addr,
        u32 *buf32, u16 len, bool bit_en)
{
    int ret = 0;
    int i;
    u16 max_len = I2C_MAX_READ_SIZE / IST30XX_DATA_LEN;
    u16 remain_len = len;

    if (bit_en)
        addr = IST30XX_BA_ADDR(addr);

    for (i = 0; i < len; i += max_len) {
        if (remain_len < max_len) max_len = remain_len;

        ret = ist30xx_read_buf(client, addr, buf32, max_len);
        if (unlikely(ret)) {
            tsp_err("Burst fail, addr: %x\n", __func__, addr);
            return ret;
        }

        addr += max_len * IST30XX_DATA_LEN;
        buf32 += max_len;
        remain_len -= max_len;
    }

    return 0;
}

int ist30xx_burst_write(struct i2c_client *client, u32 addr,
        u32 *buf32, u16 len)
{
    int ret = 0;
    int i;
    u16 max_len = I2C_MAX_WRITE_SIZE / IST30XX_DATA_LEN;
    u16 remain_len = len;

    addr = IST30XX_BA_ADDR(addr);

    for (i = 0; i < len; i += max_len) {
        if (remain_len < max_len) max_len = remain_len;

        ret = ist30xx_write_buf(client, addr, buf32, max_len);
        if (unlikely(ret)) {
            tsp_err("Burst fail, addr: %x\n", __func__, addr);
            return ret;
        }

        addr += max_len * IST30XX_DATA_LEN;
        buf32 += max_len;
        remain_len -= max_len;
    }
    
    return 0;
}

int ts_power_enable(struct ist30xx_data *data, int en)
{
    struct regulator *regulator_avdd;
    int ret = 0;
    
    regulator_avdd = regulator_get(NULL, data->dt_data->regulator_avdd);
	if (IS_ERR(regulator_avdd)) {
		tsp_err("%s: Failed to get %s regulator.\n",
			 __func__, data->dt_data->regulator_avdd);
		return PTR_ERR(regulator_avdd);
	}

    tsp_info("%s %s\n", __func__, (en) ? "on" : "off");

    if (en) {
        ret = regulator_enable(regulator_avdd);
		if (ret) {
			tsp_err("%s: Failed to enable avdd: %d\n", __func__, ret);
			return ret;
		}
    } else {
        if (regulator_is_enabled(regulator_avdd))
			regulator_disable(regulator_avdd);
    }

    regulator_put(regulator_avdd);

	return ret;
}

int ist30xx_power_on(struct ist30xx_data *data, bool download)
{
    int rc = 0;
    if (data->status.power != 1) {
        tsp_info("%s()\n", __func__);
        /* VDD enable */
        /* VDDIO enable */
        rc = ts_power_enable(data, 1);
        if (download)
            ist30xx_delay(8);
        else
            ist30xx_delay(60);

        if (!rc) {
			data->ignore_delay = true;
			ist30xx_set_i2c_32bit(data);
    	    data->ignore_delay = false;
    		data->status.power = 1;
		}
    }

    return 0;
}

int ist30xx_power_off(struct ist30xx_data *data)
{
    int rc = 0;
    if (data->status.power != 0) {
        tsp_info("%s()\n", __func__);
#if 0
        data->ignore_delay = true;
		ist30xx_isp_enable(data, true);
        data->ignore_delay = false;
#endif
        /* VDDIO disable */
        /* VDD disable */
        rc = ts_power_enable(data, 0);
        if (!rc)
            data->status.power = 0;
        data->status.noise_mode = false;
    }

    return 0;
}

int ist30xx_reset(struct ist30xx_data *data, bool download)
{
    tsp_info("%s()\n", __func__);
    ist30xx_power_off(data);
    ist30xx_delay(30);
    ist30xx_power_on(data, download);

    return 0;
}

#ifndef CONFIG_TOUCHSCREEN_IMAGIS_LPM_NO_RESET
int ist30xx_internal_suspend(struct ist30xx_data *data)
{
    u16 value = 0;

    data->suspend = true;
    if (data->spay || data->aod) {
        ist30xx_reset(data, false);
        if (data->spay)
            value |= IST30XX_SPAY;
        if (data->aod)
            value |= IST30XX_AOD;
        ist30xx_cmd_gesture(data, value);
    } else {
        ist30xx_power_off(data);
    }

    return 0;
}

int ist30xx_internal_resume(struct ist30xx_data *data)
{
    data->suspend = false;
    if (data->status.power)
        ist30xx_reset(data, false);
    else
        ist30xx_power_on(data, false);

    return 0;
}
#endif

int ist30xx_init_system(struct ist30xx_data *data)
{
    int ret;

    // TODO : place additional code here.
    ret = ist30xx_power_on(data, false);
    if (ret) {
        tsp_err("%s: ist30xx_init_system failed (%d)\n", __func__, ret);
        return -EIO;
    }

#if 0
    ret = ist30xx_reset(data, false);
    if (ret) {
        tsp_err("%s: ist30xx_reset failed (%d)\n", __func__, ret);
        return -EIO;
    }
#endif

    return 0;
}
