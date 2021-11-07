/*
 * cyttsp5_i2c.c
 * Cypress TrueTouch(TM) Standard Product V5 I2C Module.
 * For use with Cypress Txx5xx parts.
 * Supported parts include:
 * TMA5XX
 *
 * Copyright (C) 2012-2013 Cypress Semiconductor
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, and only version 2, as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Contact Cypress Semiconductor at www.cypress.com <ttdrivers@cypress.com>
 *
 */

#include "cyttsp5_regs.h"

#include <linux/i2c.h>

#define CY_I2C_DATA_SIZE  (2 * 256)
#define I2C_RETRY_TIMES		3

#ifdef CONFIG_BATTERY_SAMSUNG
#include <linux/sec_batt.h>
#endif

static int cyttsp5_i2c_read_default(struct device *dev, void *buf, int size)
{
	struct i2c_client *client = to_i2c_client(dev);
	int rc;
	int retry;

	if (!buf || !size || size > CY_I2C_DATA_SIZE)
		return -EINVAL;

	for (retry = 0; retry < I2C_RETRY_TIMES; retry++) {
	rc = i2c_master_recv(client, buf, size);
	if (rc < 0)
		msleep(20);
	else
		break;
	}
	if (retry == I2C_RETRY_TIMES)
		dev_err(dev, "%s: I2C retry 3 times over [%d]\n", __func__, rc);

	return (rc < 0) ? rc : rc != size ? -EIO : 0;
}

static int cyttsp5_i2c_read_default_nosize(struct device *dev, u8 *buf, u32 max)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct i2c_msg msgs[2];
	u8 msg_count = 1;
	int rc;
	u32 size;
	int retry;

	if (!buf)
		return -EINVAL;

	msgs[0].addr = client->addr;
	msgs[0].flags = (client->flags & I2C_M_TEN) | I2C_M_RD;
	msgs[0].len = 2;
	msgs[0].buf = buf;
	for (retry = 0; retry < I2C_RETRY_TIMES; retry++) {
		rc = i2c_transfer(client->adapter, msgs, msg_count);
		if (rc < 0)
			msleep(20);
		else
			break;
	}
	if (retry == I2C_RETRY_TIMES)
		dev_err(dev, "%s: I2C retry 3 times over [%d]\n", __func__, rc);

	if (rc < 0 || rc != msg_count)
		return (rc < 0) ? rc : -EIO;

	size = get_unaligned_le16(&buf[0]);
	if (!size || size == 2)
		return 0;

	if (size > max)
		return -EINVAL;

	for (retry = 0; retry < I2C_RETRY_TIMES; retry++) {
		rc = i2c_master_recv(client, buf, size);
		if (rc < 0)
			msleep(20);
		else
			break;
	}
	if (retry == I2C_RETRY_TIMES)
		dev_err(dev, "%s: I2C retry 3 times over [%d]\n", __func__, rc);

	return (rc < 0) ? rc : rc != (int)size ? -EIO : 0;
}

static int cyttsp5_i2c_write_read_specific(struct device *dev, u8 write_len,
		u8 *write_buf, u8 *read_buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct i2c_msg msgs[2];
	u8 msg_count = 1;
	int rc;
	int retry;

	if (!write_buf || !write_len)
		return -EINVAL;

	msgs[0].addr = client->addr;
	msgs[0].flags = client->flags & I2C_M_TEN;
	msgs[0].len = write_len;
	msgs[0].buf = write_buf;
	for (retry = 0; retry < I2C_RETRY_TIMES; retry++) {
		rc = i2c_transfer(client->adapter, msgs, msg_count);
		if (rc < 0)
			msleep(20);
		else
			break;
	}
	if (retry == I2C_RETRY_TIMES)
		dev_err(dev, "%s: I2C retry 3 times over [%d]\n", __func__, rc);
	if (rc < 0 || rc != msg_count)
		return (rc < 0) ? rc : -EIO;
	else
		rc = 0;

	if (read_buf)
		rc = cyttsp5_i2c_read_default_nosize(dev, read_buf,
				CY_I2C_DATA_SIZE);

	return rc;
}

static struct cyttsp5_bus_ops cyttsp5_i2c_bus_ops = {
	.bustype = BUS_I2C,
	.read_default = cyttsp5_i2c_read_default,
	.read_default_nosize = cyttsp5_i2c_read_default_nosize,
	.write_read_specific = cyttsp5_i2c_write_read_specific,
};

static struct of_device_id cyttsp5_i2c_of_match[] = {
	{ .compatible = "cy,cyttsp5_i2c_adapter", },
	{ }
};
MODULE_DEVICE_TABLE(of, cyttsp5_i2c_of_match);

extern int lcdtype;

static int cyttsp5_i2c_probe(struct i2c_client *client,
	const struct i2c_device_id *i2c_id)
{
	struct device *dev = &client->dev;
#ifdef CONFIG_TOUCHSCREEN_CYTTSP5_DEVICETREE_SUPPORT
	const struct of_device_id *match;
#endif
	if (lcdtype == 0) {
		dev_err(dev, "%s tsp_connect : %d TSP driver unload\n", __func__, lcdtype);
		return -EIO;
	}
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(dev, "I2C functionality not Supported\n");
		return -EIO;
	}
#ifdef CONFIG_TOUCHSCREEN_CYTTSP5_DEVICETREE_SUPPORT
	match = of_match_device(of_match_ptr(cyttsp5_i2c_of_match), dev);
	if (match)
		cyttsp5_devtree_create_and_get_pdata(dev);
#endif

	return cyttsp5_probe(&cyttsp5_i2c_bus_ops, &client->dev, client->irq,
			  CY_I2C_DATA_SIZE);
}

static int cyttsp5_i2c_remove(struct i2c_client *client)
{
#ifdef CONFIG_TOUCHSCREEN_CYTTSP5_DEVICETREE_SUPPORT
	struct device *dev = &client->dev;
	const struct of_device_id *match;
#endif
	struct cyttsp5_core_data *cd = i2c_get_clientdata(client);

	cyttsp5_release(cd);

#ifdef CONFIG_TOUCHSCREEN_CYTTSP5_DEVICETREE_SUPPORT
	match = of_match_device(of_match_ptr(cyttsp5_i2c_of_match), dev);
	if (match)
		cyttsp5_devtree_clean_pdata(dev);
#endif

	return 0;
}

static void cyttsp5_i2c_shutdown(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	const struct of_device_id *match;
	struct cyttsp5_core_data *cd = i2c_get_clientdata(client);

	cyttsp5_release(cd);

	match = of_match_device(of_match_ptr(cyttsp5_i2c_of_match), dev);
	if (match)
		cyttsp5_devtree_clean_pdata(dev);
}

static const struct i2c_device_id cyttsp5_i2c_id[] = {
	{ CYTTSP5_I2C_NAME, 0, },
	{ }
};
MODULE_DEVICE_TABLE(i2c, cyttsp5_i2c_id);

static struct i2c_driver cyttsp5_i2c_driver = {
	.driver = {
		.name = CYTTSP5_I2C_NAME,
		.owner = THIS_MODULE,
		//.pm = &cyttsp5_pm_ops,
		.of_match_table = cyttsp5_i2c_of_match,
	},
	.probe = cyttsp5_i2c_probe,
	.remove = cyttsp5_i2c_remove,
	.shutdown = cyttsp5_i2c_shutdown,
	.id_table = cyttsp5_i2c_id,
};

static int __init cyttsp5_i2c_init(void)
{
#ifdef CONFIG_BATTERY_SAMSUNG
	int rc = 0;
	if (lpcharge == 1) {
		pr_notice("%s : Do not load driver due to : LPM %d\n", __func__, lpcharge);
		return rc;
	}
#endif
	return i2c_add_driver(&cyttsp5_i2c_driver);;
}
module_init(cyttsp5_i2c_init);

static void __exit cyttsp5_i2c_exit(void)
{
	i2c_del_driver(&cyttsp5_i2c_driver);
}
module_exit(cyttsp5_i2c_exit);

MODULE_ALIAS("i2c:cyttsp5");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cypress TrueTouch(R) Standard Product I2C driver");
MODULE_AUTHOR("Cypress Semiconductor <ttdrivers@cypress.com>");
