/*
 * driver/../s2mm005.c - S2MM005 USBPD device driver
 *
 * Copyright (C) 2015 Samsung Electronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */
#include <linux/ccic/s2mm005.h>
#include <linux/ccic/s2mm005_ext.h>
#include <linux/ccic/s2mm005_fw.h>
#include <linux/usb_notify.h>

extern struct device *ccic_device;
extern struct pdic_notifier_struct pd_noti;
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
static enum dual_role_property fusb_drp_properties[] = {
	DUAL_ROLE_PROP_MODE,
	DUAL_ROLE_PROP_PR,
	DUAL_ROLE_PROP_DR,
};
#endif
////////////////////////////////////////////////////////////////////////////////
// function definition
////////////////////////////////////////////////////////////////////////////////
void s2mm005_int_clear(struct s2mm005_data *usbpd_data);
int s2mm005_read_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size);
int s2mm005_read_byte_flash(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size);
int s2mm005_write_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size);
int s2mm005_read_byte_16(const struct i2c_client *i2c, u16 reg, u8 *val);
int s2mm005_write_byte_16(const struct i2c_client *i2c, u16 reg, u8 val);
void s2mm005_rprd_mode_change(struct s2mm005_data *usbpd_data, u8 mode);
void s2mm005_manual_JIGON(struct s2mm005_data *usbpd_data, int mode);
void s2mm005_manual_LPM(struct s2mm005_data *usbpd_data, int cmd);
void s2mm005_control_option_command(struct s2mm005_data *usbpd_data, int cmd);
////////////////////////////////////////////////////////////////////////////////
//status machine of s2mm005 ccic
////////////////////////////////////////////////////////////////////////////////
//enum ccic_status {
//	state_cc_unknown = 0,
//	state_cc_idle,
//	state_cc_rid,
//	state_cc_updatefw,
//	state_cc_alternate,
//	state_cc_end=0xff,
//};
////////////////////////////////////////////////////////////////////////////////

int s2mm005_read_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size)
{
	int ret; u8 wbuf[2];
	struct i2c_msg msg[2];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = i2c->flags;
	msg[0].len = 2;
	msg[0].buf = wbuf;
	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = size;
	msg[1].buf = val;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, ARRAY_SIZE(msg));
	if (ret < 0)
		dev_err(&i2c->dev, "i2c read16 fail reg:0x%x error %d\n",
			reg, ret);
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

int s2mm005_read_byte_flash(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size)
{
	int ret; u8 wbuf[2];
	struct i2c_msg msg[2];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

	u8 W_DATA[1];
	udelay(20);
	W_DATA[0] = 0xAA;
	s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 1);
	udelay(20);

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = i2c->flags;
	msg[0].len = 2;
	msg[0].buf = wbuf;
	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = size;
	msg[1].buf = val;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, ARRAY_SIZE(msg));
	if (ret < 0)
		dev_err(&i2c->dev, "i2c read16 fail reg:0x%x error %d\n",
			reg, ret);
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

int s2mm005_write_byte(const struct i2c_client *i2c, u16 reg, u8 *val, u16 size)
{
	int ret = 0; u8 buf[258] = {0,};
	struct i2c_msg msg[1];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

	if (size > 256)
	{
		pr_err("I2C error, over the size %d", size);
		return -EIO;
	}

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = 0;
	msg[0].len = size+2;
	msg[0].buf = buf;

	buf[0] = (reg & 0xFF00) >> 8;
	buf[1] = (reg & 0xFF);
	memcpy(&buf[2], val, size);

	ret = i2c_transfer(i2c->adapter, msg, 1);
	if (ret < 0)
		dev_err(&i2c->dev, "i2c write fail reg:0x%x error %d\n", reg, ret);
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

int s2mm005_read_byte_16(const struct i2c_client *i2c, u16 reg, u8 *val)
{
	int ret; u8 wbuf[2], rbuf;
	struct i2c_msg msg[2];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = i2c->flags;
	msg[0].len = 2;
	msg[0].buf = wbuf;
	msg[1].addr = i2c->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = 1;
	msg[1].buf = &rbuf;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, 2);
	if (ret < 0)
		dev_err(&i2c->dev, "i2c read16 fail reg(0x%x), error %d\n",
			reg, ret);
	mutex_unlock(&usbpd_data->i2c_mutex);

	*val = rbuf;
	return rbuf;
}

int s2mm005_write_byte_16(const struct i2c_client *i2c, u16 reg, u8 val)
{
	int ret = 0; u8 wbuf[3];
	struct i2c_msg msg[1];
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

	mutex_lock(&usbpd_data->i2c_mutex);
	msg[0].addr = i2c->addr;
	msg[0].flags = 0;
	msg[0].len = 3;
	msg[0].buf = wbuf;

	wbuf[0] = (reg & 0xFF00) >> 8;
	wbuf[1] = (reg & 0xFF);
	wbuf[2] = (val & 0xFF);

	ret = i2c_transfer(i2c->adapter, msg, 1);
	if (ret < 0)
		dev_err(&i2c->dev, "i2c write fail reg(0x%x:%x), error %d\n",
				reg, val, ret);
	mutex_unlock(&usbpd_data->i2c_mutex);

	return ret;
}

void s2mm005_int_clear(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;

	s2mm005_write_byte_16(i2c, 0x10, 0x1);
}

void s2mm005_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	u8 R_DATA[1];
	int i;

	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

	printk("%s\n",__func__);
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x1C;
	W_DATA[3] = 0x10;
	W_DATA[4] = 0x01;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

void s2mm005_reset_enable(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	printk("%s\n",__func__);
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x5C;
	W_DATA[3] = 0x10;
	W_DATA[4] = 0x01;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

void s2mm005_system_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	u8 W_DATA[6];
	u8 R_DATA[6];

	W_DATA[0] =0x2;
	W_DATA[1] =0x20;  //word write
	W_DATA[2] =0x64;
	W_DATA[3] =0x10;

	s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 4);
	s2mm005_read_byte(i2c, 0x14, &R_DATA[0], 2);

	/* SYSTEM RESET */
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x02;
	W_DATA[2] = 0x68;
	W_DATA[3] = 0x10;
	W_DATA[4] = R_DATA[0];
	W_DATA[5] = R_DATA[1];

	s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 6);

}

void s2mm005_hard_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	struct device *i2c_dev = i2c->dev.parent->parent;

	struct pinctrl *i2c_pinctrl;

	i2c_lock_adapter(i2c->adapter);
	i2c_pinctrl = devm_pinctrl_get_select(i2c_dev, "hard_reset");
	if (IS_ERR(i2c_pinctrl))
		pr_err("could not set reset pins\n");
	printk("hard_reset: %04d %1d %01d\n", __LINE__, gpio_get_value(usbpd_data->s2mm005_sda), gpio_get_value(usbpd_data->s2mm005_scl));

	usleep_range(1 * 1000, 1 * 1000);
	i2c_pinctrl = devm_pinctrl_get_select(i2c_dev, "default");
	if (IS_ERR(i2c_pinctrl))
		pr_err("could not set default pins\n");
	usleep_range(8 * 1000, 8 * 1000);
	i2c_unlock_adapter(i2c->adapter);
	printk("hard_reset: %04d %1d %01d\n", __LINE__, gpio_get_value(usbpd_data->s2mm005_sda), gpio_get_value(usbpd_data->s2mm005_scl));
}

void s2mm005_sram_reset(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	printk("%s\n",__func__);
	/* boot control reset OM HIGH */
	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x1C;
	W_DATA[3] = 0x10;
	W_DATA[4] = 0x08;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

void s2mm005_reconnect(struct s2mm005_data *usbpd_data)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[3];
	printk("%s\n",__func__);
	W_DATA[0] = 0x03;
	W_DATA[1] = 0x02;
	W_DATA[2] = 0x00;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 3);
}

void s2mm005_manual_JIGON(struct s2mm005_data *usbpd_data, int mode)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];
	u8 R_DATA[1];
	int i;
	pr_info("usb: %s mode=%s (fw=0x%x)\n", __func__, mode? "High":"Low", usbpd_data->firm_ver[2]);
	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

	W_DATA[0] = 0x0F;
	if(mode) W_DATA[1] = 0x5;   // JIGON High
	else W_DATA[1] = 0x4;   // JIGON Low
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);

}

void s2mm005_manual_LPM(struct s2mm005_data *usbpd_data, int cmd)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[2];
	u8 R_DATA[1];
	int i;
	pr_info("usb: %s cmd=0x%x (fw=0x%x)\n", __func__, cmd, usbpd_data->firm_ver[2]);

	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

	W_DATA[0] = 0x0F;
	W_DATA[1] = cmd;
	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);
}

void s2mm005_control_option_command(struct s2mm005_data *usbpd_data, int cmd)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[2];
	u8 R_DATA[1];
	int i;
	printk("usb: %s cmd=0x%x (fw=0x%x)\n", __func__, cmd, usbpd_data->firm_ver[2]);

	/* for Wake up*/
	for(i=0; i<5; i++){
		R_DATA[0] = 0x00;
		REG_ADD = 0x8;
		s2mm005_read_byte(i2c, REG_ADD, R_DATA, 1);   //dummy read
	}
	udelay(10);

// 0x81 : Vconn control option command ON
// 0x82 : Vconn control option command OFF
// 0x83 : Water Detect option command ON
// 0x84 : Water Detect option command OFF
        REG_ADD = 0x10;
        W_DATA[0] = 0x03;
        W_DATA[1] = 0x80 | (cmd&0xF);
        s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);
}

static void s2mm005_new_toggling_control(struct s2mm005_data *usbpd_data, u8 mode)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[2];

	pr_info("%s, mode=0x%x\n",__func__, mode);

	W_DATA[0] = 0x03;
	W_DATA[1] = mode; // 0x12 : detach, 0x13 : SRC, 0x14 : SNK

	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 2);
}

static void s2mm005_toggling_control(struct s2mm005_data *usbpd_data, u8 mode)
{
	struct i2c_client *i2c = usbpd_data->i2c;
	uint16_t REG_ADD;
	u8 W_DATA[5];

	pr_info("%s, mode=0x%x\n",__func__, mode);

	W_DATA[0] = 0x02;
	W_DATA[1] = 0x01;
	W_DATA[2] = 0x00;
	W_DATA[3] = 0x50;
	W_DATA[4] = mode; // 0x1 : SRC, 0x2 : SNK, 0x3: DRP

	REG_ADD = 0x10;
	s2mm005_write_byte(i2c, REG_ADD, &W_DATA[0], 5);
}

#if defined(CONFIG_DUAL_ROLE_USB_INTF)
void s2mm005_rprd_mode_change(struct s2mm005_data *usbpd_data, u8 mode)
{
	pr_info("%s, mode=0x%x\n",__func__, mode);

	switch(mode)
	{
		case TYPE_C_ATTACH_DFP: // SRC
			s2mm005_new_toggling_control(usbpd_data, 0x12);
			msleep(1000);
			s2mm005_new_toggling_control(usbpd_data, 0x13);
		break;
		case TYPE_C_ATTACH_UFP: // SNK
			s2mm005_new_toggling_control(usbpd_data, 0x12);
			msleep(1000);
			s2mm005_new_toggling_control(usbpd_data, 0x14);
		break;
		case TYPE_C_ATTACH_DRP: // DRP
			s2mm005_toggling_control(usbpd_data, TYPE_C_ATTACH_DRP);
		break;	
	};
}
#endif

static irqreturn_t s2mm005_usbpd_irq_thread(int irq, void *data)
{
	struct s2mm005_data *usbpd_data = data;
	struct i2c_client *i2c = usbpd_data->i2c;
	int irq_gpio_status[2];
	u8 plug_attach_done;
	u8 pdic_attach = 0;
	uint32_t *pPRT_MSG = NULL;

	MSG_IRQ_STATUS_Type	MSG_IRQ_State;

	dev_info(&i2c->dev, "%d times\n", ++usbpd_data->wq_times);

	// Function State
	irq_gpio_status[0] = gpio_get_value(usbpd_data->irq_gpio);
	dev_info(&i2c->dev, "IRQ0:%02d\n", irq_gpio_status[0]);
	wake_lock_timeout(&usbpd_data->wlock, HZ);

	// Send attach event
	process_cc_attach(usbpd_data,&plug_attach_done);	

	if(usbpd_data->water_det){
		process_cc_water_det(usbpd_data);
		goto water;
	}

	// Get staus interrupt register
	process_cc_get_int_status(usbpd_data, pPRT_MSG ,&MSG_IRQ_State);

	// pd irq processing
	process_pd(usbpd_data, plug_attach_done, &pdic_attach, &MSG_IRQ_State);

	// RID processing
	process_cc_rid(usbpd_data);

water:
	/* ========================================== */
	//	s2mm005_int_clear(usbpd_data);
	irq_gpio_status[1] = gpio_get_value(usbpd_data->irq_gpio);
	dev_info(&i2c->dev, "IRQ1:%02d", irq_gpio_status[1]);

	return IRQ_HANDLED;
}

#if defined(CONFIG_OF)
static int of_s2mm005_usbpd_dt(struct device *dev,
			       struct s2mm005_data *usbpd_data)
{
	struct device_node *np = dev->of_node;
	int ret;

	usbpd_data->irq_gpio = of_get_named_gpio(np, "usbpd,usbpd_int", 0);
	usbpd_data->redriver_en = of_get_named_gpio(np, "usbpd,redriver_en", 0);

	usbpd_data->s2mm005_om = of_get_named_gpio(np, "usbpd,s2mm005_om", 0);
	usbpd_data->s2mm005_sda = of_get_named_gpio(np, "usbpd,s2mm005_sda", 0);
	usbpd_data->s2mm005_scl = of_get_named_gpio(np, "usbpd,s2mm005_scl", 0);

	np = of_find_all_nodes(NULL);
	ret = of_property_read_u32(np, "model_info-hw_rev", &usbpd_data->hw_rev);
	if (ret) {
		pr_info("%s: model_info-hw_rev is Empty\n", __func__);
		usbpd_data->hw_rev = 0;
	}

	dev_err(dev, "hw_rev:%02d usbpd_irq = %d redriver_en = %d s2mm005_om = %d\n"
		"s2mm005_sda = %d, s2mm005_scl = %d\n",
		usbpd_data->hw_rev,
		usbpd_data->irq_gpio, usbpd_data->redriver_en, usbpd_data->s2mm005_om,
		usbpd_data->s2mm005_sda, usbpd_data->s2mm005_scl);

	return 0;
}
#endif /* CONFIG_OF */

static int s2mm005_usbpd_probe(struct i2c_client *i2c,
			       const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(i2c->dev.parent);
	struct s2mm005_data *usbpd_data;
	int ret = 0;
#ifdef CONFIG_CCIC_LPM_ENABLE
	u8 check[8] = {0,};
#endif
	u8 W_DATA[8];
	u8 R_DATA[4];
	u8 temp, ftrim;
	int i;
	struct s2mm005_version chip_swver, fw_swver, hwver;
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	struct dual_role_phy_desc *desc;
	struct dual_role_phy_instance *dual_role;
#endif

	pr_info("%s\n", __func__);
	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
		dev_err(&i2c->dev, "i2c functionality check error\n");
		return -EIO;
	}
	usbpd_data = devm_kzalloc(&i2c->dev, sizeof(struct s2mm005_data), GFP_KERNEL);
	if (!usbpd_data) {
		dev_err(&i2c->dev, "Failed to allocate driver data\n");
		return -ENOMEM;
	}

#if defined(CONFIG_OF)
	if (i2c->dev.of_node)
		of_s2mm005_usbpd_dt(&i2c->dev, usbpd_data);
	else
		dev_err(&i2c->dev, "not found ccic dt! ret:%d\n", ret);
#endif
	ret = gpio_request(usbpd_data->irq_gpio, "s2mm005_irq");
	if (ret)
		goto err_free_irq_gpio;
	if (gpio_is_valid(usbpd_data->redriver_en)) {
		ret = gpio_request(usbpd_data->redriver_en, "s2mm005_redriver_en");
		if (ret)
			goto err_free_redriver_gpio;
		/* TODO REMOVE redriver always enable, Add sleep/resume */
		ret = gpio_direction_output(usbpd_data->redriver_en, 1);
		if (ret) {
			dev_err(&i2c->dev, "Unable to set input gpio direction, error %d\n", ret);
			goto err_free_redriver_gpio;
		}
	}

	gpio_direction_input(usbpd_data->irq_gpio);
	usbpd_data->irq = gpio_to_irq(usbpd_data->irq_gpio);
	dev_info(&i2c->dev, "%s:IRQ NUM %d\n", __func__, usbpd_data->irq);

	usbpd_data->dev = &i2c->dev;
	usbpd_data->i2c = i2c;
	i2c_set_clientdata(i2c, usbpd_data);
	dev_set_drvdata(ccic_device, usbpd_data);
	device_init_wakeup(usbpd_data->dev, 1);
	pd_noti.pusbpd = usbpd_data;
	mutex_init(&usbpd_data->i2c_mutex);

	/* Init */
	usbpd_data->p_prev_rid = -1;
	usbpd_data->prev_rid = -1;
	usbpd_data->cur_rid = -1;
	usbpd_data->is_dr_swap = 0;
	usbpd_data->is_pr_swap = 0;
	usbpd_data->pd_state = 0;
	usbpd_data->func_state = 0;
	usbpd_data->data_role = 0;
	usbpd_data->is_host = 0;
	usbpd_data->is_client = 0;
	usbpd_data->manual_lpm_mode = 0;
	usbpd_data->water_det = 0;
	usbpd_data->try_state_change = 0;
	wake_lock_init(&usbpd_data->wlock, WAKE_LOCK_SUSPEND,
		       "s2mm005-intr");

#if defined(CONFIG_CCIC_NOTIFIER)
	/* Create a work queue for the ccic irq thread */
	usbpd_data->ccic_wq
		= create_singlethread_workqueue("ccic_irq_event");
	 if (!usbpd_data->ccic_wq) {
		pr_err("%s failed to create work queue\n", __func__);
		ret = -ENOMEM;
		goto err_free_redriver_gpio;
	 }
#endif

	dev_err(&i2c->dev, "probed, irq %d\n", usbpd_data->irq_gpio);

	s2mm005_get_chip_hwversion(usbpd_data, &hwver);
	pr_err("%s CHIP HWversion %2x %2x %2x %2x\n", __func__,
	       hwver.main[2] , hwver.main[1], hwver.main[0], hwver.boot);
	if (hwver.boot <= 2) {
		W_DATA[0] =0x02; W_DATA[1] =0x40; W_DATA[2] =0x04; W_DATA[3] =0x11;
		s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 4);
		s2mm005_read_byte(i2c, 0x14, &R_DATA[0], 4);
		pr_err("ftrim:%02X %02X %02X %02X\n", R_DATA[0], R_DATA[1], R_DATA[2], R_DATA[3]);

		ftrim = ((R_DATA[1] & 0xF8) >> 3) - 2;
		temp = R_DATA[1] & 0x7;
		R_DATA[1] = (ftrim << 3) + temp;
		pr_err("ftrim:%02X %02X %02X %02X\n", R_DATA[0], R_DATA[1], R_DATA[2], R_DATA[3]);

		W_DATA[0] = 0x02; W_DATA[1] = 0x04; W_DATA[2] = 0x04; W_DATA[3] = 0x11;
		W_DATA[4] = R_DATA[0]; W_DATA[5] = R_DATA[1]; W_DATA[6] = R_DATA[2]; W_DATA[7] = R_DATA[3];
		s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 8);

		W_DATA[0] =0x02; W_DATA[1] =0x40; W_DATA[2] =0x04; W_DATA[3] =0x11;
		s2mm005_write_byte(i2c, 0x10, &W_DATA[0], 4);
		s2mm005_read_byte(i2c, 0x14, &R_DATA[0], 4);
		pr_err("ftrim:%02X %02X %02X %02X\n", R_DATA[0], R_DATA[1], R_DATA[2], R_DATA[3]);

	}

	for (i=0; i<2; i++) {
		s2mm005_get_chip_swversion(usbpd_data, &chip_swver);
		pr_err("%s CHIP SWversion %2x %2x %2x %2x\n", __func__,
		       chip_swver.main[2] , chip_swver.main[1], chip_swver.main[0], chip_swver.boot);
		if(chip_swver.main[0] && (chip_swver.main[0] != 0xff))
			break;
	}
	s2mm005_get_fw_version(&fw_swver, chip_swver.boot, usbpd_data->hw_rev);
	pr_err("%s SRC SWversion:%2x,%2x,%2x,%2x\n",__func__,
		fw_swver.main[2], fw_swver.main[1], fw_swver.main[0], fw_swver.boot);

	pr_err("%s: FW UPDATE boot:%01d hw_rev:%02d\n", __func__, chip_swver.boot, usbpd_data->hw_rev);

	usbpd_data->fw_product_num = fw_swver.main[2];

#ifdef CONFIG_SEC_FACTORY
	if (chip_swver.main[0] != fw_swver.main[0])
		s2mm005_flash_fw(usbpd_data,chip_swver.boot);
#else
        if (chip_swver.main[0] < fw_swver.main[0])
		s2mm005_flash_fw(usbpd_data,chip_swver.boot);
	else if ((((chip_swver.main[2] == 0xff) && (chip_swver.main[1] == 0xa5) && (chip_swver.main[0] == 0xa7))   || chip_swver.main[2] == 0x00) &&
			fw_swver.main[2] != 0x0)  //extra case, factory or old version (for dream)
				s2mm005_flash_fw(usbpd_data,chip_swver.boot);
#endif

	s2mm005_get_chip_swversion(usbpd_data, &chip_swver);
	pr_err("%s CHIP SWversion %2x %2x %2x %2x\n", __func__,
	       chip_swver.main[2] , chip_swver.main[1], chip_swver.main[0], chip_swver.boot);

	store_ccic_version(&hwver.main[0], &chip_swver.main[0], &chip_swver.boot);

	usbpd_data->firm_ver[0] = chip_swver.main[2];
	usbpd_data->firm_ver[1] = chip_swver.main[1];
	usbpd_data->firm_ver[2] = chip_swver.main[0];
	usbpd_data->firm_ver[3] = chip_swver.boot;

#ifdef CONFIG_CCIC_LPM_ENABLE
	if (chip_swver.main[0] >= 0xE) {
		pr_err("LPM_ENABLE\n");

		check[0] = 0x0F;
		check[1] = 0x06;
		s2mm005_write_byte(i2c, 0x10, &check[0], 2);
	}
#endif

#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	desc =
		devm_kzalloc(&i2c->dev,
				 sizeof(struct dual_role_phy_desc), GFP_KERNEL);
	if (!desc) {
		pr_err("unable to allocate dual role descriptor\n");
		goto err_init_irq;
	}

	desc->name = "otg_default";
	desc->supported_modes = DUAL_ROLE_SUPPORTED_MODES_DFP_AND_UFP;
	desc->get_property = dual_role_get_local_prop;
	desc->set_property = dual_role_set_prop;
	desc->properties = fusb_drp_properties;
	desc->num_properties = ARRAY_SIZE(fusb_drp_properties);
	desc->property_is_writeable = dual_role_is_writeable;
	dual_role =
		devm_dual_role_instance_register(&i2c->dev, desc);
	dual_role->drv_data = usbpd_data;
	usbpd_data->dual_role = dual_role;
	usbpd_data->desc = desc;
	init_completion(&usbpd_data->reverse_completion);
	INIT_DELAYED_WORK(&usbpd_data->role_swap_work, role_swap_check);
#endif
#if defined(CONFIG_CCIC_ALTERNATE_MODE)
	usbpd_data->alternate_state = 0;
	usbpd_data->acc_type = 0;
	ccic_register_switch_device(1);
	INIT_DELAYED_WORK(&usbpd_data->acc_detach_work, acc_detach_check);
#endif
	fp_select_pdo = s2mm005_select_pdo;
	ret = request_threaded_irq(usbpd_data->irq, NULL, s2mm005_usbpd_irq_thread,
		(IRQF_TRIGGER_FALLING | IRQF_NO_SUSPEND | IRQF_ONESHOT), "s2mm005-usbpd", usbpd_data);
	if (ret) {
		dev_err(&i2c->dev, "Failed to request IRQ %d, error %d\n", usbpd_data->irq, ret);
		goto err_init_irq;
	}

	s2mm005_int_clear(usbpd_data);
	return ret;

err_init_irq:
	if (usbpd_data->irq) {
		free_irq(usbpd_data->irq, usbpd_data);
		usbpd_data->irq = 0;
	}
err_free_redriver_gpio:
	gpio_free(usbpd_data->redriver_en);
err_free_irq_gpio:
	wake_lock_destroy(&usbpd_data->wlock);
	gpio_free(usbpd_data->irq_gpio);
	kfree(usbpd_data);
	return ret;
}

static int s2mm005_usbpd_remove(struct i2c_client *i2c)
{
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
	struct s2mm005_data *usbpd_data = dev_get_drvdata(ccic_device);

	devm_dual_role_instance_unregister(usbpd_data->dev, usbpd_data->dual_role);
	devm_kfree(usbpd_data->dev, usbpd_data->desc);
#endif
#if defined(CONFIG_CCIC_ALTERNATE_MODE)
	ccic_register_switch_device(0);
#endif
	wake_lock_destroy(&usbpd_data->wlock);

	return 0;
}

static void s2mm005_usbpd_shutdown(struct i2c_client *i2c)
{
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

	disable_irq(usbpd_data->irq);

	if ((usbpd_data->cur_rid != RID_523K) &&
	    (usbpd_data->cur_rid != RID_619K) &&
	    (!usbpd_data->manual_lpm_mode))
		s2mm005_reset(usbpd_data);
}

#if defined(CONFIG_PM)
static int s2mm005_suspend(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	pr_info("%s:%s\n", USBPD005_DEV_NAME, __func__);
#endif /* CONFIG_SAMSUNG_PRODUCT_SHIP */

	if (device_may_wakeup(dev))
		enable_irq_wake(usbpd_data->irq);

	disable_irq(usbpd_data->irq);

	return 0;
}

static int s2mm005_resume(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct s2mm005_data *usbpd_data = i2c_get_clientdata(i2c);

#if !defined(CONFIG_SAMSUNG_PRODUCT_SHIP)
	pr_info("%s:%s\n", USBPD005_DEV_NAME, __func__);
#endif /* CONFIG_SAMSUNG_PRODUCT_SHIP */

	if (device_may_wakeup(dev))
		disable_irq_wake(usbpd_data->irq);

	enable_irq(usbpd_data->irq);

	return 0;
}
#else
#define s2mm005_suspend	NULL
#define s2mm005_resume		NULL
#endif /* CONFIG_PM */

static const struct i2c_device_id s2mm005_usbpd_id[] = {
	{ USBPD005_DEV_NAME, 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, s2mm005_usbpd_id);

#if defined(CONFIG_OF)
static struct of_device_id s2mm005_i2c_dt_ids[] = {
	{ .compatible = "sec-s2mm005,i2c" },
	{ }
};
#endif /* CONFIG_OF */

#if defined(CONFIG_PM)
const struct dev_pm_ops s2mm005_pm = {
	.suspend = s2mm005_suspend,
	.resume = s2mm005_resume,
};
#endif /* CONFIG_PM */

static struct i2c_driver s2mm005_usbpd_driver = {
	.driver		= {
		.name	= USBPD005_DEV_NAME,
#if defined(CONFIG_PM)
		.pm	= &s2mm005_pm,
#endif /* CONFIG_PM */
#if defined(CONFIG_OF)
		.of_match_table	= s2mm005_i2c_dt_ids,
#endif /* CONFIG_OF */
	},
	.probe		= s2mm005_usbpd_probe,
	//.remove		= __devexit_p(s2mm005_usbpd_remove),
	.remove		= s2mm005_usbpd_remove,
	.shutdown	= s2mm005_usbpd_shutdown,
	.id_table	= s2mm005_usbpd_id,
};

static int __init s2mm005_usbpd_init(void)
{
	return i2c_add_driver(&s2mm005_usbpd_driver);
}
module_init(s2mm005_usbpd_init);

static void __exit s2mm005_usbpd_exit(void)
{
	i2c_del_driver(&s2mm005_usbpd_driver);
}
module_exit(s2mm005_usbpd_exit);

MODULE_DESCRIPTION("s2mm005 USB PD driver");
MODULE_LICENSE("GPL");
