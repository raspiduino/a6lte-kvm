#ifndef __LINUX_CM36652_H

#define __CM36652_H__
#include <linux/types.h>

#ifdef __KERNEL__
struct cm36652_platform_data {
	int irq;		/* proximity-sensor irq gpio */
	int default_hi_thd;
	int default_low_thd;
	int cancel_hi_thd;
	int cancel_low_thd;
	int default_trim;

#if defined(CONFIG_SENSORS_CM36652_LEDA_EN_GPIO)
	int leden_gpio;
#endif
#if defined(CONFIG_SENSORS_CM36652_SENSOR_EN_GPIO)
	int sensoren_gpio;
#endif
};

extern struct class *sensors_class;
#endif
#endif
