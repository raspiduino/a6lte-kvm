/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Exynos-SnapShot debugging framework for Exynos SoC
 *
 * Author: Hosung Kim <Hosung0.kim@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef EXYNOS_SNAPSHOT_H
#define EXYNOS_SNAPSHOT_H

#ifdef CONFIG_EXYNOS_SNAPSHOT
#include <asm/ptrace.h>
#include "exynos-ss-soc.h"

/* mandatory */
extern void exynos_ss_task(int cpu, void *v_task);
extern void exynos_ss_work(void *worker, void *work, void *fn, int en);
extern void exynos_ss_cpuidle(int index, unsigned state, int diff, int en);
extern void exynos_ss_suspend(void *fn, void *dev, int en);
extern void exynos_ss_irq(int irq, void *fn, unsigned int val, int en);
extern int exynos_ss_try_enable(const char *name, unsigned long long duration);
extern int exynos_ss_set_enable(const char *name, int en);
extern int exynos_ss_get_enable(const char *name, bool init);
extern int exynos_ss_save_context(void *regs);
extern int exynos_ss_save_reg(void *regs);
extern int exynos_ss_dump_panic(char *str, size_t len);
extern int exynos_ss_prepare_panic(void);
extern int exynos_ss_post_panic(void);
extern int exynos_ss_post_reboot(void);
extern int exynos_ss_set_hardlockup(int);
extern int exynos_ss_get_hardlockup(void);
extern unsigned int exynos_ss_get_item_size(char *);
extern unsigned int exynos_ss_get_item_paddr(char *);
extern void exynos_ss_panic_handler_safe(struct pt_regs *regs);
#ifdef CONFIG_EXYNOS_DRAMTEST
extern int disable_mc_powerdn(void);
#endif

/* option */
#ifdef CONFIG_EXYNOS_SNAPSHOT_REGULATOR
extern void exynos_ss_regulator(char* f_name, unsigned int addr, unsigned int volt, int en);
#else
#define exynos_ss_regulator(a,b,c,d)         do { } while(0)
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_THERMAL
extern void exynos_ss_thermal(void *data, unsigned int temp, char *name, unsigned int max_cooling);
#else
#define exynos_ss_thermal(a,b,c,d)	do { } while(0)
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_MBOX
extern void exynos_ss_mailbox(void *msg, int mode, char* f_name, void *volt);
#else
#define exynos_ss_mailbox(a,b,c,d)         do { } while(0)
#endif

#ifndef CONFIG_EXYNOS_SNAPSHOT_MINIMIZED_MODE
extern void exynos_ss_clockevent(unsigned long long clc, int64_t delta, void *next_event);
extern void exynos_ss_printk(const char *fmt, ...);
extern void exynos_ss_printkl(size_t msg, size_t val);
#else
#define exynos_ss_clockevent(a,b,c)	do { } while(0)
#define exynos_ss_printk(...)		do { } while(0)
#define exynos_ss_printkl(a,b)		do { } while(0)
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_IRQ_DISABLED
extern void exynos_ss_irqs_disabled(unsigned long flags);
#else
#define exynos_ss_irqs_disabled(a)	do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_HRTIMER
extern void exynos_ss_hrtimer(void *timer, s64 *now, void *fn, int en);
#else
#define exynos_ss_hrtimer(a,b,c,d)	do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_REG
extern void exynos_ss_reg(unsigned int read, size_t val, size_t reg, int en);
#else
#define exynos_ss_reg(a,b,c,d)		do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_SPINLOCK
extern void exynos_ss_spinlock(void *lock, int en);
#else
#define exynos_ss_spinlock(a,b)		do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_CLK
struct clk;
extern void exynos_ss_clk(void *clock, const char *func_name, int mode);
#else
#define exynos_ss_clk(a,b,c)		do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_FREQ
void exynos_ss_freq(int type, unsigned long old_freq, unsigned long target_freq, int en);
#else
#define exynos_ss_freq(a,b,c,d)	do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_IRQ_EXIT
extern void exynos_ss_irq_exit(unsigned int irq, unsigned long long start_time);
#define exynos_ss_irq_exit_var(v)	do {	v = cpu_clock(raw_smp_processor_id());	\
					} while(0)
#else
#define exynos_ss_irq_exit(a,b)		do { } while(0);
#define exynos_ss_irq_exit_var(v)	do {	v = 0; } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_PSTORE
extern int exynos_ss_hook_pmsg(char *buffer, size_t count);
#else
#define exynos_ss_hook_pmsg(a,b)	do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_CRASH_KEY
void exynos_ss_check_crash_key(unsigned int code, int value);
#else
#define exynos_ss_check_crash_key(a,b)	do { } while(0);
#endif

#ifdef CONFIG_EXYNOS_SNAPSHOT_SFRDUMP
void exynos_ss_dump_sfr(void);
#else
#define exynos_ss_dump_sfr()		do { } while(0)
#endif

extern void exynos_ss_i2c_clk(struct clk *clk, int bus_id, int en);

#else
#define exynos_ss_task(a,b)		do { } while(0)
#define exynos_ss_work(a,b,c,d)		do { } while(0)
#define exynos_ss_clockevent(a,b,c)	do { } while(0)
#define exynos_ss_cpuidle(a,b,c,d)	do { } while(0)
#define exynos_ss_suspend(a,b,c)	do { } while(0)
#define exynos_ss_regulator(a,b,c,d)	do { } while(0)
#define exynos_ss_thermal(a,b,c,d)	do { } while(0)
#define exynos_ss_mailbox(a,b,c,d)	do { } while(0)
#define exynos_ss_irq(a,b,c,d)		do { } while(0)
#define exynos_ss_irq_exit(a,b)		do { } while(0)
#define exynos_ss_irqs_disabled(a)	do { } while(0)
#define exynos_ss_spinlock(a,b)		do { } while(0)
#define exynos_ss_clk(a,b,c)		do { } while(0)
#define exynos_ss_freq(a,b,c,d)		do { } while(0)
#define exynos_ss_irq_exit_var(v)	do { v = 0; } while(0)
#define exynos_ss_reg(a,b,c,d)		do { } while(0)
#define exynos_ss_hrtimer(a,b,c,d)	do { } while(0)
#define exynos_ss_hook_pmsg(a,b)	do { } while(0)
#define exynos_ss_printk(...)		do { } while(0)
#define exynos_ss_printkl(a,b)		do { } while(0)
#define exynos_ss_save_context(a)	do { } while(0)
#define exynos_ss_try_enable(a,b)	do { } while(0)
#define exynos_ss_set_enable(a,b)	do { } while(0)
#define exynos_ss_get_enable(a)		do { } while(0)
#define exynos_ss_dump_panic(a,b)	do { } while(0)
#define exynos_ss_dump_sfr()		do { } while(0)
#define exynos_ss_prepare_panic()	do { } while(0)
#define exynos_ss_post_panic()		do { } while(0)
#define exynos_ss_post_reboot()		do { } while(0)
#define exynos_ss_set_hardlockup(a)	do { } while(0)
#define exynos_ss_get_hardlockup()	do { } while(0)
#define exynos_ss_get_item_size(a)	do { } while(0)
#define exynos_ss_get_item_paddr(a)	do { } while(0)
#define exynos_ss_check_crash_key(a, b)	do { } while (0)
#define exynos_ss_i2c_clk(a, b)		do { } while (0)
#endif /* CONFIG_EXYNOS_SNAPSHOT */

/**
 * esslog_flag - added log information supported.
 * @ESS_FLAG_IN: Generally, marking into the function
 * @ESS_FLAG_ON: Generally, marking the status not in, not out
 * @ESS_FLAG_OUT: Generally, marking come out the function
 * @ESS_FLAG_SOFTIRQ: Marking to pass the softirq function
 * @ESS_FLAG_SOFTIRQ_HI_TASKLET: Marking to pass the tasklet function
 * @ESS_FLAG_SOFTIRQ_TASKLET: Marking to pass the tasklet function
 */
enum esslog_flag {
	ESS_FLAG_IN = 1,
	ESS_FLAG_ON = 2,
	ESS_FLAG_OUT = 3,
	ESS_FLAG_SOFTIRQ = 10000,
	ESS_FLAG_SOFTIRQ_HI_TASKLET = 10100,
	ESS_FLAG_SOFTIRQ_TASKLET = 10200,
	ESS_FLAG_CALL_TIMER_FN = 20000
};

enum esslog_freq_flag {
	ESS_FLAG_APL = 0,
	ESS_FLAG_ATL,
	ESS_FLAG_INT,
	ESS_FLAG_MIF,
	ESS_FLAG_ISP,
	ESS_FLAG_DISP,
};
#endif
