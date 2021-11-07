#if defined(CONFIG_CCIC_NOTIFIER)
#include <linux/ifpmic/ccic/ccic_notifier.h>
#endif
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
#include <linux/usb/class-dual-role.h>
#endif

#ifdef CONFIG_BATTERY_SAMSUNG
#ifdef CONFIG_USB_TYPEC_MANAGER_NOTIFIER
#include <linux/battery/battery_notifier.h>
#endif
#endif

#ifndef __USBPD_EXT_H__
#define __USBPD_EXT_H__

#ifdef CONFIG_BATTERY_SAMSUNG
#ifdef CONFIG_USB_TYPEC_MANAGER_NOTIFIER
extern struct pdic_notifier_struct pd_noti;
#endif
#endif

/* CCIC Dock Observer Callback parameter */
enum {
	CCIC_DOCK_DETACHED	= 0,
	CCIC_DOCK_HMT		= 105,	/* Samsung Gear VR */
	CCIC_DOCK_ABNORMAL	= 106,
	CCIC_DOCK_MPA		= 109,	/* Samsung Multi Port Adaptor */
	CCIC_DOCK_DEX		= 110,	/* Samsung Dex */
	CCIC_DOCK_HDMI		= 111,	/* Samsung HDMI Dongle */
};

#define GEAR_VR_DETACH_WAIT_MS		(1000)

/* Samsung Acc VID */
#define SAMSUNG_VENDOR_ID		0x04E8
#define SAMSUNG_MPA_VENDOR_ID		0x04B4
/* Samsung Acc PID */
#define GEARVR_PRODUCT_ID		0xA500
#define GEARVR_PRODUCT_ID_1		0xA501
#define GEARVR_PRODUCT_ID_2		0xA502
#define GEARVR_PRODUCT_ID_3		0xA503
#define GEARVR_PRODUCT_ID_4		0xA504
#define GEARVR_PRODUCT_ID_5		0xA505
#define DEXDOCK_PRODUCT_ID		0xA020
#define HDMI_PRODUCT_ID			0xA025
#define MPA_PRODUCT_ID			0x2122
/* Samsung UVDM structure */
#define SEC_UVDM_SHORT_DATA		0x0
#define SEC_UVDM_LONG_DATA		0x1
#define SEC_UVDM_ININIATOR		0x0
#define SEC_UVDM_RESPONDER_ACK	0x1
#define SEC_UVDM_RESPONDER_NAK	0x2
#define SEC_UVDM_RESPONDER_BUSY	0x3
#define SEC_UVDM_UNSTRUCTURED_VDM	0x0

/*For DP Pin Assignment */
#define DP_PIN_ASSIGNMENT_NODE	0x00000000
#define DP_PIN_ASSIGNMENT_A	0x00000001	/* ( 1 << 0 ) */
#define DP_PIN_ASSIGNMENT_B	0x00000002	/* ( 1 << 1 ) */
#define DP_PIN_ASSIGNMENT_C	0x00000004	/* ( 1 << 2 ) */
#define DP_PIN_ASSIGNMENT_D	0x00000008	/* ( 1 << 3 ) */
#define DP_PIN_ASSIGNMENT_E	0x00000010	/* ( 1 << 4 ) */
#define DP_PIN_ASSIGNMENT_F	0x00000020	/* ( 1 << 5 ) */

#if defined(CONFIG_CCIC_NOTIFIER)
void ccic_event_work(void *data, int dest, int id, int attach, int event);
extern void select_pdo(int num);
#endif
#if defined(CONFIG_DUAL_ROLE_USB_INTF)
extern void role_swap_check(struct work_struct *wk);
extern int dual_role_is_writeable(struct dual_role_phy_instance *drp,
				  enum dual_role_property prop);
extern int dual_role_get_local_prop(struct dual_role_phy_instance *dual_role,
				    enum dual_role_property prop,
				    unsigned int *val);
extern int dual_role_set_prop(struct dual_role_phy_instance *dual_role,
			      enum dual_role_property prop,
			      const unsigned int *val);
extern int dual_role_init(void *_data);
#endif
#endif
