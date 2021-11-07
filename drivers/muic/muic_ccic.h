#ifndef _MUIC_CCIC_
#define _MUIC_CCIC_

extern int muic_handle_ccic_supported_dev(muic_data_t *pmuic, muic_attached_dev_t new_dev);
extern int muic_is_ccic_supported_dev(muic_data_t *pmuic, muic_attached_dev_t new_dev);
extern int muic_is_ccic_supported_jig(muic_data_t *pmuic, muic_attached_dev_t new_dev);
extern void muic_register_ccic_notifier(muic_data_t *pmuic);
extern void muic_ccic_pseudo_noti(int mid, int rid);
extern int mdev_continue_for_TA_USB(muic_data_t *pmuic, int mdev);
extern int muic_get_current_legacy_dev(muic_data_t *pmuic);
extern void muic_set_legacy_dev(muic_data_t *pmuic, int new_dev);
extern void muic_set_pdesc_mdev(muic_data_t *pmuic, int new_dev);
extern void mdev_handle_ccic_detach(muic_data_t *pmuic);
extern int muic_set_dcd_rescan(muic_data_t *pmuic);
extern int get_ccic_info(void);

#endif
