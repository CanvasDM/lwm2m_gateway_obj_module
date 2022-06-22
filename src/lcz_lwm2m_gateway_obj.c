/**
 * @file lcz_lwm2m_gateway_obj.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_gateway_obj, CONFIG_LCZ_LWM2M_GATEWAY_OBJ_LOG_LEVEL);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zephyr.h>
#include <init.h>
#include <bluetooth/addr.h>
#include <lwm2m_obj_gateway.h>
#include <lcz_lwm2m.h>

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
#include <lcz_param_file.h>
#endif

#include "lcz_lwm2m_gateway_obj.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define DEV_FLAG_IN_USE 0x01
#define DEV_FLAG_INST_CREATED 0x02

/* Structure used to hold active devices */
struct gateway_obj_device_t {
	/* BLE device address */
	bt_addr_le_t addr;

	/* Expiration time */
	int64_t expires;

	/* Status flags */
	uint8_t flags;

	/* Object 25 instance number */
	uint16_t instance;

	/* Lifetime of the device (in seconds) */
	uint16_t lifetime;

	/* Pointers to private application data */
	void *dm_data_ptr;
	void *telem_data_ptr;
};

/* Structure used to hold allow and block lists */
struct gateway_obj_allow_block_t {
	/* BLE device address */
	bt_addr_le_t addr;

	union {
		/* Expiration time (used for block list) */
		int64_t expires;

		/* Object 25 instance (used for allow list) */
		uint16_t instance;
	} d;
};

/* How often to check lists for expired devices */
#define MANAGE_LIST_PERIOD (10 * MSEC_PER_SEC)

/* String lengths for parsing allow list file parameters */
#define BLE_ADDRESS_TYPE_LEN (2 * sizeof(allow_list[0].addr.type))
#define BLE_ADDRESS_VAL_LEN (2 * sizeof(allow_list[0].addr.a.val))

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/

/* Device lists */
static struct gateway_obj_device_t devices[CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES];
static struct gateway_obj_allow_block_t block_list[CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE];
#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
static struct gateway_obj_allow_block_t allow_list[CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST_SIZE];
static int allow_list_len = 0;
#endif

/* User callbacks */
static lcz_lwm2m_device_deleted_cb_t dm_delete_cb;
static lcz_lwm2m_device_deleted_cb_t telem_delete_cb;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_obj_init(const struct device *device);

static void register_instance(int idx);
static void delete_instance(int idx, bool delete_obj);
static int add_blocklist(int idx, uint16_t duration);
static int instance_deleted_cb(uint16_t obj_inst_id);

static void manage_lists(uint32_t tag);

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_lwm2m_gw_obj_lookup_ble(const bt_addr_le_t *addr)
{
	int i;

	/* Check our device list for the device */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if (((devices[i].flags & DEV_FLAG_IN_USE) != 0) &&
		    bt_addr_le_cmp(addr, &(devices[i].addr)) == 0) {
			break;
		}
	}

	/* If we found the device we were looking for, return it */
	if (i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) {
		return i;
	} else {
		return -ENOENT;
	}
}

int lcz_lwm2m_gw_obj_lookup_path(char *prefix)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char *prefix_str;
	uint16_t prefix_len;
	uint8_t prefix_flags;
	int i;
	int r;

	/* Check our device list for the device */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if ((devices[i].flags & DEV_FLAG_IN_USE) != 0) {
			/* Get the prefix string */
			snprintf(path, sizeof(path),
				 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
					 LWM2M_GATEWAY_PREFIX_RID),
				 devices[i].instance);
			r = lwm2m_engine_get_res_data(path, (void **)&prefix_str, &prefix_len,
						      &prefix_flags);

			/* Check the prefix against the path string */
			if (r == 0 && strcmp(prefix_str, prefix) == 0) {
				break;
			}
		}
	}

	/* If we found the device we were looking for, return it */
	if (i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) {
		return i;
	} else {
		return -ENOENT;
	}
}

int lcz_lwm2m_gw_obj_create(const bt_addr_le_t *addr)
{
	int64_t now = k_uptime_get();
	int instance = -1;
	int retval = 0;
	int i;

	/* Check the block list */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE; i++) {
		if ((block_list[i].d.expires == 0 || block_list[i].d.expires >= now) &&
		    (bt_addr_le_cmp(addr, &(block_list[i].addr)) == 0)) {
			break;
		}
	}
	/* If we found the device on the list, device is blocked */
	if (i < CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE) {
		retval = -EPERM;
	}

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
	/* Check the allow list */
	if (retval == 0) {
		for (i = 0; i < allow_list_len; i++) {
			if (bt_addr_le_cmp(addr, &(allow_list[i].addr)) == 0) {
				instance = allow_list[i].d.instance;
				break;
			}
		}
		/* If we did NOT find the device on the list, device is blocked */
		if ((allow_list_len > 0) && (i >= allow_list_len)) {
			retval = -EPERM;
		}
	}
#endif

	/* Create the device if we're allowed to */
	if (retval == 0) {
		for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
			if ((devices[i].flags & DEV_FLAG_IN_USE) == 0) {
				break;
			}
		}

		if (i >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) {
			retval = -ENOMEM;
		} else {
			/* Set instance value to array index if wasn't set above */
			if (instance < 0) {
				instance = i;
			}

			devices[i].flags |= DEV_FLAG_IN_USE;
			memcpy(&(devices[i].addr), addr, sizeof(devices[0].addr));
			devices[i].instance = instance;
			devices[i].lifetime = CONFIG_LCZ_LWM2M_GATEWAY_OBJ_DEFAULT_LIFETIME_SECONDS;
			if (devices[i].lifetime != 0) {
				devices[i].expires =
					k_uptime_get() + (devices[i].lifetime * MSEC_PER_SEC);
			} else {
				devices[i].expires = 0;
			}
			devices[i].dm_data_ptr = NULL;
			devices[i].telem_data_ptr = NULL;
		}
	}

	return retval;
}

bt_addr_le_t *lcz_lwm2m_gw_obj_get_address(int idx)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return NULL;
	} else {
		return &(devices[idx].addr);
	}
}

char *lcz_lwm2m_gw_obj_get_addr_string(int idx)
{
	static char addr_str[BT_ADDR_LE_STR_LEN];

	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return NULL;
	} else {
		bt_addr_le_to_str(&(devices[idx].addr), addr_str, sizeof(addr_str));
		return addr_str;
	}
}

int lcz_lwm2m_gw_obj_get_instance(int idx)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return -ENOENT;
	} else {
		return devices[idx].instance;
	}
}

char *lcz_lwm2m_gw_obj_get_prefix(int idx)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char *prefix_str = NULL;
	uint16_t prefix_len;
	uint8_t prefix_flags;
	int r;

	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return NULL;
	} else {
		/* Set the prefix string */
		snprintf(path, sizeof(path),
			 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
				 LWM2M_GATEWAY_PREFIX_RID),
			 devices[idx].instance);
		r = lwm2m_engine_get_res_data(path, (void **)&prefix_str, &prefix_len,
					      &prefix_flags);
		if (r != 0) {
			prefix_str = NULL;
		}
	}

	return prefix_str;
}

int lcz_lwm2m_gw_obj_foreach(lcz_lwm2m_device_foreach_cb_t cb, void *priv)
{
	int n = 0;
	int i;

	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if ((devices[i].flags & DEV_FLAG_IN_USE) != 0) {
			if (cb != NULL) {
				cb(i, devices[i].dm_data_ptr, devices[i].telem_data_ptr, priv);
			}
			n++;
		}
	}

	return n;
}

void lcz_lwm2m_gw_obj_tick(int idx)
{
	if ((idx < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) &&
	    ((devices[idx].flags & DEV_FLAG_IN_USE) != 0)) {
		if (devices[idx].lifetime != 0) {
			devices[idx].expires =
				k_uptime_get() + (devices[idx].lifetime * MSEC_PER_SEC);
		} else {
			devices[idx].expires = 0;
		}
	}
}

int lcz_lwm2m_gw_obj_set_endpoint_name(int idx, char *name, int name_len)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char endpoint[CONFIG_LCZ_LWM2M_GATEWAY_DEVICE_ID_MAX_STR_SIZE];
	int retval = 0;

	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		retval = -ENOENT;
	} else {
		if ((devices[idx].flags & DEV_FLAG_INST_CREATED) == 0) {
			register_instance(idx);
		}
		if ((devices[idx].flags & DEV_FLAG_INST_CREATED) != 0) {
			snprintf(path, sizeof(path),
				 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
					 LWM2M_GATEWAY_DEVICE_RID),
				 devices[idx].instance);
			/* Limit the size of the string to what fits in the object */
			if (name_len > (sizeof(endpoint) - 1)) {
				name_len = sizeof(endpoint) - 1;
			}

			/* Copy and nul-terminate the string */
			memcpy(endpoint, name, name_len);
			endpoint[name_len] = '\0';

			/* Set it in the object */
			lwm2m_engine_set_string(path, endpoint);
		} else {
			retval = -ENOMEM;
		}
	}

	return retval;
}

int lcz_lwm2m_gw_obj_set_object_list(int idx, char *obj_list, int obj_list_len)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char objlist[CONFIG_LCZ_LWM2M_GATEWAY_IOT_DEVICE_OBJECTS_MAX_STR_SIZE];
	int retval = 0;

	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		retval = -ENOENT;
	} else {
		if ((devices[idx].flags & DEV_FLAG_INST_CREATED) == 0) {
			register_instance(idx);
		}
		if ((devices[idx].flags & DEV_FLAG_INST_CREATED) != 0) {
			snprintf(path, sizeof(path),
				 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
					 LWM2M_GATEWAY_IOT_DEVICE_OBJECTS_RID),
				 devices[idx].instance);

			/* Limit the size of the object list string to what fits in the object */
			if (obj_list_len > (sizeof(objlist) - 1)) {
				obj_list_len = sizeof(objlist) - 1;
			}

			/* Copy and nul-terminate the string */
			memcpy(objlist, obj_list, obj_list_len);
			objlist[obj_list_len] = '\0';

			/* Set it in the object */
			lwm2m_engine_set_string(path, objlist);
		} else {
			retval = -ENOMEM;
		}
	}

	return retval;
}

int lcz_lwm2m_gw_obj_set_lifetime(int idx, uint16_t lifetime)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return -ENOENT;
	} else {
		devices[idx].lifetime = lifetime;
		if (devices[idx].lifetime != 0) {
			devices[idx].expires =
				k_uptime_get() + (devices[idx].lifetime * MSEC_PER_SEC);
		} else {
			devices[idx].expires = 0;
		}
		return 0;
	}
}

int lcz_lwm2m_gw_obj_set_dm_data(int idx, void *dm_ptr)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return -ENOENT;
	} else {
		devices[idx].dm_data_ptr = dm_ptr;
		return 0;
	}
}

void *lcz_lwm2m_gw_obj_get_dm_data(int idx)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return NULL;
	} else {
		return devices[idx].dm_data_ptr;
	}
}

int lcz_lwm2m_gw_obj_set_telem_data(int idx, void *telem_ptr)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return -ENOENT;
	} else {
		devices[idx].telem_data_ptr = telem_ptr;
		return 0;
	}
}

void *lcz_lwm2m_gw_obj_get_telem_data(int idx)
{
	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return NULL;
	} else {
		return devices[idx].telem_data_ptr;
	}
}

int lcz_lwm2m_gw_obj_add_blocklist(int idx, uint16_t duration)
{
	int retval = -ENOMEM;

	if ((idx >= CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		retval = -ENOENT;
	} else {
		/* Add the device to the blocklist */
		retval = add_blocklist(idx, duration);

		/* Delete the device from our active devices */
		delete_instance(idx, true);
	}

	return retval;
}

void lcz_lwm2m_gw_obj_set_dm_delete_cb(lcz_lwm2m_device_deleted_cb_t dm_cb)
{
	dm_delete_cb = dm_cb;
}

void lcz_lwm2m_gw_obj_set_telem_delete_cb(lcz_lwm2m_device_deleted_cb_t telem_cb)
{
	telem_delete_cb = telem_cb;
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static void register_instance(int idx)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char *prefix_str;
	uint16_t prefix_len;
	uint8_t prefix_flags;
	int r;

	/* Create the instance */
	snprintf(path, sizeof(path), STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u",
		 devices[idx].instance);
	r = lwm2m_engine_create_obj_inst(path);
	if (r == 0) {
		/* Remember that we created the instance */
		devices[idx].flags |= DEV_FLAG_INST_CREATED;

		/* Set the prefix string */
		snprintf(path, sizeof(path),
			 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
				 LWM2M_GATEWAY_PREFIX_RID),
			 devices[idx].instance);
		r = lwm2m_engine_get_res_data(path, (void **)&prefix_str, &prefix_len,
					      &prefix_flags);
		if (r == 0) {
			snprintf(prefix_str, prefix_len,
				 CONFIG_LCZ_LWM2M_GATEWAY_DEFAULT_DEVICE_PREFIX "%u",
				 devices[idx].instance);
		}
	}
}

static void delete_instance(int idx, bool delete_obj)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	uint8_t flags;

	/* Call the delete callbacks */
	if (dm_delete_cb) {
		dm_delete_cb(idx, devices[idx].dm_data_ptr);
	}
	if (telem_delete_cb) {
		telem_delete_cb(idx, devices[idx].telem_data_ptr);
	}

	/* Remove it from our database */
	flags = devices[idx].flags;
	devices[idx].flags = 0;

	/* Delete the instance from object 25 */
	if (delete_obj && (flags & DEV_FLAG_INST_CREATED) != 0) {
		snprintf(path, sizeof(path), STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u",
			 devices[idx].instance);
		lwm2m_engine_delete_obj_inst(path);
	}
}

static int add_blocklist(int idx, uint16_t duration)
{
	int64_t now = k_uptime_get();
	int retval = -ENOMEM;
	int i;

	/* Find a spot in the blocklist for the device */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE; i++) {
		if (block_list[i].d.expires != 0 && block_list[i].d.expires < now) {
			memcpy(&(block_list[i].addr), &(devices[idx].addr),
			       sizeof(block_list[0].addr));
			if (duration == 0) {
				block_list[i].d.expires = 0;
			} else {
				block_list[i].d.expires = now + (duration * MSEC_PER_SEC);
			}
			retval = 0;
			break;
		}
	}

	return retval;
}

static int instance_deleted_cb(uint16_t obj_inst_id)
{
	int i;

	/* Find the index into our array from the instance ID */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if (((devices[i].flags & DEV_FLAG_IN_USE) != 0) &&
		    (devices[i].instance == obj_inst_id)) {
			break;
		}
	}

	if (i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES) {
		/* Add the device to the blocklist forever */
		add_blocklist(i, 0);

		/* Delete our database entry */
		delete_instance(i, false);
	}

	return 0;
}

static void manage_lists(uint32_t tag)
{
	ARG_UNUSED(tag);
	int64_t now = k_uptime_get();
	int i;

	/* Delete any active devices that are past their expiration time */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if (((devices[i].flags & DEV_FLAG_IN_USE) != 0) && (devices[i].expires != 0) &&
		    (now > devices[i].expires)) {
			delete_instance(i, true);
		}
	}
}

SYS_INIT(lcz_lwm2m_gateway_obj_init, APPLICATION, CONFIG_LCZ_LWM2M_GATEWAY_OBJ_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_obj_init(const struct device *device)
{
#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
	int n_allow;
	size_t fsize;
	char *fstr = NULL;
	param_kvp_t *kv = NULL;
#endif /* LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST */
	int i;
	int ret;

	ARG_UNUSED(device);

	/* Register object 25 delete callback */
	lwm2m_engine_register_delete_callback(LWM2M_OBJECT_GATEWAY_ID, instance_deleted_cb);

	/* Register a service to periodically maintain our lists */
	lwm2m_engine_add_service(manage_lists, MANAGE_LIST_PERIOD, 0);

	/* Reset the block list */
	memset(block_list, 0, sizeof(block_list));
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE; i++) {
		block_list[i].d.expires = -1;
	}

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
	/* Reset the allow list in memory */
	memset(allow_list, 0, sizeof(allow_list));
	allow_list_len = 0;

	/* Parse the allow list */
	n_allow = lcz_param_file_parse_from_file(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST_FILE,
						 &fsize, &fstr, &kv);

	/*
	 * Entries in the parameter file will look like:
	 *     0001=TTAABBCCDDEEFF
	 *
	 * where 0001 will be the instance number that we use, TT is the Bluetooth address type
	 * byte and AABBCCDDEEFF is the Bluetooth address of the device.
	 */
	for (i = 0; i < n_allow && allow_list_len < CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST_SIZE;
	     i++) {
		/* Length needs to include Bluetooth address type plus value */
		if (kv[i].length == (BLE_ADDRESS_TYPE_LEN + BLE_ADDRESS_VAL_LEN)) {
			ret = hex2bin(kv[i].keystr, BLE_ADDRESS_TYPE_LEN,
				      &(allow_list[allow_list_len].addr.type),
				      sizeof(allow_list[0].addr.type));
			if (ret == sizeof(allow_list[0].addr.type)) {
				ret = hex2bin(kv[i].keystr + BLE_ADDRESS_TYPE_LEN,
					      BLE_ADDRESS_VAL_LEN,
					      allow_list[allow_list_len].addr.a.val,
					      sizeof(allow_list[0].addr.a.val));
				if (ret == sizeof(allow_list[0].addr.a.val)) {
					allow_list[allow_list_len].d.instance = kv[i].id;
					allow_list_len++;
				}
			}
		}
	}

	if (fstr != NULL) {
		k_free(fstr);
	}

	if (kv != NULL) {
		k_free(kv);
	}
#endif /* LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST */

	return 0;
}
