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
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_gateway_obj, CONFIG_LCZ_LWM2M_GATEWAY_OBJ_LOG_LEVEL);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zephyr/zephyr.h>
#include <zephyr/init.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/net/lwm2m.h>
#include <lwm2m_obj_gateway.h>

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
#include <lcz_kvp.h>
#endif

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_STATIC_INST_LIST)
#include <file_system_utilities.h>
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
	void *security_data_ptr;
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

/* Current max line length is 23 characters
 * Allow room in file for comments.
 */
#define MAX_KVP_STR_SIZE 32
#define MAX_KVP_FILE_SIZE 512

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/

/* Device lists */
static struct gateway_obj_device_t devices[CONFIG_LWM2M_GATEWAY_MAX_INSTANCES];
static struct gateway_obj_allow_block_t block_list[CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE];
#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
static struct gateway_obj_allow_block_t allow_list[CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST_SIZE];
static int allow_list_len = -1;
static K_SEM_DEFINE(allow_list_sem, 1, 1);
static const lcz_kvp_cfg_t KVP_CFG = { .max_file_out_size = MAX_KVP_FILE_SIZE, .encrypted = false };
#endif

/* User callbacks */
static lcz_lwm2m_device_deleted_cb_t dm_delete_cb;
static lcz_lwm2m_device_deleted_cb_t telem_delete_cb;
static lcz_lwm2m_device_deleted_cb_t security_delete_cb;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_obj_init(const struct device *device);

static bool invalid_index(int idx);
static void register_instance(int idx);
static void delete_instance(int idx, bool delete_obj);
static int add_blocklist(int idx, uint16_t duration);
static int instance_deleted_cb(uint16_t obj_inst_id);
static int get_instance(const bt_addr_le_t *addr, int idx);

static void manage_lists(uint32_t tag);

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
static int convert(lcz_kvp_t *kvp, struct gateway_obj_allow_block_t *elem);
#endif

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_lwm2m_gw_obj_lookup_ble(const bt_addr_le_t *addr)
{
	int i;

	/* Check our device list for the device */
	for (i = 0; i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if (((devices[i].flags & DEV_FLAG_IN_USE) != 0) &&
		    bt_addr_le_cmp(addr, &(devices[i].addr)) == 0) {
			break;
		}
	}

	/* If we found the device we were looking for, return it */
	if (i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) {
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
	for (i = 0; i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if ((devices[i].flags & DEV_FLAG_IN_USE) != 0) {
			/* Get the prefix string */
			snprintf(path, sizeof(path),
				 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
					 LWM2M_GATEWAY_PREFIX_RID),
				 devices[i].instance);
			r = lwm2m_engine_get_res_buf(path, (void **)&prefix_str, NULL, &prefix_len,
						     &prefix_flags);

			/* Check the prefix against the path string */
			if (r == 0 && strcmp(prefix_str, prefix) == 0) {
				break;
			}
		}
	}

	/* If we found the device we were looking for, return it */
	if (i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) {
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
	if (retval >= 0) {
		if (k_sem_take(&allow_list_sem, K_NO_WAIT) == 0) {
			for (i = 0; i < allow_list_len; i++) {
				if (bt_addr_le_cmp(addr, &(allow_list[i].addr)) == 0) {
					instance = allow_list[i].d.instance;
					break;
				}
			}
			/* If we did NOT find the device on the list, device is blocked */
			if ((allow_list_len >= 0) && (i >= allow_list_len)) {
				retval = -EPERM;
			}
			k_sem_give(&allow_list_sem);
		} else {
			/* Try again - List is being updated */
			retval = -EAGAIN;
		}
	}
#endif

	/* Create the device if we're allowed to */
	if (retval >= 0) {
		for (i = 0; i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
			if ((devices[i].flags & DEV_FLAG_IN_USE) == 0) {
				break;
			}
		}

		if (i >= CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) {
			retval = -ENOMEM;
		} else {
			/* If it wasn't set above, get instance value. */
			if (instance < 0) {
				instance = get_instance(addr, i);
			}

			retval = i;
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
			devices[i].security_data_ptr = NULL;
		}
	}

	return retval;
}

bt_addr_le_t *lcz_lwm2m_gw_obj_get_address(int idx)
{
	if (invalid_index(idx)) {
		return NULL;
	} else {
		return &(devices[idx].addr);
	}
}

char *lcz_lwm2m_gw_obj_get_addr_string(int idx)
{
	static char addr_str[BT_ADDR_LE_STR_LEN];

	if (invalid_index(idx)) {
		return NULL;
	} else {
		bt_addr_le_to_str(&(devices[idx].addr), addr_str, sizeof(addr_str));
		return addr_str;
	}
}

int lcz_lwm2m_gw_obj_get_instance(int idx)
{
	if (invalid_index(idx)) {
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

	if (invalid_index(idx)) {
		return NULL;
	} else {
		/* Set the prefix string */
		snprintf(path, sizeof(path),
			 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
				 LWM2M_GATEWAY_PREFIX_RID),
			 devices[idx].instance);
		r = lwm2m_engine_get_res_buf(path, (void **)&prefix_str, NULL, &prefix_len,
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

	for (i = 0; i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
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
	if ((idx < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) &&
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
	char endpoint[CONFIG_LWM2M_GATEWAY_DEVICE_ID_MAX_STR_SIZE];
	int retval = 0;

	if (invalid_index(idx)) {
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

bool lcz_lwm2m_gw_obj_inst_created(int idx)
{
	if (invalid_index(idx)) {
		return false;
	} else {
		return ((devices[idx].flags & DEV_FLAG_INST_CREATED) != 0);
	}
}

int lcz_lwm2m_gw_obj_get_endpoint_name(int idx, char *name, int name_len)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	int retval = 0;

	if (invalid_index(idx)) {
		retval = -ENOENT;
	} else if ((devices[idx].flags & DEV_FLAG_INST_CREATED) != 0) {
		snprintf(path, sizeof(path),
			 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
				 LWM2M_GATEWAY_DEVICE_RID),
			 devices[idx].instance);

		retval = lwm2m_engine_get_string(path, name, name_len);
	} else {
		retval = -EEXIST;
	}

	return retval;
}

int lcz_lwm2m_gw_obj_set_object_list(int idx, char *obj_list, int obj_list_len)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char objlist[CONFIG_LWM2M_GATEWAY_IOT_DEVICE_OBJECTS_MAX_STR_SIZE];
	int retval = 0;

	if (invalid_index(idx)) {
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
				LOG_ERR("Object list length %d too long", obj_list_len);
				obj_list_len = 0;
			}

			/* Copy and nul-terminate the string */
			memcpy(objlist, obj_list, obj_list_len);
			objlist[obj_list_len] = '\0';

			/* Set it in the object */
			retval = lwm2m_engine_set_string(path, objlist);
		} else {
			retval = -ENOMEM;
		}
	}

	return retval;
}

int lcz_lwm2m_gw_obj_get_object_list_length(int idx)
{
	char path[LWM2M_MAX_PATH_STR_LEN];
	char list[CONFIG_LWM2M_GATEWAY_IOT_DEVICE_OBJECTS_MAX_STR_SIZE];
	int retval = 0;

	if (invalid_index(idx)) {
		retval = -ENOENT;
	} else {
		if ((devices[idx].flags & DEV_FLAG_INST_CREATED) == 0) {
			retval = -ENOENT;
		} else {
			snprintf(path, sizeof(path),
				 STRINGIFY(LWM2M_OBJECT_GATEWAY_ID) "/%u/" STRINGIFY(
					 LWM2M_GATEWAY_IOT_DEVICE_OBJECTS_RID),
				 devices[idx].instance);

			retval = lwm2m_engine_get_string(path, list, sizeof(list));
			if (retval == 0) {
				retval = strlen(list);
			}
		}
	}

	return retval;
}

int lcz_lwm2m_gw_obj_set_lifetime(int idx, uint16_t lifetime)
{
	if (invalid_index(idx)) {
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
	if (invalid_index(idx)) {
		return -ENOENT;
	} else {
		devices[idx].dm_data_ptr = dm_ptr;
		return 0;
	}
}

void *lcz_lwm2m_gw_obj_get_dm_data(int idx)
{
	if (invalid_index(idx)) {
		return NULL;
	} else {
		return devices[idx].dm_data_ptr;
	}
}

int lcz_lwm2m_gw_obj_set_telem_data(int idx, void *telem_ptr)
{
	if (invalid_index(idx)) {
		return -ENOENT;
	} else {
		devices[idx].telem_data_ptr = telem_ptr;
		return 0;
	}
}

void *lcz_lwm2m_gw_obj_get_telem_data(int idx)
{
	if (invalid_index(idx)) {
		return NULL;
	} else {
		return devices[idx].telem_data_ptr;
	}
}

int lcz_lwm2m_gw_obj_set_security_data(int idx, void *security_ptr)
{
	if ((idx >= CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return -ENOENT;
	} else {
		devices[idx].security_data_ptr = security_ptr;
		return 0;
	}
}

void *lcz_lwm2m_gw_obj_get_security_data(int idx)
{
	if ((idx >= CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return NULL;
	} else {
		return devices[idx].security_data_ptr;
	}
}

int lcz_lwm2m_gw_obj_add_blocklist(int idx, uint16_t duration)
{
	int retval = -ENOMEM;

	if (invalid_index(idx)) {
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

void lcz_lwm2m_gw_obj_set_security_delete_cb(lcz_lwm2m_device_deleted_cb_t security_cb)
{
	security_delete_cb = security_cb;
}

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
/*
 * Example File:
 * # instance number = Bluetooth address, optional address type
 * 04=C0:92:98:FC:F8:B7,1
 * 08=DD:BB:19:5D:7E:FD
 * 12=C6:30:15:77:69:EE
 * 16=cb:cf:5b:65:f6:b3
 */
int lcz_lwm2m_gw_obj_load_allow_list(const struct shell *shell)
{
	const char *fname = CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST_FILE;
	const size_t max_size = CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST_SIZE;
	int i;
	int r = -EPERM;
	size_t fsize = 0;
	char *fstr = NULL;
	lcz_kvp_t *kv = NULL;
	size_t pairs = 0;

	do {
		r = lcz_kvp_parse_from_file(&KVP_CFG, fname, &fsize, &fstr, &kv);
		if (r < 0) {
			if (r != -ENOENT) {
				LOG_ERR("Unable to parse KVP file");
			}
			break;
		}
		pairs = r;

		if (pairs > max_size) {
			LOG_WRN("File contains more elements than list size %u > %u", pairs,
				max_size);
			pairs = max_size;
		}

		k_sem_take(&allow_list_sem, K_FOREVER);
		memset(allow_list, 0, sizeof(allow_list));
		allow_list_len = 0;

		for (i = 0; i < pairs; i++) {
			r = convert(&kv[i], &allow_list[i]);
			if (r < 0) {
				break;
			}
			allow_list_len += 1;
		}
		k_sem_give(&allow_list_sem);

	} while (0);

	k_free(kv);
	k_free(fstr);

	if (shell) {
		shell_print(shell, "load %s: size: %u status: %d pairs: %u allow_list_len: %d",
			    fname, fsize, r, pairs, allow_list_len);
	} else {
		LOG_DBG("load %s: size: %u status: %d pairs: %u allow_list_len: %d", fname, fsize,
			r, pairs, allow_list_len);
	}

	return (r < 0) ? r : allow_list_len;
}
#endif

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static bool invalid_index(int idx)
{
	if ((idx < 0) || (idx >= CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) ||
	    ((devices[idx].flags & DEV_FLAG_IN_USE) == 0)) {
		return true;
	} else {
		return false;
	}
}

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
		r = lwm2m_engine_get_res_buf(path, (void **)&prefix_str, &prefix_len, NULL,
					     &prefix_flags);
		if (r == 0) {
			snprintf(prefix_str, prefix_len,
				 CONFIG_LWM2M_GATEWAY_DEFAULT_DEVICE_PREFIX "%u",
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
	if (security_delete_cb) {
		security_delete_cb(idx, devices[idx].security_data_ptr);
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
	char addr_str[BT_ADDR_LE_STR_LEN];
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
			bt_addr_le_to_str(&(block_list[i].addr), addr_str, sizeof(addr_str));
			LOG_INF("Adding %s to blocklist with expiration %lld", addr_str,
				block_list[i].d.expires);
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
	for (i = 0; i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
		if (((devices[i].flags & DEV_FLAG_IN_USE) != 0) &&
		    (devices[i].instance == obj_inst_id)) {
			break;
		}
	}

	if (i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES) {
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
	for (i = 0; i < CONFIG_LWM2M_GATEWAY_MAX_INSTANCES; i++) {
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
	ARG_UNUSED(device);
	int i;

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
	lcz_lwm2m_gw_obj_load_allow_list(NULL);
#endif

	return 0;
}

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_ALLOW_LIST)
static bool valid_instance(uint16_t instance)
{
	/* reserved locations are for gateway */
	if (instance < CONFIG_LCZ_LWM2M_GATEWAY_OBJ_LEGACY_INST_OFFSET) {
		return false;
	}

	/* Allow multiple sensor instances per BTxxx (when gateway is creating sensor objects). */
	if ((instance % LCZ_LWM2M_INSTANCES_PER_BTXXX) != 0) {
		return false;
	}

	return true;
}

/* Convert the key-value pair strings into binary (allow list format) */
static int convert(lcz_kvp_t *kvp, struct gateway_obj_allow_block_t *elem)
{
	char str[MAX_KVP_STR_SIZE];
	int count;
	unsigned int temp_addr[BT_ADDR_SIZE];
	unsigned int temp_type;
	uint16_t instance;
	unsigned int i;
	char *comma;

	if (kvp->key_len > MAX_KVP_STR_SIZE) {
		LOG_WRN("%s: Key name too long", __func__);
		return -EINVAL;
	}

	if (kvp->val_len > MAX_KVP_STR_SIZE) {
		LOG_WRN("%s: Value too long", __func__);
		return -EINVAL;
	}

	if (kvp->key == NULL) {
		LOG_ERR("%s: Invalid key pointer", __func__);
		return -EINVAL;
	}
	if (kvp->val == NULL) {
		LOG_ERR("%s: Invalid value pointer", __func__);
		return -EINVAL;
	}

	/* terminate key then convert */
	memcpy(str, kvp->key, kvp->key_len);
	str[kvp->key_len] = 0;
	instance = (uint16_t)strtoul(str, NULL, 10);
	if (!valid_instance(instance)) {
		LOG_ERR("Invalid instance %u str: %s", instance, str);
		return -EINVAL;
	}

	memcpy(str, kvp->val, kvp->val_len);
	str[kvp->val_len] = 0;
	/* Default for optional parameter */
	temp_type = BT_ADDR_LE_RANDOM;
	/* Temporary ints are used because hhx requires LIBC NANO to be disabled. */
	count = sscanf(str, "%x:%x:%x:%x:%x:%x,%u", &temp_addr[5], &temp_addr[4], &temp_addr[3],
		       &temp_addr[2], &temp_addr[1], &temp_addr[0], &temp_type);
	if (count < BT_ADDR_SIZE) {
		LOG_ERR("%s: Unable to parse address: %u < %u str: %s", __func__, count,
			BT_ADDR_SIZE, str);
		return -EINVAL;
	} else {
		/* Don't print address type */
		comma = strchr(str, ',');
		if (comma) {
			*comma = 0;
		}
		LOG_INF("Adding %s to allow list (instance: %u)", str, instance);
		elem->d.instance = instance;
		for (i = 0; i < BT_ADDR_SIZE; i++) {
			if (temp_addr[i] > UINT8_MAX) {
				return -EINVAL;
			}
			elem->addr.a.val[i] = (uint8_t)temp_addr[i];
		}
		if (temp_type > UINT8_MAX) {
			return -EINVAL;
		}
		elem->addr.type = (uint8_t)temp_type;
		return 0;
	}
}
#endif

/* Create instance value based on array index or
 * create instance value based on Bluetooth address.
 */
static int get_instance(const bt_addr_le_t *addr, int idx)
{
#if !defined(CONFIG_LCZ_LWM2M_GATEWAY_OBJ_STATIC_INST_LIST)
	return LCZ_LWM2M_GW_LEGACY_INSTANCE(idx);
#else
	const char *file_name = CONFIG_LCZ_LWM2M_GATEWAY_OBJ_STATIC_INST_LIST_FILE;
	uint32_t i = 0;
	uint32_t offset = 0;
	ssize_t status;
	bt_addr_le_t inst_addr = { 0 };
	const size_t size = sizeof(bt_addr_le_t);

	do {
		status = fsu_read_abs_block(file_name, offset, &inst_addr, size);
		if (bt_addr_le_cmp(addr, &inst_addr) == 0) {
			LOG_INF("Matched Bluetooth Address index: %u", i);
			break;
		}
		i += 1;
		offset += size;
	} while (status == size);

	/* If address wasn't found, then add it to the list */
	if (status <= 0) {
		status = fsu_append_abs(file_name, (void *)addr, size);
		LOG_DBG("Append static instance list: %d", status);
	}

	return LCZ_LWM2M_GW_LEGACY_INSTANCE(i);
#endif
}
