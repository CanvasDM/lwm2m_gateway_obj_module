/**
 * @file lcz_lwm2m_gateway_obj.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_LWM2M_GATEWAY_OBJ_H__
#define __LCZ_LWM2M_GATEWAY_OBJ_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <zephyr.h>
#include <zephyr/types.h>
#include <bluetooth/addr.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
typedef void (*lcz_lwm2m_device_deleted_cb_t)(int idx, void *data_ptr);
typedef void (*lcz_lwm2m_device_foreach_cb_t)(int idx, void *dm_ptr, void *telem_ptr, void *priv);

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/

/**
 * @brief Find gateway object index for a device by BLE address
 *
 * Look up a device in the gateway object database by Bluetooth address.
 *
 * @param[in] addr BLE address to look up
 *
 * @returns <0 on error or the index of the gateway object database entry.
 */
int lcz_lwm2m_gw_obj_lookup_ble(const bt_addr_le_t *addr);

/**
 * @brief Find gateway object index for a device by path
 *
 * Look up a device in the gateway object database by path.
 *
 * @param[in] path Path to look up
 *
 * @returns <0 on error or the index of the gateway object database entry.
 */
int lcz_lwm2m_gw_obj_lookup_path(char *prefix);

/**
 * @brief Add a device to the database
 *
 * @param[in] addr BLE address of the device to add
 *
 * @returns <0 on error or the index of the gateway object database entry.
 */
int lcz_lwm2m_gw_obj_create(const bt_addr_le_t *addr);

/**
 * @brief Get the BLE address of a device
 *
 * @param[in] idx Gateway object database index
 *
 * @returns a pointer to the BLE address for the device or NULL if the device is invalid
 */
bt_addr_le_t *lcz_lwm2m_gw_obj_get_address(int idx);

/**
 * @brief Get the BLE address of a device as a string
 *
 * @param[in] idx Gateway object database index
 *
 * @returns a pointer to a statically-allocated string representing the device address
 * or NULL on error
 */
char *lcz_lwm2m_gw_obj_get_addr_string(int idx);

/**
 * @brief Get the instance number of a device
 *
 * @param[in] idx Gateway object database index
 *
 * @returns The instance number used for the device or a negative error code
 */
int lcz_lwm2m_gw_obj_get_instance(int idx);

/**
 * @brief Get the prefix string for a device
 *
 * @param[in] idx Gateway object database index
 *
 * @returns A pointer to the prefix string for the device or NULL if it doesn't exist
 */
char *lcz_lwm2m_gw_obj_get_prefix(int idx);

/**
 * @brief Call a callback function for each device in the database
 *
 * This function can be used by other software layers to iterate over the
 * list of devices in the gateway object database. The provided callback is
 * called for each device in the database. The priv pointer is passed along
 * to the callback for private use by the callback.
 *
 * @param[in] cb Callback function to call on each database device
 * @param[in] priv Private data pointer passed to the callback
 *
 * @returns the number of devices in the database
 */
int lcz_lwm2m_gw_obj_foreach(lcz_lwm2m_device_foreach_cb_t cb, void *priv);

/**
 * @brief Update a device's expiration time
 *
 * The gateway object database keeps an expiration time for each device based
 * on its lifetime value. This function "ticks" the expiration time to that
 * the device will not expire until at least the device's lifetime.
 *
 * @param[in] idx Gateway object database index
 */
void lcz_lwm2m_gw_obj_tick(int idx);

/**
 * @brief Set/update a device's endpoint name
 *
 * Name will be copied into the database, so the passed pointer does
 * not need to persist.
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] name New endpoint name
 * @param[in] name_len Length of endpoint name string
 *
 * @returns <0 or error or 0 if name was updated.
 */
int lcz_lwm2m_gw_obj_set_endpoint_name(int idx, char *name, int name_len);

/**
 * @brief Read device's endpoint name from the database
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] name Buffer to write endpoint name into
 * @param[in] name_len Length of endpoint name string
 *
 * @returns <0 or error or 0 if name was copied.
 */
int lcz_lwm2m_gw_obj_get_endpoint_name(int idx, char *name, int name_len);

/**
 * @brief Set/update a device's object list
 *
 * The object list is specified as a CoreLnk string. The string will be
 * copied into the database, so the passed pointer does not need to
 * persist. The passed pointer also does not need to be NUL-terminated.
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] obj_list New object list
 * @param[in] obj_list_len Length of object list string
 *
 * @returns <0 or error or 0 if object list was updated.
 */
int lcz_lwm2m_gw_obj_set_object_list(int idx, char *obj_list, int obj_list_len);

/**
 * @brief Set/update a device's lifetime value
 *
 * Devices in the gateway object database have a defined lifetime. When the
 * device is not seen for a duration longer than its lifetime, the device is
 * removed from the database. This function is used to set a device's
 * lifetime value.
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] lifetime Device lifetime in seconds (0 if the device should
 * never be removed).
 *
 * @returns <0 or error or 0 if object list was updated.
 */
int lcz_lwm2m_gw_obj_set_lifetime(int idx, uint16_t lifetime);

/**
 * @brief Set/update a device's private DM data
 *
 * The gateway object database holds a pointer to private DM data
 * associated with the device. This function can be used to set
 * or update this pointer.
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] dm_ptr New DM private data pointer
 *
 * @returns <0 on error or 0 if database was updated.
 */
int lcz_lwm2m_gw_obj_set_dm_data(int idx, void *dm_ptr);

/**
 * @brief Get a device's private DM data
 *
 * @param[in] idx Gateway object database index for the device
 *
 * @returns The pointer to the private DM data or NULL on error
 */
void *lcz_lwm2m_gw_obj_get_dm_data(int idx);

/**
 * @brief Set/update a device's private telemetry data
 *
 * The gateway object database holds a pointer to private telemetry
 * data associated with the device. This function can be used to set
 * or update this pointer.
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] telem_ptr New telemetry private data pointer
 *
 * @returns <0 on error or 0 if database was updated.
 */
int lcz_lwm2m_gw_obj_set_telem_data(int idx, void *telem_ptr);

/**
 * @brief Get a device's private telemetry data
 *
 * @param[in] idx Gateway object database index for the device
 *
 * @returns The pointer to the private telemetry data or NULL on error
 */
void *lcz_lwm2m_gw_obj_get_telem_data(int idx);

/**
 * @brief Add device to blocklist
 *
 * Add the given device to the blocklist. The duration of the blocklisting is given by the
 * duration parameter. It is either 0 for a "permanent" blocklisting (until the next power
 * cycle of the gateway) or a value in seconds after which the device will be allowed again.
 *
 * The block list has a maximum size (given by CONFIG_LCZ_LWM2M_GATEWAY_OBJ_BLOCK_LIST_SIZE).
 * Attempting to add more than that number of entries to the block list will result in an
 * -ENOMEM error returned by this function.
 *
 * @param[in] idx Gateway object database index for the device
 * @param[in] duration Duration of the blocklisting in seconds (or 0 for a permanent block)
 *
 * @returns <0 on error or 0 if the device was added to the block list
 */
int lcz_lwm2m_gw_obj_add_blocklist(int idx, uint16_t duration);

/**
 * @brief Set DM device delete callback
 *
 * This function allows the DM layer to set a callback to be called when
 * a device from the gateway object database is deleted. Devices are deleted
 * for two reasons: the device has not been seen within its lifetime duration
 * or the server has indicated that the device should not be linked to this
 * gateway.
 *
 * @param[in] dm_cb Pointer to the new DM device delete callback
 */
void lcz_lwm2m_gw_obj_set_dm_delete_cb(lcz_lwm2m_device_deleted_cb_t dm_cb);

/**
 * @brief Set telemetry device delete callback
 *
 * This function allows the telemetry layer to set a callback to be called when
 * a device from the gateway object database is deleted. Devices are deleted
 * for two reasons: the device has not been seen within its lifetime duration
 * or the server has indicated that the device should not be linked to this
 * gateway.
 *
 * @param[in] dm_cb Pointer to the new telemetry device delete callback
 */
void lcz_lwm2m_gw_obj_set_telem_delete_cb(lcz_lwm2m_device_deleted_cb_t telem_cb);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_GATEWAY_OBJ_H__ */
