/*
 * (C) Copyright 2014 Emil Ljungdahl
 *
 * This file is part of libambit.
 *
 * libambit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contributors:
 *
 */
#include "libambit.h"
#include "libambit_int.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Local definitions
 */

/*
 * Static functions
 */
static int device_info_get(ambit_object_t *object, ambit_device_info_t *info);

/*
 * Static variables
 */
static uint8_t komposti_version[] = { 0x01, 0x08, 0x01, 0x00 };

/*
 * Public functions
 */
ambit_object_t *libambit_detect(void)
{
    hid_device *handle;
    struct hid_device_info *devs, *cur_dev;
    ambit_object_t *ret_object = NULL;
    uint16_t vendor_id, product_id;
    const ambit_known_device_t *device = NULL;
    char *path = NULL;

    LOG_INFO("Searching devices");

    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        LOG_INFO("vendor_id=%04x, product_id=%04x", cur_dev->vendor_id, cur_dev->product_id);
        if (libambit_device_support_known(cur_dev->vendor_id, cur_dev->product_id)) {
            LOG_INFO("match!");
            if (cur_dev->path != NULL) {
                path = strdup (cur_dev->path);
            }
            vendor_id = cur_dev->vendor_id;
            product_id = cur_dev->product_id;
            break;
        }
        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);

    // If we found a device, lets try read out information
    if (cur_dev != NULL) {
        LOG_INFO("Trying to open device");
        handle = hid_open(vendor_id, product_id, NULL);
        if (handle != NULL) {
            // Setup hid device correctly
            hid_set_nonblocking(handle, 1);

            ret_object = malloc(sizeof(ambit_object_t));
            memset(ret_object, 0, sizeof(ambit_object_t));
            ret_object->handle = handle;
            ret_object->vendor_id = vendor_id;
            ret_object->product_id = product_id;

            // Get device info to resolve supported functionality
            if (device_info_get(ret_object, &ret_object->device_info) == 0) {
                device = libambit_device_support_find(vendor_id, product_id, ret_object->device_info.model, ret_object->device_info.fw_version);
                strncpy(ret_object->device_info.name, device->name, LIBAMBIT_PRODUCT_NAME_LENGTH);
                ret_object->device_info.is_supported = device->supported;
                ret_object->driver = device->driver;

                // Initialize driver
                ret_object->driver->init(ret_object, device->driver_param);

                LOG_INFO("Successfully opened device \"%s\" SW: %d.%d.%d, Supported: %s", device->name, ret_object->device_info.fw_version[0], ret_object->device_info.fw_version[1], ret_object->device_info.fw_version[3] << 8 | ret_object->device_info.fw_version[2], device->supported ? "YES" : "NO");
            }
            else {
                free(ret_object);
                ret_object = NULL;
                LOG_ERROR("Failed to retreive device info");
            }
        }
        else {
#ifdef DEBUG_PRINT_ERROR
            int error = 0;
            int fd = 0;
            if (path) fd = open (path, O_RDWR);
            if (-1 == fd) error = errno;
            else close (fd);
#endif
            LOG_ERROR("Failed to open device \"%s\"", device->name);
            LOG_ERROR("Reason: %s", (error ? strerror(error) : "Unknown"));
        }
    }

    if (path) free (path);
    return ret_object;
}

void libambit_close(ambit_object_t *object)
{
    LOG_INFO("Closing");
    if (object != NULL) {
        if (object->driver != NULL) {
            // Make sure to clear log lock (if possible)
            if (object->driver->lock_log != NULL) {
                object->driver->lock_log(object, false);
            }
            if (object->driver->deinit != NULL) {
                object->driver->deinit(object);
            }
        }

        if (object->handle != NULL) {
            hid_close(object->handle);
        }

        free(object);
    }
}

bool libambit_device_supported(ambit_object_t *object)
{
    bool ret = false;

    if (object != NULL) {
        ret = object->device_info.is_supported;
    }

    return ret;
}

int libambit_device_info_get(ambit_object_t *object, ambit_device_info_t *info)
{
    int ret = -1;

    if (object != NULL) {
        if (info != NULL) {
            memcpy(info, &object->device_info, sizeof(ambit_device_info_t));
        }
        ret = 0;
    }

    return ret;
}

void libambit_sync_display_show(ambit_object_t *object)
{
    if (object->driver != NULL && object->driver->lock_log != NULL) {
        object->driver->lock_log(object, true);
    }
}

void libambit_sync_display_clear(ambit_object_t *object)
{
    if (object->driver != NULL && object->driver->lock_log != NULL) {
        object->driver->lock_log(object, false);
    }
}

int libambit_date_time_set(ambit_object_t *object, struct tm *tm)
{
    int ret = -1;

    if (object->driver != NULL && object->driver->date_time_set != NULL) {
        ret = object->driver->date_time_set(object, tm);
    }
    else {
        LOG_WARNING("Driver does not support date_time_set");
    }

    return ret;
}

int libambit_device_status_get(ambit_object_t *object, ambit_device_status_t *status)
{
    int ret = -1;

    if (object->driver != NULL && object->driver->status_get != NULL) {
        ret = object->driver->status_get(object, status);
    }
    else {
        LOG_WARNING("Driver does not support status_get");
    }

    return ret;
}

int libambit_personal_settings_get(ambit_object_t *object, ambit_personal_settings_t *settings)
{
    int ret = -1;

    if (object->driver != NULL && object->driver->personal_settings_get != NULL) {
        ret = object->driver->personal_settings_get(object, settings);
    }
    else {
        LOG_WARNING("Driver does not support personal_settings_get");
    }

    return ret;
}

int libambit_gps_orbit_header_read(ambit_object_t *object, uint8_t data[8])
{
    int ret = -1;

    if (object->driver != NULL && object->driver->gps_orbit_header_read != NULL) {
        ret = object->driver->gps_orbit_header_read(object, data);
    }
    else {
        LOG_WARNING("Driver does not support gps_orbit_header_read");
    }

    return ret;
}

int libambit_gps_orbit_write(ambit_object_t *object, uint8_t *data, size_t datalen)
{
    int ret = -1;

    if (object->driver != NULL && object->driver->gps_orbit_write != NULL) {
        ret = object->driver->gps_orbit_write(object, data, datalen);
    }
    else {
        LOG_WARNING("Driver does not support gps_orbit_write");
    }

    return ret;
}

int libambit_log_read(ambit_object_t *object, ambit_log_skip_cb skip_cb, ambit_log_push_cb push_cb, ambit_log_progress_cb progress_cb, void *userref)
{
    int ret = -1;

    if (object->driver != NULL && object->driver->log_read != NULL) {
        ret = object->driver->log_read(object, skip_cb, push_cb, progress_cb, userref);
    }
    else {
        LOG_WARNING("Driver does not support log_read");
    }

    return ret;
}

void libambit_log_entry_free(ambit_log_entry_t *log_entry)
{
    int i;

    if (log_entry != NULL) {
        if (log_entry->samples != NULL) {
            for (i=0; i<log_entry->samples_count; i++) {
                if (log_entry->samples[i].type == ambit_log_sample_type_periodic) {
                    if (log_entry->samples[i].u.periodic.values != NULL) {
                        free(log_entry->samples[i].u.periodic.values);
                    }
                }
                if (log_entry->samples[i].type == ambit_log_sample_type_gps_base) {
                    if (log_entry->samples[i].u.gps_base.satellites != NULL) {
                        free(log_entry->samples[i].u.gps_base.satellites);
                    }
                }
                if (log_entry->samples[i].type == ambit_log_sample_type_unknown) {
                    if (log_entry->samples[i].u.unknown.data != NULL) {
                        free(log_entry->samples[i].u.unknown.data);
                    }
                }
            }
            free(log_entry->samples);
        }
        free(log_entry);
    }
}

static int device_info_get(ambit_object_t *object, ambit_device_info_t *info)
{
    uint8_t *reply_data = NULL;
    size_t replylen;
    int ret = -1;

    LOG_INFO("Reading device info");

    if (libambit_protocol_command(object, ambit_command_device_info, komposti_version, sizeof(komposti_version), &reply_data, &replylen, 1) == 0) {
        if (info != NULL) {
            memcpy(info->model, reply_data, 16);
            info->model[16] = 0;
            memcpy(info->serial, &reply_data[16], 16);
            info->serial[16] = 0;
            memcpy(info->fw_version, &reply_data[32], 4);
            memcpy(info->hw_version, &reply_data[36], 4);
        }
        ret = 0;
    }
    else {
        LOG_WARNING("Failed to device info");
    }

    libambit_protocol_free(reply_data);

    return ret;
}
