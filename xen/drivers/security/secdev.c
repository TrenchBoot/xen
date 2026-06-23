/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Copyright (c) 2023, Apertus Solutions, LLC
 * All rights reserved.
 */

#include <xen/err.h>
#include <xen/lib.h>

#include "secdev.h"
#include "tpm/tpm_drv.h"

static struct {
    struct secdev_handle *tpm;
} dev_handles;

static struct secdev_handle *get_dev_handle(secdev_id_t id)
{
    switch ( id )
    {
    case SECDEV_TPM:
        if ( dev_handles.tpm != NULL )
            return dev_handles.tpm;

        printk(XENLOG_ERR "Requested TPM but no TPM was registered\n");
        break;
    default:
        printk(XENLOG_ERR "Unknown device id (%d)\n", id);
    }

    return NULL;
}

ssize_t secdev_getrandom(enum secdev_id dev_id, secdev_opt_t *opts)
{
    struct secdev_handle *h = get_dev_handle(dev_id);
    secdev_result_t res;
    int ret = 0;

    if ( h == NULL )
        return -EINVAL;

    if ( h->getrandom == NULL )
    {
        printk(XENLOG_ERR "getrandom() unsupported by security device (%d) \n",
               dev_id);
        return -EINVAL;
    }

    ret = h->getrandom(opts, &res);
    if ( ret < 0 )
        return ret;

    return res.tpm.random.len;
}

int secdev_measure_buffer(enum secdev_id dev_id, secdev_opt_t *opts)
{
    struct secdev_handle *h = get_dev_handle(dev_id);
    secdev_result_t res;

    if ( h == NULL )
        return -EINVAL;

    if ( h->measure_buffer == NULL )
    {
        printk(XENLOG_ERR "measure_domain() unsupported by security device (%d) \n",
               dev_id);
        return -EINVAL;
    }

    return h->measure_buffer(opts, &res);
}

int secdev_measure_domain(enum secdev_id dev_id, secdev_opt_t *opts)
{
    struct secdev_handle *h = get_dev_handle(dev_id);
    secdev_result_t res;

    if ( h == NULL )
        return -EINVAL;

    if ( h->measure_domain == NULL )
    {
        printk(XENLOG_ERR "measure_domain() unsupported by security device (%d) \n",
               dev_id);
        return -EINVAL;
    }

    return h->measure_domain(opts, &res);
}

bool secdev_available(enum secdev_id dev_id)
{
    return (get_dev_handle(dev_id) != NULL);
}

int secdev_init(void)
{
#ifdef CONFIG_TPM_HARDWARE
    dev_handles.tpm = tpm_driver_init();
#endif

    return 0;
}
