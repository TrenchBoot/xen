/*
 * tpm_mmio.c: TPM MMIO hardware interface
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <asm/io.h>
#include <asm/processor.h>
#include <xen/lib.h>
#include <xen/lib/hash.h>
#include <xen/lib/sha1.h>
#include <xen/lib/sha2.h>

#include "tpm.h"

/* Global variables for TPM status register */
static tpm20_reg_sts_t g_reg_sts, *g_reg_sts_20 = &g_reg_sts;
static tpm12_reg_sts_t *g_reg_sts_12 = (tpm12_reg_sts_t *)&g_reg_sts;


/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
        uint8_t _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

typedef union {
        uint8_t _raw[1];
} tpm_reg_data_crb_t;

#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_d)  /* let it long enough */
#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100

#define read_tpm_sts_reg(locality) { \
if ( get_tpm()->family == TPM_IF_12 ) \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_20); \
}

#define write_tpm_sts_reg(locality) { \
if ( get_tpm()->family == TPM_IF_12 ) \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_20); \
}

/* MMIO status register helpers */

static void tpm_print_status_register(void)
{
    if ( get_tpm()->family == TPM_IF_12 )
    {
        printk(XENLOG_INFO"TPM: status reg content: %02x %02x %02x\n",
            (uint32_t)g_reg_sts_12->_raw[0],
            (uint32_t)g_reg_sts_12->_raw[1],
            (uint32_t)g_reg_sts_12->_raw[2]);
    }
    else
    {
        printk(XENLOG_INFO"TPM: status reg content: %02x %02x %02x %02x\n",
            (uint32_t)g_reg_sts_20->_raw[0],
            (uint32_t)g_reg_sts_20->_raw[1],
            (uint32_t)g_reg_sts_20->_raw[2],
            (uint32_t)g_reg_sts_20->_raw[3]);
    }
}

static uint16_t tpm_get_burst_count(uint32_t locality)
{
    read_tpm_sts_reg(locality);
    return g_reg_sts.burst_count;
}

static bool tpm_check_expect_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(XENLOG_INFO"Wait on Expect = 0, Status register %02x\n",
        g_reg_sts._raw[0]);
#endif
    return g_reg_sts.sts_valid == 1 && g_reg_sts.expect == 0;
}

static bool tpm_check_da_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(XENLOG_INFO"Waiting for DA Flag, Status register %02x\n",
        g_reg_sts._raw[0]);
#endif
    return g_reg_sts.sts_valid == 1 && g_reg_sts.data_avail == 1;
}

/* FIFO interface commands */

bool cf_check fifo_request_locality(uint32_t locality)
{
    uint32_t            i;
    tpm_reg_access_t    reg_acc;

    /* request access to the TPM from locality N */
    reg_acc._raw[0] = 0;
    reg_acc.request_use = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 1 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

    if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT )
    {
        printk(XENLOG_ERR"TPM: FIFO_INF access reg request use timeout\n");
        return false;
    }

    return true;
}

static bool cf_check fifo_validate_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_access_t reg_acc;

    for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- )
    {
        /*
         * TCG spec defines reg_acc.tpm_reg_valid_sts bit to indicate whether
         * other bits of access reg are valid.( but this bit will also be 1
         * while this locality is not available, so check seize bit too)
         * It also defines that reading reg_acc.seize should always return 0
         */
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.tpm_reg_valid_sts == 1 && reg_acc.seize == 0)
            return true;
        cpu_relax();
    }
    if ( i <= 0 )
        printk(XENLOG_ERR"TPM: tpm_validate_locality timeout\n");

    return false;
}

static bool cf_check fifo_release_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_access_t reg_acc;

#ifdef TPM_TRACE
    printk(XENLOG_INFO"TPM: releasing locality %u\n", locality);
#endif

    if ( !fifo_validate_locality(locality) )
        return true;

    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
    if ( reg_acc.active_locality == 0 )
        return true;

    /* make inactive by writing a 1 */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 0 )
            return true;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

    printk(XENLOG_INFO"TPM: access reg release locality timeout\n");
    return false;
}

static void fifo_quick_release_locality(uint32_t locality)
{
    tpm_reg_access_t reg_acc;

    /* fire and forget deactivate locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
}

static void fifo_send_cmd_ready_status(uint32_t locality)
{
    /* write 1 to TPM_STS_x.commandReady to let TPM enter ready state */
    memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
    g_reg_sts.command_ready = 1;
    write_tpm_sts_reg(locality);
}

static bool fifo_check_cmd_ready_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(XENLOG_INFO".");
#endif
    return g_reg_sts.command_ready;
}

static bool fifo_wait_cmd_ready(uint32_t locality)
{
    uint32_t i;

    /* request access to the TPM from locality N */
    if ( !fifo_request_locality(locality) )
        return false;

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk(XENLOG_INFO"TPM: wait for cmd ready \n");
#endif

    i = 0;
    do {
        fifo_send_cmd_ready_status(locality);
        cpu_relax();
        /* then see if it has */

        if ( fifo_check_cmd_ready_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_CMD_READY_TIME_OUT );
#ifdef TPM_TRACE
    printk(XENLOG_INFO"\n");
#endif

    if ( i > TPM_CMD_READY_TIME_OUT )
    {
        tpm_print_status_register();
        printk(XENLOG_INFO"TPM: tpm timeout for command_ready\n");
        fifo_quick_release_locality(locality);
        return false;
    }

    return true;
}

static void fifo_execute_cmd(uint32_t locality)
{
    memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
    g_reg_sts.tpm_go = 1;
    write_tpm_sts_reg(locality);
}

static bool cf_check fifo_submit_cmd(
    uint32_t locality, uint8_t *in, u32 in_size,  u8 *out, u32 *out_size)
{
    uint32_t i, rsp_size, offset;
    uint16_t row_size;

    if ( locality >= TPM_NR_LOCALITIES )
    {
        printk(XENLOG_WARNING
            "TPM: Invalid locality for tpm_write_cmd_fifo()\n");
        return false;
    }
    if ( in == NULL || out == NULL || out_size == NULL )
    {
        printk(XENLOG_WARNING
            "TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return false;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE )
    {
        printk(XENLOG_WARNING
            "TPM: in/out buf size must be larger than 10 bytes\n");
        return false;
    }

    if ( !fifo_validate_locality(locality) )
    {
        printk(XENLOG_WARNING"TPM: Locality %d is not open\n", locality);
        return false;
    }

    if ( !fifo_wait_cmd_ready(locality) )
        return false;

#ifdef TPM_TRACE
    {
        printk(XENLOG_INFO"TPM: cmd size = 0x%x\nTPM: cmd content: ", in_size);
        printk("TPM: \t%*ph\n", in_size, in);
    }
#endif

    /* write the command to the TPM FIFO */
    offset = 0;
    do {
        i = 0;
        do {
            /* find out how many bytes the TPM can accept in a row */
            row_size = tpm_get_burst_count(locality);
            if ( row_size > 0 )   break;
            else  cpu_relax();
            i++;
        } while ( i <= TPM_CMD_WRITE_TIME_OUT );
        if ( i > TPM_CMD_WRITE_TIME_OUT )
        {
            printk(XENLOG_ERR"TPM: write cmd timeout\n");
            fifo_quick_release_locality(locality);
            return false;
        }

        for ( ; row_size > 0 && offset < in_size; row_size--, offset++ )
            write_tpm_reg(locality, TPM_REG_DATA_FIFO,
                (tpm_reg_data_fifo_t *)&in[offset]);
    } while ( offset < in_size );

    i = 0;
    do {
        if ( tpm_check_expect_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT )
    {
        printk(XENLOG_ERR"TPM: wait for expect becoming 0 timeout\n");
        fifo_quick_release_locality(locality);
        return false;
    }

    /* command has been written to the TPM, it is time to execute it. */
    fifo_execute_cmd(locality);

    /* check for data available */
    i = 0;
    do {
        if ( tpm_check_da_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(XENLOG_ERR"TPM: wait for data available timeout\n");
        fifo_quick_release_locality(locality);
        return false;
    }

    rsp_size = 0;
    offset = 0;
    do {
        /* find out how many bytes the TPM returned in a row */
        i = 0;
        do {
            row_size = tpm_get_burst_count(locality);
            if ( row_size > 0 )
                break;
            else
                cpu_relax();
            i++;
        } while ( i <= TPM_RSP_READ_TIME_OUT );
        if ( i > TPM_RSP_READ_TIME_OUT )
        {
            printk(XENLOG_ERR"TPM: read rsp timeout\n");
            fifo_quick_release_locality(locality);
            return false;
        }

        for ( ; row_size > 0 && offset < *out_size; row_size--, offset++ )
        {
            if ( offset < *out_size )
            {
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                    (tpm_reg_data_fifo_t *)&out[offset]);
            }
            else
            {
                /* discard the responded bytes exceeding out buf size */
                tpm_reg_data_fifo_t discard;
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                    (tpm_reg_data_fifo_t *)&discard);
            }

            /* get outgoing data size */
            if ( offset == RSP_RST_OFFSET - 1 )
                reverse_copy(&rsp_size, &out[RSP_SIZE_OFFSET], sizeof(rsp_size));
        }
    } while ( offset < RSP_RST_OFFSET ||
              (offset < rsp_size && offset < *out_size) );

    *out_size = (*out_size > rsp_size) ? rsp_size : *out_size;

#ifdef TPM_TRACE
    {
        printk(XENLOG_INFO"TPM: response size = %d\n", *out_size);
        printk(XENLOG_INFO"TPM: response content: ");
        printk("TPM: \t%*ph\n", *out_size, out);
    }
#endif

    fifo_send_cmd_ready_status(locality);

    return true;
}


static const struct tpm_hw_if fifo_hw_intf = {
    .request_locality = fifo_request_locality,
    .validate_locality = fifo_validate_locality,
    .release_locality = fifo_release_locality,
    .submit_cmd = fifo_submit_cmd,
};


/*
 * CRB interafce commands
 */

/* Pre-declaration for single loop circular call */
static bool crb_locality_workaround(void);

static bool cf_check crb_request_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_loc_state_t  reg_loc_state;
    tpm_reg_loc_ctrl_t    reg_loc_ctrl;

    /* request access to the TPM from locality N */
    memset(&reg_loc_ctrl,0,sizeof(reg_loc_ctrl));
    reg_loc_ctrl.requestAccess = 1;
    write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
        if ( reg_loc_state.active_locality == locality &&
             reg_loc_state.loc_assigned == 1)
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

    if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT )
    {
        printk(XENLOG_ERR"TPM: access loc request use timeout\n");
        printk(XENLOG_ERR"  attempting workaround\n");
        return crb_locality_workaround();
    }

    return true;
}

static bool crb_locality_workaround(void)
{
    tpm_reg_ctrl_cmdsize_t  CmdSize;
    tpm_reg_ctrl_cmdaddr_t  CmdAddr;
    tpm_reg_ctrl_rspsize_t  RspSize;
    tpm_reg_ctrl_rspaddr_t  RspAddr;
    uint32_t locality = 0;

    if ( !crb_request_locality(locality) )
        return false;

    CmdAddr.cmdladdr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdAddr.cmdhaddr = 0;
    RspAddr.rspaddr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdSize.cmdsize = TPMCRBBUF_LEN;
    RspSize.rspsize = TPMCRBBUF_LEN;

    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, &CmdAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, &CmdSize);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, &RspAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, &RspSize);

    return true;
}

bool cf_check crb_validate_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_loc_state_t reg_loc_state;

    for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- )
    {
        /*
        *  Platfrom Tpm  Profile for TPM 2.0 SPEC
        */
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
        if ( reg_loc_state.tpm_reg_valid_sts == 1 &&
             reg_loc_state.loc_assigned == 1 &&
             reg_loc_state.active_locality == locality)
        {
            printk(XENLOG_INFO"TPM: reg_loc_state._raw[0]:  0x%x\n",
                reg_loc_state._raw[0]);
            return true;
        }
        cpu_relax();
    }

    printk(XENLOG_ERR"TPM: tpm_validate_locality_crb timeout\n");
    printk(XENLOG_INFO"TPM: reg_loc_state._raw[0]: 0x%x\n",
        reg_loc_state._raw[0]);
    return false;
}

bool cf_check crb_relinquish_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_loc_state_t reg_loc_state;
    tpm_reg_loc_ctrl_t reg_loc_ctrl;

#ifdef TPM_TRACE
    printk(XENLOG_INFO"TPM: releasing CRB_INF locality %u\n", locality);
#endif

    if ( !crb_validate_locality(locality) )
        return true;
    read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
    if ( reg_loc_state.loc_assigned == 0 )
        return true;

    /* make inactive by writing a 1 */
    memset(&reg_loc_ctrl,0,sizeof(reg_loc_ctrl));
    reg_loc_ctrl.relinquish = 1;
    write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
        if ( reg_loc_state.loc_assigned == 0 )
            return true;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

    printk(XENLOG_INFO"TPM: CRB_INF release locality timeout\n");
    return false;
}


static bool crb_send_cmd_ready_status(uint32_t locality)
{
    uint32_t i = 0;
    tpm_reg_ctrl_request_t reg_ctrl_request;
    tpm_reg_ctrl_sts_t reg_ctrl_sts;

    read_tpm_reg(locality, TPM_CRB_CTRL_STS, &reg_ctrl_sts);

#ifdef TPM_TRACE
    printk(XENLOG_INFO"1. reg_ctrl_sts.tpmidle: 0x%x\n", reg_ctrl_sts.tpmidle);
    printk(XENLOG_INFO"1. reg_ctrl_sts.tpmsts: 0x%x\n", reg_ctrl_sts.tpmsts);
#endif

    if ( reg_ctrl_sts.tpmidle == 1)
    {
        memset(&reg_ctrl_request,0,sizeof(reg_ctrl_request));
        reg_ctrl_request.cmdReady = 1;
        write_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

        return true;
    }

    memset(&reg_ctrl_request,0,sizeof(reg_ctrl_request));
    reg_ctrl_request.goIdle = 1;
    write_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

    do {
        read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);
        if ( reg_ctrl_request.goIdle == 0)
        {
            break;
        }
        else
        {
            cpu_relax();
            read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

#ifdef TPM_TRACE
            printk(XENLOG_INFO"1. reg_ctrl_request.goIdle: 0x%x\n",
                reg_ctrl_request.goIdle);
            printk(XENLOG_INFO"1. reg_ctrl_request.cmdReady: 0x%x\n",
                reg_ctrl_request.cmdReady);
#endif

        }
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT);

    if ( i > TPM_DATA_AVAIL_TIME_OUT )
    {
        printk(XENLOG_ERR"TPM: reg_ctrl_request.goidle timeout!\n");
        return false;
    }

    read_tpm_reg(locality, TPM_CRB_CTRL_STS, &reg_ctrl_sts);

#ifdef TPM_TRACE
    printk(XENLOG_INFO"2. reg_ctrl_sts.tpmidle: 0x%x\n", reg_ctrl_sts.tpmidle);
    printk(XENLOG_INFO"2. reg_ctrl_sts.tpmsts: 0x%x\n", reg_ctrl_sts.tpmsts);
#endif

    memset(&reg_ctrl_request,0,sizeof(reg_ctrl_request));
    reg_ctrl_request.cmdReady = 1;
    write_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

#ifdef TPM_TRACE
    printk(XENLOG_INFO"2. reg_ctrl_request.goIdle: 0x%x\n",
        reg_ctrl_request.goIdle);
    printk(XENLOG_INFO"2. reg_ctrl_request.cmdReady: 0x%x\n",
        reg_ctrl_request.cmdReady);
#endif

    read_tpm_reg(locality, TPM_CRB_CTRL_STS, &reg_ctrl_sts);

#ifdef TPM_TRACE
    printk(XENLOG_INFO"2. reg_ctrl_sts.tpmidle: 0x%x\n", reg_ctrl_sts.tpmidle);
    printk(XENLOG_INFO"2. reg_ctrl_sts.tpmsts: 0x%x\n", reg_ctrl_sts.tpmsts);
#endif

    return true;

}

static bool crb_check_cmd_ready_status(uint32_t locality)
{
    tpm_reg_ctrl_request_t reg_ctrl_request;
    read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

#ifdef TPM_TRACE
    printk(XENLOG_INFO"3. reg_ctrl_request.goIdle: 0x%x\n",
        reg_ctrl_request.goIdle);
    printk(XENLOG_INFO"3. reg_ctrl_request.cmdReady: 0x%x\n",
        reg_ctrl_request.cmdReady);
#endif

    if ( reg_ctrl_request.cmdReady == 0)
        return true;
    else
        return false;

}

static bool crb_wait_cmd_ready(uint32_t locality)
{
    uint32_t i;

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk(XENLOG_INFO"TPM: wait for cmd ready \n");
#endif
    crb_send_cmd_ready_status(locality);
    i = 0;
    do {
        if ( crb_check_cmd_ready_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_CMD_READY_TIME_OUT );

    if ( i > TPM_CMD_READY_TIME_OUT )
    {
        //tpm_print_status_register();
        printk(XENLOG_INFO"TPM: tpm timeout for command_ready\n");
        return false;
    }

    return true;
}

bool cf_check crb_submit_cmd(
    uint32_t locality, uint8_t *in, u32 in_size,  u8 *out, u32 *out_size)
{
    uint32_t i;
    //tpm_reg_loc_ctrl_t reg_loc_ctrl;
    tpm_reg_ctrl_start_t start;
    tpm_reg_ctrl_cmdsize_t  CmdSize;
    tpm_reg_ctrl_cmdaddr_t  CmdAddr;
    tpm_reg_ctrl_rspsize_t  RspSize;
    tpm_reg_ctrl_rspaddr_t  RspAddr;
    uint32_t tpm_crb_data_buffer_base;

    if ( locality >= TPM_NR_LOCALITIES )
    {
        printk(XENLOG_WARNING
            "TPM: Invalid locality for tpm_submit_cmd_crb()\n");
        return false;
    }
    if ( in == NULL || out == NULL || out_size == NULL )
    {
        printk(XENLOG_WARNING
            "TPM: Invalid parameter for tpm_submit_cmd_crb()\n");
        return false;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE )
    {
        printk(XENLOG_WARNING
            "TPM: in/out buf size must be larger than 10 bytes\n");
        return false;
    }

    if ( !crb_validate_locality(locality) )
    {
        printk(XENLOG_WARNING
            "TPM: CRB Interface Locality %d is not open\n", locality);
        return false;
    }

    if ( !crb_wait_cmd_ready(locality) )
    {
        printk(XENLOG_WARNING"TPM: tpm_wait_cmd_read_crb failed\n");
     return false;
    }

#ifdef TPM_TRACE
    {
        printk(XENLOG_INFO
            "TPM: Before submit, cmd size = 0x%x\nTPM: Before submit, cmd content: ",
            in_size);
        printk("TPM: \t%*ph\n", in_size, in);
    }
#endif

    /* write the command to the TPM CRB  buffer 01-04-2016  */
//copy *in and size to crb buffer

    CmdAddr.cmdladdr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdAddr.cmdhaddr = 0;
    RspAddr.rspaddr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdSize.cmdsize = TPMCRBBUF_LEN;
    RspSize.rspsize = TPMCRBBUF_LEN;
    tpm_crb_data_buffer_base = TPM_CRB_DATA_BUFFER;


#ifdef TPM_TRACE
    printk(XENLOG_INFO"CmdAddr.cmdladdr is 0x%x\n",CmdAddr.cmdladdr);
    printk(XENLOG_INFO"CmdAddr.cmdhaddr is 0x%x\n",CmdAddr.cmdhaddr);
    printk(XENLOG_INFO"CmdSize.cmdsize is 0x%x\n",CmdSize.cmdsize);
    printk(XENLOG_INFO"RspAddr.rspaddr is 0x%lx\n",RspAddr.rspaddr);
    printk(XENLOG_INFO"RspSize.rspsize is 0x%x\n",RspSize.rspsize);
#endif

    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, &CmdAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, &CmdSize);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, &RspAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, &RspSize);
    // write the command to the buffer
    for ( i = 0 ; i< in_size; i++ )
    {
        write_tpm_reg(locality, tpm_crb_data_buffer_base++,
            (tpm_reg_data_crb_t *)&in[i]);
        //tpm_crb_data_buffer_base++;
    }

    /* command has been written to the TPM, it is time to execute it. */
    start.start = 1;
    write_tpm_reg(locality, TPM_CRB_CTRL_START, &start);
    //read_tpm_reg(locality, TPM_CRB_CTRL_START, &start);
    printk(XENLOG_INFO"tpm_ctrl_start.start is 0x%x\n",start.start);

    /* check for data available */
    i = 0;
    do {
        read_tpm_reg(locality, TPM_CRB_CTRL_START, &start);
        //printk(XENLOG_INFO"tpm_ctrl_start.start is 0x%x\n",start.start);
        if ( start.start == 0 )
            break;
         else
            cpu_relax();
         i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );

    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(XENLOG_ERR"TPM: wait for data available timeout\n");
        return false;
    }

    tpm_crb_data_buffer_base = TPM_CRB_DATA_BUFFER;

    for ( i = 0 ; i< *out_size; i++ )
    {
        read_tpm_reg(locality, tpm_crb_data_buffer_base++, (tpm_reg_data_crb_t *)&out[i]);
        //tpm_crb_data_buffer_base++;
    }

#ifdef TPM_TRACE
    {
        printk(XENLOG_INFO"TPM: After cmd submit, response size = 0x%x\n",
            *out_size);
        printk(XENLOG_INFO"TPM: After cmd submit, response content: ");
        printk("TPM: \t%*ph\n", *out_size, out);
    }
#endif

    //tpm_send_cmd_ready_status_crb(locality);

    return true;
}

static const struct tpm_hw_if crb_hw_intf = {
    .request_locality = crb_request_locality,
    .validate_locality = crb_validate_locality,
    .release_locality = crb_relinquish_locality,
    .submit_cmd = crb_submit_cmd,
};


void mmio_detect_interface(struct tpm_if *tpm)
{
    tpm_crb_interface_id_t crb_interface;
    read_tpm_reg(0, TPM_INTERFACE_ID, &crb_interface);
    if (crb_interface.interface_type == TPM_INTERFACE_ID_CRB  )
    {
        printk(XENLOG_INFO"TPM: PTP CRB interface is active...\n");
        tpm->family = TPM_IF_20_CRB;
        tpm->hw = &crb_hw_intf;
        return;
    }
    if (crb_interface.interface_type == TPM_INTERFACE_ID_FIFO_20)
    {
        printk(XENLOG_INFO"TPM: TPM 2.0 FIFO interface is active...\n");
        tpm->family = TPM_IF_20_FIFO;
        tpm->hw = &fifo_hw_intf;
        return;
    }

    tpm->family = TPM_IF_12;
    tpm->hw = &fifo_hw_intf;
    return;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
