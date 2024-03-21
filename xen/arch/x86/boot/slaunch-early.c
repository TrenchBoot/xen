/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/kernel.h>
#include <xen/slr-table.h>
#include <xen/types.h>

#include <asm/intel-txt.h>
#include <asm/slaunch.h>
#include <asm/x86-vendors.h>

/*
 * The AMD-defined structure layout for the SLB. The last two fields are
 * SL-specific.
 */
struct skinit_sl_header
{
    uint16_t skl_entry_point;
    uint16_t length;
    uint8_t reserved[62];
    uint16_t skl_info_offset;
    uint16_t bootloader_data_offset;
} __packed;

static bool is_intel_cpu(void)
{
    /*
     * asm/processor.h can't be included in early code, which means neither
     * cpuid() function nor boot_cpu_data can be used here.
     */
    uint32_t eax, ebx, ecx, edx;
    asm volatile ( "cpuid"
          : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
          : "0" (0), "c" (0) );
    return ebx == X86_VENDOR_INTEL_EBX
        && ecx == X86_VENDOR_INTEL_ECX
        && edx == X86_VENDOR_INTEL_EDX;
}

void asmlinkage slaunch_early_init(uint32_t load_base_addr,
                                   uint32_t tgt_base_addr,
                                   uint32_t tgt_end_addr,
                                   uint32_t slaunch_param,
                                   struct slaunch_early_init_results *result)
{
    void *txt_heap;
    const struct txt_os_mle_data *os_mle;
    const struct slr_table *slrt;
    const struct txt_os_sinit_data *os_sinit;
    const struct slr_entry_hdr *entry;
    const struct slr_entry_intel_info *intel_info;
    uint32_t size = tgt_end_addr - tgt_base_addr;

    if ( !is_intel_cpu() )
    {
        /*
         * Not an Intel CPU. Currently the only other option is AMD with SKINIT
         * and secure-kernel-loader (SKL).
         */
        const struct slr_entry_amd_info *amd_info;
        const struct skinit_sl_header *sl_header = (void *)slaunch_param;

        /*
         * slaunch_param holds a physical address of SLB.
         * Bootloader's data is SLRT.
         */
        result->slrt_pa = slaunch_param + sl_header->bootloader_data_offset;

        slrt = (struct slr_table *)(uintptr_t)result->slrt_pa;

        entry = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_AMD_INFO);
        if ( entry == NULL )
        {
            /* No reset mechanism or an error register on AMD. */
            asm volatile ("ud2");
            unreachable();
        }

        amd_info = container_of(entry, const struct slr_entry_amd_info, hdr);
        /* Basic checks only, SKL checked and consumed the rest. */
        if ( amd_info->hdr.size != sizeof(*amd_info) )
        {
            /* No reset mechanism or an error register on AMD. */
            asm volatile ("ud2");
            unreachable();
        }

        result->mbi_pa = amd_info->boot_params_base;
        return;
    }

    txt_heap = txt_init();
    os_mle = txt_start(txt_heap, TXT_OS2MLE);
    os_sinit = txt_start(txt_heap, TXT_OS2SINIT);

    if ( os_mle->slrt & ~0xffffffffULL )
        txt_reset(SLAUNCH_ERROR_BAD_SLRT_ADDRESS);

    result->slrt_pa = os_mle->slrt;

    slrt = (const struct slr_table *)result->slrt_pa;

    entry = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);
    if ( entry == NULL )
        txt_reset(SLAUNCH_ERROR_NO_VENDOR_INFO);

    intel_info = container_of(entry, const struct slr_entry_intel_info, hdr);
    if ( intel_info->hdr.size != sizeof(*intel_info) )
        txt_reset(SLAUNCH_ERROR_BAD_VENDOR_INFO);

    result->mbi_pa = intel_info->boot_params_base;

    txt_verify_pmr_ranges(os_mle, os_sinit, intel_info,
                          load_base_addr, tgt_base_addr, size);
}
