/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Functions related to DRTM on Intel using its TXT (Trusted eXecution
 * Technology).
 *
 * Copyright (c) 2022-2026 3mdeb Sp. z o.o.  All rights reserved.
 */

#include <xen/acpi.h>
#include <xen/bug.h>
#include <xen/delay.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/vmap.h>
#include <xen/xmalloc.h>
#include <asm/e820.h>
#include <asm/intel-txt.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/processor.h>
#include <asm/slaunch.h>

/*
 * Corresponding TXT registers seem to have 64-bits allocated for them, yet the
 * actual values are 32-bit long, so using the latter.
 */
static uint32_t __initdata txt_heap_base, txt_heap_size;

void __init txt_map_mem_regions(void)
{
    int rc;

    rc = slaunch_map_l2(TXT_PRIV_CONFIG_REGS_BASE, TXT_CONFIG_SPACE_SIZE);
    BUG_ON(rc != 0);

    txt_heap_base = txt_read(TXTCR_HEAP_BASE);
    BUG_ON(txt_heap_base == 0);

    txt_heap_size = txt_read(TXTCR_HEAP_SIZE);
    BUG_ON(txt_heap_size == 0);

    rc = slaunch_map_l2(txt_heap_base, txt_heap_size);
    BUG_ON(rc != 0);
}

/* Mark a RAM region as reserved if it isn't marked that way already. */
static bool __init reserve_ram(struct e820map *map, uint64_t start,
                               uint64_t end)
{
    unsigned int i;

    for ( i = 0; i < map->nr_map; i++ )
    {
        uint64_t rs = map->map[i].addr;
        uint64_t re = rs + map->map[i].size;

        /* The entry includes the range. */
        if ( start >= rs && end <= re )
            break;

        /* The entry intersects the range. */
        if ( end > rs && start < re )
        {
            /* Fatal failure. */
            return false;
        }
    }

    /*
     * If the range is not included by any entry and no entry intersects it,
     * then it's not listed in the memory map.  Consider this case as a success
     * since we're only preventing RAM from being used and unlisted range should
     * not be used.
     */
    if ( i == map->nr_map )
        return true;

    /*
     * e820_change_range_type() fails if the range is already marked with the
     * desired type.  Don't consider it an error if firmware has done it for us.
     */
    if ( map->map[i].type == E820_RESERVED )
        return true;

    return e820_change_range_type(map, start, end, E820_RAM, E820_RESERVED);
}

void __init txt_reserve_mem_regions(void)
{
    bool ok;
    uint32_t sinit_base, sinit_size;

    /* TXT Heap */
    BUG_ON(txt_heap_base == 0);
    printk("SLAUNCH: reserving TXT heap range [%#x, %#x)\n", txt_heap_base,
           txt_heap_base + txt_heap_size);
    ok = reserve_ram(&e820_raw, txt_heap_base, txt_heap_base + txt_heap_size);
    BUG_ON(!ok);

    sinit_base = txt_read(TXTCR_SINIT_BASE);
    BUG_ON(sinit_base == 0);

    sinit_size = txt_read(TXTCR_SINIT_SIZE);
    BUG_ON(sinit_size == 0);

    /* SINIT */
    printk("SLAUNCH: reserving SINIT memory range [%#x, %#x)\n", sinit_base,
           sinit_base + sinit_size);
    ok = reserve_ram(&e820_raw, sinit_base, sinit_base + sinit_size);
    BUG_ON(!ok);

    /* TXT Private Space */
    printk("SLAUNCH: reserving private TXT registers range [%#x, %#x)\n",
           TXT_PRIV_CONFIG_REGS_BASE,
           TXT_PRIV_CONFIG_REGS_BASE + TXT_CONFIG_SPACE_SIZE);
    ok = reserve_ram(&e820_raw, TXT_PRIV_CONFIG_REGS_BASE,
                     TXT_PRIV_CONFIG_REGS_BASE + TXT_CONFIG_SPACE_SIZE);
    BUG_ON(!ok);
}

void __init txt_restore_mtrrs(bool verbose)
{
    const struct slr_entry_hdr *entry;
    const struct slr_entry_intel_info *intel_info;
    uint64_t mtrr_cap, mtrr_def, base, mask;
    unsigned int i;
    unsigned int vcnt;
    uint64_t def_type;
    struct mtrr_pausing_state pausing_state;

    mtrr_cap = rdmsr(MSR_MTRRcap);
    mtrr_def = rdmsr(MSR_MTRRdefType);

    vcnt = mtrr_cap & 0xFF;

    if ( verbose )
    {
        printk("MTRRs set previously for SINIT ACM:\n");
        printk(" MTRR cap: %"PRIx64" type: %"PRIx64"\n", mtrr_cap, mtrr_def);

        for ( i = 0; i < vcnt; i++ )
        {
            base = rdmsr(MSR_IA32_MTRR_PHYSBASE(i));
            mask = rdmsr(MSR_IA32_MTRR_PHYSMASK(i));

            printk(" MTRR[%d]: base %"PRIx64" mask %"PRIx64"\n",
                   i, base, mask);
        }
    }

    entry =
        slr_next_entry_by_tag(slaunch_get_slrt(), NULL, SLR_ENTRY_INTEL_INFO);
    intel_info = container_of(entry, const struct slr_entry_intel_info, hdr);

    if ( vcnt != intel_info->saved_bsp_mtrrs.mtrr_vcnt )
    {
        printk("Bootloader saved %ld MTRR values, but there should be %d\n",
               intel_info->saved_bsp_mtrrs.mtrr_vcnt, vcnt);
        /* Choose the smaller one to be on the safe side. */
        if ( intel_info->saved_bsp_mtrrs.mtrr_vcnt < vcnt )
            vcnt = intel_info->saved_bsp_mtrrs.mtrr_vcnt;
    }

    def_type = intel_info->saved_bsp_mtrrs.default_mem_type;
    mtrr_pause_caching(&pausing_state);

    for ( i = 0; i < vcnt; i++ )
    {
        base = intel_info->saved_bsp_mtrrs.mtrr_pair[i].mtrr_physbase;
        mask = intel_info->saved_bsp_mtrrs.mtrr_pair[i].mtrr_physmask;
        wrmsr(MSR_IA32_MTRR_PHYSBASE(i), base);
        wrmsr(MSR_IA32_MTRR_PHYSMASK(i), mask);
    }

    pausing_state.def_type = def_type;
    mtrr_resume_caching(pausing_state);

    if ( verbose )
    {
        printk("Restored MTRRs:\n");

        /*
         * If MTRRs are not enabled or WB is not the default, MTRRs won't be
         * printed.
         */
        if ( !test_bit(11, &def_type) || (def_type & 0x7) == X86_MT_WB )
        {
            for ( i = 0; i < vcnt; i++ )
            {
                base = rdmsr(MSR_IA32_MTRR_PHYSBASE(i));
                mask = rdmsr(MSR_IA32_MTRR_PHYSMASK(i));
                printk(" MTRR[%d]: base %"PRIx64" mask %"PRIx64"\n",
                       i, base, mask);
            }
        }
    }

    /* Restore IA32_MISC_ENABLES */
    wrmsr(MSR_IA32_MISC_ENABLE, intel_info->saved_misc_enable_msr);
}

static const struct acpi_tpr_instance * __hwdom_init
dtpr_first_instance(const struct acpi_table_dtpr *dtpr)
{
    return (const struct acpi_tpr_instance *)(dtpr + 1);
}

static const struct acpi_tpr_array * __hwdom_init
tpr_pair_addrs(const struct acpi_tpr_instance *ins)
{
    return (const struct acpi_tpr_array *)(ins + 1);
}

static const struct acpi_tpr_instance * __hwdom_init
tpr_next_instance(const struct acpi_tpr_instance *ins)
{
    return (const struct acpi_tpr_instance *)
            (tpr_pair_addrs(ins) + ins->tpr_cnt);
}

static const struct acpi_tpr_array * __hwdom_init
tpr_srl_addrs(const struct acpi_tpr_aux_sr *aux)
{
    return (const struct acpi_tpr_array *)(aux + 1);
}

static const struct acpi_tpr_aux_sr * __hwdom_init
dtpr_validate_and_find_aux_sr(const struct acpi_table_dtpr *dtpr, size_t size)
{
    const void *ptr = dtpr_first_instance(dtpr);
    const struct acpi_tpr_aux_sr *aux;
    size_t remaining;
    uint32_t i;

    BUG_ON(size < sizeof(*dtpr));
    remaining = size - sizeof(*dtpr);

    for ( i = 0; i < dtpr->ins_cnt; i++ )
    {
        const struct acpi_tpr_instance *ins = ptr;
        BUG_ON(remaining < sizeof(*ins));
        BUG_ON(ins->tpr_cnt == 0);
        BUG_ON(remaining - sizeof(*ins) < ins->tpr_cnt * sizeof(struct acpi_tpr_array));
        remaining -= sizeof(*ins) + ins->tpr_cnt * sizeof(struct acpi_tpr_array);
        ptr = tpr_next_instance(ins);
    }

    aux = ptr;
    BUG_ON(remaining < sizeof(*aux));
    BUG_ON(remaining - sizeof(*aux) < aux->srl_cnt * sizeof(struct acpi_tpr_array));
    return aux;
}

static void __iomem *__hwdom_init tpr_map(uint64_t addr, size_t size)
{
    void __iomem *reg = ioremap(addr, size);

    if ( reg == NULL )
        panic("SLAUNCH: cannot map TPR register at %#"PRIx64"\n", addr);

    return reg;
}

static void __hwdom_init tpr_serialize_dma(const struct acpi_tpr_array *regs,
                                           uint32_t cnt)
{
    void __iomem **maps = xmalloc_array(void __iomem *, cnt);
    uint32_t i;

    BUG_ON(maps == NULL);

    for ( i = 0; i < cnt; i++ )
        maps[i] = tpr_map(regs[i].base, sizeof(uint64_t));

    for ( i = 0; i < cnt; i++ )
        writeq(readq(maps[i]) | TXT_TPR_SERIALIZE_CTRL, maps[i]);

    for ( i = 0; i < cnt; i++ )
    {
        s_time_t deadline = NOW() + TXT_TPR_SERIALIZE_TIMEOUT;
        while ( readq(maps[i]) & TXT_TPR_SERIALIZE_STS )
        {
            if ( NOW() > deadline )
                panic("SLAUNCH: timed out serializing DMA at %#"PRIx64"\n",
                      regs[i].base);
            cpu_relax();
        }
    }

    for ( i = 0; i < cnt; i++ )
        iounmap(maps[i]);

    xfree(maps);
}

static void __hwdom_init tpr_disable_range(uint64_t pair_addr)
{
    void __iomem *pair = tpr_map(pair_addr, 2 * sizeof(uint64_t));
    writeq(0, pair + sizeof(uint64_t));
    writeq(TXT_TPR_BASE_DISABLE, pair);
    iounmap(pair);
}

void __hwdom_init txt_disable_dma_protection(void)
{
    struct txt_os_sinit_data *os_sinit;
    const struct txt_ext_data_element *dtpr_elem;
    const struct acpi_table_dtpr *dtpr;
    const struct acpi_tpr_instance *ins;
    const struct acpi_tpr_aux_sr *aux = NULL;
    uint32_t i, j;
    void *heap;

    if ( !slaunch_active || boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
        return;

    heap = __va(txt_read(TXTCR_HEAP_BASE));
    os_sinit = txt_start(heap, TXT_OS2SINIT);
    if ( !(os_sinit->capabilities & (1u << TXT_SINIT_MLE_CAP_TPR_SUPPORT)) )
        return;

    dtpr_elem = txt_find_sinit_mle_ext_data_element(
        txt_start(heap, TXT_SINIT2MLE), TXT_HEAP_EXTDATA_TYPE_DTPR);
    BUG_ON(dtpr_elem == NULL);
    BUG_ON(dtpr_elem->size < sizeof(*dtpr_elem));

    dtpr = (const struct acpi_table_dtpr *)dtpr_elem->data;
    aux = dtpr_validate_and_find_aux_sr(dtpr, dtpr_elem->size - sizeof(*dtpr_elem));

    tpr_serialize_dma(tpr_srl_addrs(aux), aux->srl_cnt);

    /* Disable every TPR of every hardware instance. */
    for ( ins = dtpr_first_instance(dtpr), i = 0; i < dtpr->ins_cnt;
          ins = tpr_next_instance(ins), i++ )
        for ( j = 0; j < ins->tpr_cnt; j++ )
            tpr_disable_range(tpr_pair_addrs(ins)[j].base);

    printk(XENLOG_INFO
           "SLAUNCH: disabled TPR DMA protection (%u instance(s), %u serialization register(s))\n",
           dtpr->ins_cnt, aux->srl_cnt);
}
