/*
 * Client for the AMD PSP DRTM mailbox.
 *
 * On a PSP-assisted SKINIT launch the bootloader sets up a Trusted Memory
 * Region covering the memory it launches into, and SKL leaves it in place. The
 * TMR is the AMD analogue of the Intel PMRs, so it stays until Xen has its own
 * DMA protection: the release is issued from iov_detect(), after the IOMMUs are
 * enabled and before setup_IO_APIC() runs check_timer().
 *
 * On the way out the DRTM TPM localities are locked, so that a kernel started
 * by kexec, or firmware after a reboot, cannot reach locality 2.
 */

#include <xen/cache.h>
#include <xen/delay.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/types.h>
#include <xen/vmap.h>
#include <asm/amd_psp.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/slaunch.h>

/*
 * The PSP BAR is not described in PCI configuration space. It is read out of
 * the System Management Network, whose address and data registers are 0xB8 and
 * 0xBC of device 0:0.0.
 */
#define SMN_ADDRESS_REG                 0xB8
#define SMN_DATA_REG                    0xBC

#define IOHC0NBCFG_SMNBASE              0x13B00000
#define PSP_BASE_ADDR_LO_SMN_ADDRESS    (IOHC0NBCFG_SMNBASE + 0x102E0)

#define PSP_BASE_ADDR_LO_MASK           0xFFF00000

/* Offset of C2PMSG_72 from the PSP BAR. */
#define PSP_C2PMSG_72                   0x10a20

/*
 * 100 ms per attempt. SKL allows five seconds for a command to land and is the
 * implementation that has been exercised against this mailbox, so use its
 * budget rather than the shorter one Linux applies.
 */
#define PSP_READY_RETRIES               50
#define PSP_READY_DELAY_MS              100

static bool __read_mostly psp_active;
static bool __read_mostly tmr_released;
static void __iomem *c2pmsg_72;

/*
 * The AMD Secure Processor devices that carry a DRTM mailbox, and the register
 * layout each one uses. This is the list the bootloader and SKL match against,
 * see grub-core/loader/slaunch/psp.c and SKL's psp.c. Xen has to repeat the
 * probe rather than read the answer out of the SLRT, because the bootloader
 * fills slr_entry_amd_info.psp_version while staging the table, which is before
 * its own discovery has run, so the field is always zero.
 */
typedef enum {
    PSP_NONE = 0,
    PSP_V1,
    PSP_V2,
    PSP_V3,
    ASP,
} psp_version_t;

static const struct {
    uint16_t vendor_id;
    uint16_t dev_id;
    psp_version_t version;
} psp_devs_list[] __initconst = {
    { 0x1022, 0x1537, PSP_NONE },
    { 0x1022, 0x1456, PSP_V1 },
    { 0x1022, 0x1468, PSP_NONE },
    { 0x1022, 0x1486, PSP_V2 },
    { 0x1022, 0x15DF, PSP_V3 },
    { 0x1022, 0x1649, PSP_V2 },
    { 0x1022, 0x14CA, PSP_V3 },
    { 0x1022, 0x15C7, PSP_V3 },
    { 0x1022, 0x156E, ASP },
};

static const char *const psp_status_strings[] = {
    "DRTM_NO_ERROR",
    "DRTM_NOT_SUPPORTED",
    "DRTM_LAUNCH_ERROR",
    "DRTM_TMR_SETUP_FAILED_ERROR",
    "DRTM_TMR_DESTROY_FAILED_ERROR",
    "UNDEFINED",
    "UNDEFINED",
    "DRTM_GET_TCG_LOGS_FAILED_ERROR",
    "DRTM_OUT_OF_RESOURCES_ERROR",
    "DRTM_GENERIC_ERROR",
    "DRTM_INVALID_SERVICE_ID_ERROR",
    "DRTM_MEMORY_UNALIGNED_ERROR",
    "DRTM_MINIMUM_SIZE_ERROR",
    "DRTM_GET_TMR_DESCRIPTOR_FAILED",
    "DRTM_EXTEND_OSSL_DIGEST_FAILED",
    "DRTM_SETUP_NOT_ALLOWED",
    "DRTM_GET_IVRS_TABLE_FAILED",
};

static const char *psp_status_string(uint32_t status)
{
    if ( status >= ARRAY_SIZE(psp_status_strings) )
        return "UNDEFINED";

    return psp_status_strings[status];
}

/*
 * The SMN address and data registers are a pair, and Xen's config accessors
 * take and drop the config lock once per access. This only runs on the boot
 * CPU before the APs are up, so nothing can interleave with it.
 */
static uint32_t __init smn_read(uint32_t address)
{
    pci_conf_write32(PCI_SBDF(0, 0, 0, 0), SMN_ADDRESS_REG, address);

    return pci_conf_read32(PCI_SBDF(0, 0, 0, 0), SMN_DATA_REG);
}

/*
 * Walk configuration space for an AMD Secure Processor with a DRTM mailbox and
 * report which register layout it uses. A device on the list tagged PSP_NONE
 * has no mailbox, so the walk continues past it.
 */
static psp_version_t __init find_psp_device(void)
{
    unsigned int bus, dev, fn, i;

    for ( bus = 0; bus < 256; bus++ )
        for ( dev = 0; dev < 32; dev++ )
            for ( fn = 0; fn < 8; fn++ )
            {
                pci_sbdf_t sbdf = PCI_SBDF(0, bus, dev, fn);
                uint32_t id = pci_conf_read32(sbdf, PCI_VENDOR_ID);

                if ( (uint16_t)id == 0xFFFF )
                {
                    /* An absent function 0 means the whole device is absent. */
                    if ( fn == 0 )
                        break;
                    continue;
                }

                for ( i = 0; i < ARRAY_SIZE(psp_devs_list); i++ )
                    if ( psp_devs_list[i].vendor_id == (uint16_t)id &&
                         psp_devs_list[i].dev_id == (uint16_t)(id >> 16) &&
                         psp_devs_list[i].version != PSP_NONE )
                        return psp_devs_list[i].version;
            }

    return PSP_NONE;
}

/*
 * The mailbox is usable when the ready bit is set in a register that is
 * answering. An all-ones read carries the ready bit too, so test for it first.
 */
static bool psp_mbox_ready(uint32_t reg_val)
{
    return reg_val != 0xFFFFFFFF && (reg_val & DRTM_MBOX_READY_MASK);
}

/*
 * Poll for bit 31 of C2PMSG_72 and return the register. The ready bit clear on
 * return means the PSP is still working on the last command.
 */
static uint32_t psp_wait_for_ready(void)
{
    uint32_t reg_val = readl(c2pmsg_72);
    unsigned int retry;

    if ( reg_val == 0xFFFFFFFF )
        return reg_val;

    for ( retry = 0; retry < PSP_READY_RETRIES; retry++ )
    {
        reg_val = readl(c2pmsg_72);

        if ( reg_val & DRTM_MBOX_READY_MASK )
            break;

        mdelay(PSP_READY_DELAY_MS);
    }

    return reg_val;
}

/* Issue one command and report whether the PSP completed it without error. */
static bool psp_command(uint32_t cmd_word, const char *name)
{
    uint32_t reg_val, status;

    writel(cmd_word, c2pmsg_72);

    reg_val = psp_wait_for_ready();
    if ( !psp_mbox_ready(reg_val) )
    {
        printk(XENLOG_ERR "SLAUNCH: PSP did not complete %s, C2PMSG_72 %#x\n",
               name, reg_val);
        return false;
    }

    status = reg_val & DRTM_MBOX_STATUS_MASK;

    if ( status != DRTM_NO_ERROR )
    {
        printk(XENLOG_ERR "SLAUNCH: %s failed - %s\n", name,
               psp_status_string(status));
        return false;
    }

    return true;
}

bool slaunch_psp_active(void)
{
    return psp_active;
}

void __init slaunch_psp_setup(void)
{
    static bool __initdata probe_done;
    psp_version_t version;
    uint32_t bar, reg_val;

    if ( probe_done )
        return;
    probe_done = true;

    if ( boot_cpu_data.x86_vendor != X86_VENDOR_AMD )
        return;

    /*
     * No mailbox means the launch used the DEV rather than a TMR, and there is
     * nothing for Xen to release.
     */
    version = find_psp_device();
    if ( version == PSP_NONE )
        return;

    /*
     * From here on a TMR is assumed to be live, because the bootloader sets one
     * up whenever its own probe finds this device. Every path below therefore
     * leaves psp_active set, so that a failure to reach the mailbox fails the
     * boot instead of passing silently.
     */
    psp_active = true;
    printk("SLAUNCH: PSP-assisted launch, PSP version %u\n",
           (unsigned int)version);

    /*
     * A zero BAR is the one case the bootloader also gives up on, and it then
     * launches without a TMR, so clear the flag and let the boot continue.
     * Everything below this point the bootloader proved working before it set
     * the TMR up, so a failure there is Xen's and stays fatal.
     */
    bar = smn_read(PSP_BASE_ADDR_LO_SMN_ADDRESS) & PSP_BASE_ADDR_LO_MASK;
    if ( bar == 0 )
    {
        printk("SLAUNCH: no PSP BAR reported by the SMN, assuming no TMR\n");
        psp_active = false;
        return;
    }

    /*
     * Only C2PMSG_72 is mapped. The argument registers C2PMSG_93 through
     * C2PMSG_95 belong to the commands the bootloader and SKL issue, and
     * neither of Xen's two commands takes an argument.
     */
    c2pmsg_72 = ioremap(bar + PSP_C2PMSG_72, sizeof(uint32_t));
    if ( c2pmsg_72 == NULL )
    {
        printk(XENLOG_ERR "SLAUNCH: failed to map the PSP DRTM mailbox\n");
        return;
    }

    reg_val = psp_wait_for_ready();
    if ( !psp_mbox_ready(reg_val) )
    {
        printk(XENLOG_ERR
               "SLAUNCH: PSP is not ready to take commands, C2PMSG_72 %#x\n",
               reg_val);
        iounmap(c2pmsg_72);
        c2pmsg_72 = NULL;
    }
}

bool slaunch_psp_tmr_release(void)
{
    if ( tmr_released )
        return true;

    if ( c2pmsg_72 == NULL )
        return false;

    if ( !psp_command((DRTM_CMD_TMR_RELEASE << DRTM_MBOX_CMD_SHIFT) |
                      (DRTM_TMR_INDEX_0 << DRTM_MBOX_TMR_INDEX_SHIFT),
                      "DRTM_CMD_TMR_RELEASE") )
        return false;

    tmr_released = true;
    printk("SLAUNCH: released TMR 0, DMA protection is now the IOMMU's\n");

    return true;
}

void slaunch_psp_finalize(void)
{
    if ( !psp_active || c2pmsg_72 == NULL )
        return;

    if ( !psp_command(DRTM_CMD_TPM_LOCALITY_ACCESS << DRTM_MBOX_CMD_SHIFT,
                      "DRTM_CMD_TPM_LOCALITY_ACCESS") )
        printk(XENLOG_ERR "SLAUNCH: DRTM TPM localities are still open\n");

    iounmap(c2pmsg_72);
    c2pmsg_72 = NULL;
}
