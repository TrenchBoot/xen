#ifndef _MCHECK_AMD_H
#define _MCHECK_AMD_H

bool cf_check mc_amd_recoverable_scan(uint64_t status);
bool cf_check mc_amd_addrcheck(uint64_t status, uint64_t misc, int addrtype);

#endif
