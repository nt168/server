#ifndef PHY_DEF_H
#define PHY_DEF_H
#define m_phydir "/opt/phytune/server"
#define m_rstdir "/opt/phytune/server/results"
#define m_phydb  "/opt/phytune/server/conf/phytune.db"
#define m_pmucnf "/opt/phytune/agent/arm/pmucnf"

//tools
#define m_thwdir "/opt/phytune/agent/arm/tools/hardware"
#define m_sysdir "/opt/phytune/agent/arm/tools/system"
#define m_torpth "/opt/phytune/agent/arm/tools/system/toroot.sh"
#define m_perpth "/opt/phytune/agent/arm/tools/system/perfep.sh"
#define m_deppth "/opt/phytune/agent/arm/tools/system/deps.sh"
#define m_dridir "/opt/phytune/agent/arm/tools/driver"
#define m_pcipth "/opt/phytune/agent/arm/tools/driver/pcie.sh"
#define m_ddrpth "/opt/phytune/agent/arm/tools/driver/ddr.sh"

#define m_tmpdir "/tmp"
#define m_empdir "/opt/phytune/agent/arm/modules/Performance/dutpro"
#define m_hwcpth "/opt/phytune/agent/arm/pmucnf/$CPU/$TYP/hw.cnf"
#define m_pmupth "/opt/phytune/agent/arm/pmucnf/$CPU/$TYP/pmu.sh"
#define m_2jspth "/opt/phytune/agent/arm/pmucnf/$CPU/$TYP/res2json.py"
#define m_resdir "/opt/phytune/server/results"
#define m_unvalb "unavailable"
#define m_pciten "设备名称"
#define m_ddrten "Locator"
//#define m_ddrten "Handle"
#define m_pcinam "pcie"
#define m_ddrnam "ddr"
#define m_ddrust "Unknow"
#define m_dimm	 "DIMM"

#define m_nspdes "phy-server"
#define m_nspl 11
#define kilflg "/tmp/kilflg"
#define kilmasflg "/tmp/kilmasflg"

#define m_seglin "<<<This is a beautiful segmentation line1>>>"

#if 0
#define PMU_ITEMS \
    PMUIT(CPU,           0)  \
    PMUIT(DDR,           1)  \
    PMUIT(PCIE,          2)  \

#define PMUIT(name, val) name = (val),
typedef enum pmudet { PMU_ITEMS } pmudet;
#undef PMUIT

#define PMUIT(name, val) [val] = #name,
static const char* const _pmu_str_tbl[] = { PMU_ITEMS };
#undef PMUIT

#define PMU2STR(v) \
    (((unsigned)(v) < sizeof(_pmu_str_tbl)/sizeof(*_pmu_str_tbl) && _pmu_str_tbl[v]) \
        ? _pmu_str_tbl[v] : "UNKNOWN")
#endif

#define CPU_ITEMS \
    CPUITM(D2000,           0)  \
    CPUITM(S2500,           1)  \
	CPUITM(S5000C,          2)  \
	CPUITM(S5000C_E,        3)  \
	CPUITM(D3000M,          4)  \

#define CPUITM(name, val) name = (val),
typedef enum cpudet { CPU_ITEMS } cpudet;
#undef CPUITM

#define CPUITM(name, val) [val] = #name,
static const char* const _cpu_str_tbl[] = { CPU_ITEMS };
#undef CPUITM

#define CPU2STR(v) \
    (((unsigned)(v) < sizeof(_cpu_str_tbl)/sizeof(*_cpu_str_tbl) && _cpu_str_tbl[v]) \
        ? _cpu_str_tbl[v] : "UNKNOWN")

#endif


