/*
 * results.h
 *
 *  Created on: Feb 28, 2023
 *      Author: nt168
 */
#include "common.h"
#include "messtype.h"
#define mtcnmlen 64
#define evtnmlen 64
#define evtvllen 32
#define mjslnlen 256

#ifndef RESULTS_H_
#define RESULTS_H_
struct phy_pmu_event
{
	size_t len;
	char event_name[64];
	char event_value[32];
	char metric_name[64];
	struct phy_pmu_event * next;
};

struct phy_pmu_metrics
{
	char metric_name[64];
	struct phy_pmu_event* curr_orig;
	struct phy_pmu_event* curr_stat;
	struct phy_pmu_event* orig_data;
	struct phy_pmu_event* stat_data;
	struct phy_pmu_metrics * next;
};

struct phy_pmu_analysis
{
	char anal_name[64];
	struct phy_pmu_metrics* current;
	struct phy_pmu_metrics* metrics;
};

struct phy_ddr{
	char node_id;
	char hm_id;
	char pmu_id;
	unsigned short DDW;
};

struct phy_pxu{
	char node_id;
	char pxu_id;
	char ctrler_id;
	unsigned short XDW;
};

struct phy_peu{
	char node_id;
	char pmu_id;
	char ctrler_id;
	unsigned short EDW;
};

typedef void* phy_dxe_st;

struct phy_dxe_analysis
{
	char anal_name[64];
	struct phy_dxe_st* dxe;
};

#define phy_ddr_json "{\n\
	\"title\": \"testing items\",\n\
	\"DDR Node(${node_id})HM(${hm_id})CHANNEL(${pmu_id}); DDR_Freq:${ddr_freq_in_GHz}GHz; DDR_DATA_WIDTH:${DDR_DATA_WIDTH}; DDR Effectiveness\": { \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/cycles/\": \"0\",                     \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/rxreq/\": \"0\",                      \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/rxreq_RNS/\": \"0\",                  \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/rxreq_WNSP/\": \"0\",				   \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/rxreq_WNSF/\": \"0\",                 \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/rxdat/\": \"0\",                      \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/txdat/\": \"0\",                      \n\
		\"phyt${node_id}_hm${hm_id}_pmu${pmu_id}/bandwidth/\": \"0\",                  \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_DDR_WR_FLOW_RT\": \"0 GBps\",           \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_DDR_RD_FLOW_RT\": \"0 GBps\",           \n\
		\"[N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_RT]\": \"0 GTps\",         \n\
		\"[N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_RNS_RT]\": \"0 GTps\",     \n\
		\"[N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_WNSP_RT]\": \"0 GTps\",    \n\
		\"[N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_WNSF_RT]\": \"0 GTps\",    \n\
		\"[N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxdat_RT]\": \"0 GTps\",         \n\
		\"[N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_txdat_RT]\": \"0 GTps\"          \n\
	}\n\
}"

#define phy_ddr_chart_json "{\n\
	\"数据流量 histogram\": {\n\
		\"DDR_Freq\": \"${ddr_freq_in_GHz} GHz\", \n\
		\"DDR_DATA_WIDTH\": \"${DDR_DATA_WIDTH}\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_DDR_WR_FLOW_RT\": \"0 GBps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_DDR_RD_FLOW_RT\": \"0 GBps\"  \n\
	}, \n\
	\"事务流量 histogram\": { \n\
		\"DDR_Freq\": \"${ddr_freq_in_GHz} GHz\", \n\
		\"DDR_DATA_WIDTH\": \"${DDR_DATA_WIDTH}\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_RNS_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_WNSP_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_WNSF_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxdat_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_txdat_RT\": \"0 GTps\" \n\
	}\n\
}"
#if 0
#define phy_ddr_chart_json "{\n\
	\"数据流量  histogram\": {\n\
		\"DDR_Freq ${ddr_freq_in_GHz}GHz; DDR_DATA_WIDTH ${DDR_DATA_WIDTH}\": { \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_DDR_WR_FLOW_RT\": \"0 GBps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_DDR_RD_FLOW_RT\": \"0 GBps\"  \n\
		}\n\
	}, \n\
	\"事务流量  histogram\": { \n\
		\"DDR_Freq ${ddr_freq_in_GHz}GHz; DDR_DATA_WIDTH ${DDR_DATA_WIDTH}\": { \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_RNS_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_WNSP_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxreq_WNSF_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_rxdat_RT\": \"0 GTps\", \n\
		\"N(${node_id})H(${hm_id})C(${pmu_id})_TRANS_txdat_RT\": \"0 GTps\" \n\
		}\n\
	}\n\
}"
#endif
#define phy_c2c_json "{\n\
	\"title\": \"testing items\", \n\
	\"Node(${node_id})C2C(${c2c_id})Ctrler(${ctrler_id}); C2C_Freq: ${c2c_freq_in_GHz} GHz; C2C_DATA_WIDTH: ${C2C_DATA_WIDTH}; C2C Effectiveness\": { \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/cycles,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/ar,ctrler=${ctrler_id}/\": \"0\",           \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/r_last,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/r_err,ctrler=${ctrler_id}/\": \"0\",        \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/r_full,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/aw,ctrler=${ctrler_id}/\": \"0\",           \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/w_last,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/w_err,ctrler=${ctrler_id}/\": \"0\",        \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/b,ctrler=${ctrler_id}/\": \"0\",            \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/w_data,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/delay_rd,ctrler=${ctrler_id}/\": \"0\",     \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/rd_max,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/rd_min,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/rdelay_time,ctrler=${ctrler_id}/\": \"0\",  \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/delay_wr,ctrler=${ctrler_id}/\": \"0\",     \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/wr_max,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/wr_min,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_c2c${c2c_id}_pmu/wdelay_time,ctrler=${ctrler_id}/\": \"0\",  \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_WR_FLOW_RT\": \"0 GBps\",          \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_RD_FLOW_RT\": \"0 GBps\",          \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_WR_DELAY\": \"0\",                 \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_RD_DELAY\": \"0\",                 \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_ar_RT]\": \"0 GTps\",         \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_r_last_RT]\": \"0 GTps\",     \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_r_err_RT]\": \"0 GTps\",      \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_r_full_RT]\": \"0 GTps\",     \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_aw_RT]\": \"0 GTps\",         \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_w_last_RT]\": \"0 GTps\",     \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_w_err_RT]\": \"0 GTps\",      \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_b_RT]\": \"0 GTps\",          \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_delay_rd_RT]\": \"0 GTps\",   \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_delay_wr_RT]\": \"0 GTps\"    \n\
	}\n\
}"

#define phy_c2c_chart_json "{ \n\
	\"数据流量 histogram\": { \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_WR_FLOW_RT\": \"0 GBps\", \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_RD_FLOW_RT\": \"0 GBps\" \n\
	},\n\
	\"事务流量 histogram\": { \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_ar_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_r_last_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_r_err_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_r_full_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_aw_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_w_last_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_w_err_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_b_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_delay_rd_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})X(${c2c_id})C(${ctrler_id})_TRANS_delay_wr_RT]\": \"0 GTps\" \n\
	},\n\
	\"读写延迟 histogram\": { \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_WR_DELAY\": \"0\", \n\
		\"N(${node_id})X(${c2c_id})C(${ctrler_id})_RD_DELAY\": \"0\" \n\
	}\n\
}"

#define phy_pcie_json "{\n\
	\"title\": \"testing items\", \n\
	\"Node(${node_id})PCIE(${pmu_id})Ctrler(${ctrler_id}); PCIe_Freq: ${pcie_freq_in_GHz} GHz; PCIe_DATA_WIDTH: ${PCIe_DATA_WIDTH}; PCIe Effectiveness\": { \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/cycles,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/ar,ctrler=${ctrler_id}/\": \"0\",           \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/r_last,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/r_err,ctrler=${ctrler_id}/\": \"0\",        \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/r_full,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/aw,ctrler=${ctrler_id}/\": \"0\",           \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/w_last,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/w_err,ctrler=${ctrler_id}/\": \"0\",        \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/b,ctrler=${ctrler_id}/\": \"0\",            \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/w_data,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/delay_rd,ctrler=${ctrler_id}/\": \"0\",     \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/rd_max,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/rd_min,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/rdelay_time,ctrler=${ctrler_id}/\": \"0\",  \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/delay_wr,ctrler=${ctrler_id}/\": \"0\",     \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/wr_max,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/wr_min,ctrler=${ctrler_id}/\": \"0\",       \n\
		\"phyt${node_id}_pcie_pmu${pmu_id}/wdelay_time,ctrler=${ctrler_id}/\": \"0\",  \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_WR_FLOW_RT\": \"0 GBps\",           \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_RD_FLOW_RT\": \"0 GBps\",           \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_WR_DELAY\": \"0\",                  \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_RD_DELAY\": \"0\",                  \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_ar_RT]\": \"0 GTps\",        \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_r_last_RT]\": \"0 GTps\",    \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_r_err_RT]\": \"0 GTps\",     \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_r_full_RT]\": \"0 GTps\",    \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_aw_RT]\": \"0 GTps\",        \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_w_last_RT]\": \"0 GTps\",    \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_w_err_RT]\": \"0 GTps\",     \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_b_RT]\": \"0 GTps\",         \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_delay_rd_RT]\": \"0 GTps\",  \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_delay_wr_RT]\": \"0 GTps\"   \n\
	}\n\
}"

#define phy_pcie_chart_json "{\n\
	\"数据流量 histogram\": {\n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_WR_FLOW_RT\": \"0 GBps\", \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_RD_FLOW_RT\": \"0 GBps\" \n\
	}, \n\
	\"事务流量 histogram\": { \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_ar_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_r_last_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_r_err_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_r_full_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_aw_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_w_last_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_w_err_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_b_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_delay_rd_RT]\": \"0 GTps\", \n\
		\"[N(${node_id})E(${pmu_id})C(${ctrler_id})_TRANS_delay_wr_RT]\": \"0 GTps\" \n\
	}, \n\
	\"读写延迟 histogram\": { \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_WR_DELAY\": \"0\", \n\
		\"N(${node_id})E(${pmu_id})C(${ctrler_id})_RD_DELAY\": \"0\" \n\
	}\n\
}"

bool pmu_ddr_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile);
void pmu_orig_struct(const char* origfile, struct phy_pmu_analysis **ppm);
void iterator_pmu_orig_struct(struct phy_pmu_analysis *ppa);
void destroy_pmu_orig_struct(struct phy_pmu_analysis *ppa);
void pmu_orig_struct_to_jason(const char* jsonfile, struct phy_pmu_analysis *ppa);
void pmu_orig_struct_to_json(const char* origfile, const char* jsonfile);
bool pmu_orig_struct_to_json_p(const char* origfile, const char* jsonfile, char** chartjsonfile);
bool pmu_dcp_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile);
bool pmu_pcie_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile);
bool pmu_c2c_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile);
bool topdown_orig_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile);
bool fs_orig_to_json(const char* origfile, const char* source_jsonfile, const char* callsite_jsonfile, const char* obj_jsonfile, const char* cacheline_jsonfile);
bool numa_orig_to_json(const char* origfile, const char* source_jsonfile, const char* callsite_jsonfile, const char* obj_jsonfile, const char* cacheline_jsonfile);
bool memaccess_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile);
void search_and_extlin(const char *filename, const char **ptarr, char **res);
#endif /* RESULTS_H_ */
