#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "execdesc.h"
#include "libpq/crypt.h"
#include "libpq/libpq-be.h"
#include "objectaccess.h"
#include "explain.h"
#include "pathnodes.h"
#include "selfuncs.h"
#include "queryjumble.h"
#include "tcop/utility.h"
#include "ipc.h"
#include "miscadmin.h"
#include "user.h"
#include "auth.h"
#include "executor.h"
#include "objectaccess.h"
#include "rowsecurity.h"
#include "explain.h"
#include "lsyscache.h"
#include "optimizer/paths.h"
#include "plancat.h"
#include "selfuncs.h"
#include "planner.h"
#include "analyze.h"


PG_MODULE_MAGIC;

/* List of hooks.
THIS EXTENSION IS NOT COMPATIBLE WITH OTHER EXTENSIONS YET 
//func_setup
//func_beg
//func_end
//stmt_beg
//stmt_end*/

static void order_hook_emit_log_hook(ErrorData *edata) {
    (void)edata;
    elog(LOG, "emit_log_hook called");
}
static void order_hook_shmem_startup_hook() {
    elog(LOG, "shmem_startup_hook called");
}
static void order_hook_shmem_request_hook() {
    elog(LOG, "shmem_request_hook called");
}
static void order_hook_check_password_hook(const char *username, 
                                           const char *shadow_pass, 
                                           PasswordType password_type, 
                                           Datum validuntil_time, 
                                           bool validuntil_null) {
    (void)username; (void)shadow_pass; (void)password_type, (void)validuntil_time; (void)validuntil_null;
    elog(LOG, "check_password_hook called");
}

static void order_hook_ClientAuthentication_hook(Port *port, int status) {
    (void)port; (void)status;
    elog(LOG, "ClientAuthentication_hook called");
}
static bool order_hook_ExecutorCheckPerms_hook(List *rangeTable,
											  List *rtePermInfos,
											  bool ereport_on_violation) {
    (void)rangeTable; (void)rtePermInfos; (void)ereport_on_violation;
    elog(LOG, "ExecutorCheckPerms_hook called");
    return true;
}
static void order_hook_object_access_hook(ObjectAccessType access,
										 Oid classId,
										 Oid objectId,
										 int subId,
										 void *arg) {
    (void)access; (void)classId; (void)objectId; (void)subId; (void)arg;
    elog(LOG, "object_access_hook called");
}

static List* order_hook_row_security_policy_hook_permissive(CmdType cmdtype,
												Relation relation) {
    (void)cmdtype; (void)relation;
    elog(LOG, "row_security_policy_hook_permissive called");
    return NULL;
}
static List* order_hook_row_security_policy_hook_restrictive(CmdType cmdtype,
												Relation relation) {
    (void)cmdtype; (void)relation;
    elog(LOG, "row_security_policy_hook_restrictive called");
    return NULL;
}

static bool order_hook_needs_fmgr_hook(Oid fn_oid) {
    (void)fn_oid;
    elog(LOG, "needs_fmgr_hook called");
    return false;
}

static void order_hook_fmgr_hook(FmgrHookEventType event,
								FmgrInfo *flinfo, Datum *arg) {
    (void)event; (void)flinfo; (void)arg;
    elog(LOG, "fmgr_hook called");
}

static const char* order_hook_explain_get_index_name_hook(Oid indexId) {
    (void)indexId;
    elog(LOG, "explain_get_index_name_hook called");
    return NULL;
}

static void order_hook_ExplainOneQuery_hook(Query *query,
										   int cursorOptions,
										   IntoClause *into,
										   ExplainState *es,
										   const char *queryString,
										   ParamListInfo params,
										   QueryEnvironment *queryEnv) {
    // Important: override execution!!
    elog(LOG, "ExplainOneQuery_hook called");
    // copy pasted default code here.
    PlannedStmt *plan;
    instr_time	planstart,
                planduration;
    BufferUsage bufusage_start,
                bufusage;

    if (es->buffers)
        bufusage_start = pgBufferUsage;
    INSTR_TIME_SET_CURRENT(planstart);

    /* plan the query */
    plan = pg_plan_query(query, queryString, cursorOptions, params);

    INSTR_TIME_SET_CURRENT(planduration);
    INSTR_TIME_SUBTRACT(planduration, planstart);

    /* calc differences of buffer counters. */
    if (es->buffers)
    {
        memset(&bufusage, 0, sizeof(BufferUsage));
        BufferUsageAccumDiff(&bufusage, &pgBufferUsage, &bufusage_start);
    }

    /* run it (if needed) and produce output */
    ExplainOnePlan(plan, into, es, queryString, params, queryEnv,
                    &planduration, (es->buffers ? &bufusage : NULL));
}

static int32 order_hook_get_attavgwidth_hook(Oid relid, AttrNumber attnum) {
    (void)relid; (void)attnum;
    elog(LOG, "get_attavgwidth_hook called");
    return 0;
}

static bool order_hook_get_index_stats_hook(PlannerInfo *root,
										   Oid indexOid,
										   AttrNumber indexattnum,
										   VariableStatData *vardata) {
    (void)root; (void)indexOid; (void)indexattnum; (void)vardata;
    elog(LOG, "get_index_stats_hook called");
    return false;
}

static void order_hook_get_relation_info_hook(PlannerInfo *root,
											 Oid relationObjectId,
											 bool inhparent,
											 RelOptInfo *rel) {
    (void)root; (void)relationObjectId; (void)inhparent; (void)rel;                                            
    elog(LOG, "get_relation_info_hook called");
}

static bool order_hook_get_relation_stats_hook(PlannerInfo *root,
											  RangeTblEntry *rte,
											  AttrNumber attnum,
											  VariableStatData *vardata) {
    (void)root; (void)rte; (void)attnum; (void)vardata;                                            
    elog(LOG, "get_relation_stats_hook called");
    return false;
}

static PlannedStmt* order_hook_planner_hook(Query *parse,
                                    const char *query_string,
                                    int cursorOptions,
                                    ParamListInfo boundParams) {
    // overwrites planner!
    elog(LOG, "order_hook_planner_hook called");
    return standard_planner(parse, query_string, cursorOptions, boundParams);
}

static RelOptInfo* order_hook_join_search_hook(PlannerInfo *root,
                                        int levels_needed,
                                        List *initial_rels) {
    // overwrites join order
    elog(LOG, "join_search_hook called");
    return standard_join_search(root, levels_needed, initial_rels);
}

static void order_hook_set_rel_pathlist_hook(PlannerInfo *root,
                                            RelOptInfo *rel,
                                            Index rti,
                                            RangeTblEntry *rte) {
    (void)root; (void)rel; (void)rti; (void)rte;
    elog(LOG, "set_rel_pathlist_hook called");
}

static void order_hook_set_join_pathlist_hook(PlannerInfo *root,
                                             RelOptInfo *joinrel,
                                             RelOptInfo *outerrel,
                                             RelOptInfo *innerrel,
                                             JoinType jointype,
                                             JoinPathExtraData *extra) {
    (void)root; (void)joinrel; (void)outerrel; (void)innerrel; (void)jointype; (void)extra;
    elog(LOG, "set_join_pathlist_hook called");
}

static void order_hook_create_upper_paths_hook(PlannerInfo *root,
											  UpperRelationKind stage,
											  RelOptInfo *input_rel,
											  RelOptInfo *output_rel,
											  void *extra) {
    (void)root; (void)stage; (void)input_rel; (void)output_rel; (void)extra;
    elog(LOG, "create_upper_paths_hook called");
}

static void order_hook_post_parse_analyze_hook(ParseState *pstate,
											  Query *query,
											  JumbleState *jstate) {
    (void)pstate; (void)query; (void)jstate;
    elog(LOG, "post_parse_analyze_hook called");
}

// executor hooks overrunning other hooks
static void order_hook_ExecutorStart_hook(QueryDesc *queryDesc, int eflags) {
    elog(LOG, "ExecutorStart_hook called");
    standard_ExecutorStart(queryDesc, eflags);
}

static void order_hook_ExecutorRun_hook(QueryDesc *queryDesc,
								ScanDirection direction,
								uint64 count, bool execute_once) {
    elog(LOG, "ExecutorRun_hook called");
    standard_ExecutorRun(queryDesc, direction, count, execute_once);
}

static void order_hook_ExecutorFinish_hook(QueryDesc *queryDesc) {
    elog(LOG, "ExecutorFinish_hook called");
    standard_ExecutorFinish(queryDesc);
}

static void order_hook_ExecutorEnd_hook(QueryDesc *queryDesc) {
    elog(LOG, "ExecutorEnd_hook called");
    standard_ExecutorEnd(queryDesc);
}

static void order_hook_ProcessUtility_hook(PlannedStmt *pstmt,
										  const char *queryString,
										  bool readOnlyTree,
										  ProcessUtilityContext context,
										  ParamListInfo params,
										  QueryEnvironment *queryEnv,
										  DestReceiver *dest, QueryCompletion *qc) {
    elog(LOG, "ProcessUtility_hook called");
    standard_ProcessUtility(pstmt, queryString, readOnlyTree,
		context, params, queryEnv,
		dest, qc);
}

static Node* order_hook_CoerceParamHook(ParseState *pstate, Param *param,
								  Oid targetTypeId, int32 targetTypeMod,
								  int location) {
   (void)pstate; (void)param; (void)targetTypeId; (void)targetTypeMod; (void)location;
   elog(LOG, "CoerceParamHook called");
   return NULL;
}

/* how to handle these?
static void order_hook_ParamCompileHook(ParamListInfo params, struct Param *param,
                                        struct ExprState *state,
                                        Datum *resv, bool *resnull) {
   (void)params; (void)param; (void)state; (void)resv; (void)resnull;
   elog(LOG, "ParamCompileHook called");
} 

static void order_hook_ParamFetchHook(ParamListInfo params,
                                      int paramid, bool speculative,
                                      ParamExternData *workspace) {
    (void)params; (void)paramid; (void)speculative; (void)workspace;
    elog(LOG, "ParamFetchHook called");

static void order_hook_ParserSetupHook(struct ParseState *pstate, void *arg) {
    (void)pstate; (void)arg;
    elog(LOG, "ParserSetupHook called");
}
} */

static Node* order_hook_ParseParamRefHook (ParseState *pstate, ParamRef *pref) {
    (void)pstate; (void)pref;
    elog(LOG, "ParseParamRefHook called");
    return NULL;
}

static Node* order_hook_PostParseColumnRefHook(ParseState *pstate, ColumnRef *cref, Node *var) {
    (void)pstate; (void)cref; (void)var;
    elog(LOG, "PostParseColumnRefHook called");
    return NULL;
}

static Node* order_hook_PreParseColumnRefHook(ParseState *pstate, ColumnRef *cref) {
    (void)pstate; (void)cref;
    elog(LOG, "PreParseColumnRefHook called");
    return NULL;
}


void _PG_init(void) {
    emit_log_hook = order_hook_emit_log_hook;
    shmem_startup_hook = order_hook_shmem_startup_hook;
    shmem_request_hook = order_hook_shmem_request_hook;
    check_password_hook = order_hook_check_password_hook;
    ClientAuthentication_hook = order_hook_ClientAuthentication_hook;
    ExecutorCheckPerms_hook = order_hook_ExecutorCheckPerms_hook;
    object_access_hook = order_hook_object_access_hook;
    row_security_policy_hook_permissive = order_hook_row_security_policy_hook_permissive;
    row_security_policy_hook_restrictive = order_hook_row_security_policy_hook_restrictive;
    needs_fmgr_hook = order_hook_needs_fmgr_hook;
    fmgr_hook = order_hook_fmgr_hook;
    explain_get_index_name_hook = order_hook_explain_get_index_name_hook;
    ExplainOneQuery_hook = order_hook_ExplainOneQuery_hook;
    get_attavgwidth_hook = order_hook_get_attavgwidth_hook;
    get_index_stats_hook = order_hook_get_index_stats_hook;
    get_relation_info_hook = order_hook_get_relation_info_hook;
    get_relation_stats_hook = order_hook_get_relation_stats_hook;
    planner_hook = order_hook_planner_hook;
    join_search_hook = order_hook_join_search_hook;
    set_rel_pathlist_hook = order_hook_set_rel_pathlist_hook;
    set_join_pathlist_hook = order_hook_set_join_pathlist_hook;
    create_upper_paths_hook = order_hook_create_upper_paths_hook;
    post_parse_analyze_hook = order_hook_post_parse_analyze_hook;
    ExecutorStart_hook = order_hook_ExecutorStart_hook;
    ExecutorRun_hook = order_hook_ExecutorRun_hook;
    ExecutorFinish_hook = order_hook_ExecutorFinish_hook;
    ExecutorEnd_hook = order_hook_ExecutorEnd_hook;
    ProcessUtility_hook = order_hook_ProcessUtility_hook;

    // TODO: how to pass Parser Hooks

}
