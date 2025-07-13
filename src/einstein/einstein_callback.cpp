#include "einstein_common.h"
#include "einstein_utils.h"
#include "einstein_syscalls.h"
#include "einstein_rewrite.h"
#include <regex>
#include <sstream>
#include <sys/stat.h>
// =====================================================================
// Global variables
// =====================================================================

string application_name = "";
// report_num starts at 1 (not 0) because we're using the report_nums as tags, and tag 0 is reserved for the EMPTY tag
static unsigned long long report_num = 1;

// =====================================================================
// Helpers
// =====================================================================

void inc_report_num()
{
    report_num++;
    if (report_num >= RESERVED_BYTES)
        EINSTEIN_EXIT("Error: report_num (0x%llx) >= RESERVED_BYTES (0x%lx)\n", report_num, RESERVED_BYTES);
}

void fix_syscall_args(syscall_ctx_t *ctx)
{
    // If any execve/execveat's env vars contain "LD_PRELOAD" and "cmdsvr", then overwrite the pointer to that var with a pointer to a dummy var
    if (ctx->nr == __NR_execve || ctx->nr == __NR_execveat)
    {
        // execve's and execveat's envp are different arg numbers
        const char **curr_envp;
        // const char *syscall, *filename, **argvp;
        if (ctx->nr == __NR_execve)
        {
            // syscall = "execve";
            // filename = (const char *) ctx->arg[0];
            // argvp = (const char **) ctx->arg[1];
            curr_envp = (const char **)ctx->arg[2];
        }
        if (ctx->nr == __NR_execveat)
        {
            // syscall = "execveat";
            // filename = (const char *) ctx->arg[1];
            // argvp = (const char **) ctx->arg[2];
            curr_envp = (const char **)ctx->arg[3];
        }
        // EINSTEIN_LOG("EINSTEIN: Checking execve/execveat's envp for preloaded cmdsvr: %s  (filename = '%s', argvp = '%s', envp = '%s')\n",
        //     syscall, filename, str_arr_info(argvp, false).c_str(), str_arr_info(curr_envp, false).c_str());
        for (int i = 0; curr_envp != NULL && curr_envp[i] != NULL; i++)
        {
            const char *curr_env = curr_envp[i];
            if (strstr(curr_env, "LD_PRELOAD") != NULL && strstr(curr_env, "cmdsvr") != NULL)
            {
                // EINSTEIN_LOG("EINSTEIN: Overwriting LD_PRELOADed cmdsvr env var passed to execve/execveat.\n");
                curr_envp[i] = "MY_EINSTEIN_VAR=hello";
            }
        }
        // EINSTEIN_LOG("EINSTEIN: Finished checking execve/execveat's envp for preloaded cmdsvr: %s  (filename = '%s', argvp = '%s', envp = '%s')\n",
        //     syscall, filename, str_arr_info(argvp, false).c_str(), str_arr_info(curr_envp, false).c_str());
    }
}

// TODO: Should we have a mutex for syscall_sites_covered, so that different threads don't access it at the same time?
static std::set<string> syscall_sites_covered;
bool syscall_covered(syscall_ctx_t *ctx)
{
    // A syscall site is the pair: (syscall number, syscall backtrace)... Although in all likelihood, one backtrace will only ever make one type of syscall.
    string s = einstein_syscalls[ctx->nr].name + ":" + bt_str(ctx->pinctx, false, true);

    // This syscall_site already exists in syscall_sites_covered
    if (syscall_sites_covered.find(s) != syscall_sites_covered.end())
        return true;

    // This syscall_site does not yet exist in syscall_sites_covered, so let's add it
    syscall_sites_covered.insert(s);
    return false;
}

// =====================================================================
// PC Tracking
// =====================================================================

ADDRINT _einstein_last_taint_pc = 0;
static string _einstein_last_recvfrom_backtrace = "";
static std::string _einstein_taintall_file;
bool _einstein_save_taint = true;

void einstein_init_taintall_file() {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/tmp/taintall");
    _einstein_taintall_file = std::string(filepath);
    
    // Remove the file if it exists from a previous run
    unlink(_einstein_taintall_file.c_str());
    
    EINSTEIN_LOG("Taintall trigger file: %s\n", _einstein_taintall_file.c_str());
}

void einstein_check_taintall_file() {
    struct stat st;
    if (stat(_einstein_taintall_file.c_str(), &st) == 0) {
        /* 
         * 1. Einstein starts
         *      It tracks all the syscalls 
         * 2. simple-test.sh sends taintall
         *      /tmp/taintall created
         * 3. Einstein stops saving syscalls
         *      the last saved was just prior `taintall` => the quiescent state
        */
        unlink(_einstein_taintall_file.c_str());
        _einstein_save_taint = false;
    }
}

string bt_str_vanilla(CONTEXT *ctx, bool include_module_names, bool include_addresses)
{
    // Get the original backtrace with PIN addresses
    string original_bt = bt_str(ctx, include_module_names, include_addresses);
    
    // Debug: print what we actually got
    EINSTEIN_LOG("DEBUG: Original backtrace format:\n%s\n", original_bt.c_str());
    
    // If addresses aren't included, return as-is
    if (!include_addresses) {
        return original_bt;
    }

    /* Used to do translation here but no more. */
    return "SMTH went wrong!";
}



/* Deprecated.
 * Keeping it cause it has the check on IMG and might need it later
 * XXX remove later tho
 */
string get_pin_offset_info(CONTEXT *ctx)
{
    string offset_info = "";
    PIN_LockClient();
    // Get current instruction pointer to find main executable
    ADDRINT current_ip = PIN_GetContextReg(ctx, REG_INST_PTR);
    IMG main_img = IMG_FindByAddress(current_ip);
    
    // Try to find main executable if current IP doesn't give us one
    if (!IMG_Valid(main_img) || !IMG_IsMainExecutable(main_img)) {
        // Look through all loaded images to find main executable
        for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
            if (IMG_IsMainExecutable(img)) {
                main_img = img;
                break;
            }
        }
    }
    
    if (IMG_Valid(main_img) && IMG_IsMainExecutable(main_img)) {
        ADDRINT pin_low = IMG_LowAddress(main_img);
     
        
        char offset_buf[512];
        snprintf(offset_buf, sizeof(offset_buf), 
                "\"pin_base_address\": \"0x%lx\",", pin_low);
        
        offset_info = string(offset_buf);
    } else {
        offset_info = "\"pin_base_address\": \"0x0\",";
    }
    PIN_UnlockClient();
    
    return offset_info;
}


// =====================================================================
// Analysis routines
// =====================================================================


void einstein_pre_syscall_hook(THREADID tid, syscall_ctx_t *ctx)
{
    fix_syscall_args(ctx);

    if (ctx->nr == __NR_close)
        fd_close((int)ctx->arg[0]);

    // If this is not an interesting syscall AND the syscall nr is untainted, return
    if (!is_syscall_sec_sensitive(ctx->nr) && !is_syscall_fd_creator(ctx->nr) && tagqarr_is_empty(ctx->nr_taint))
        return;

    // If the backtrace contains the string "libdbt-cmdsvr", return
    if (bt_str(ctx->pinctx, true, true).find("libdbt-cmdsvr") != string::npos)
        return;

    /*
     * I feel like this should have some checks to check if PC is in IMG bound
     * but ATM looks like its working(?)
     */
    if (_einstein_save_taint)
    {
        _einstein_last_recvfrom_backtrace = bt_str_vanilla(ctx->pinctx, true, false);
        EINSTEIN_LOG("PC tracking triggered by taintall signal\n");
        einstein_check_taintall_file();
    }

    // If we're in 'rewrite' mode, only check for this
    if (do_rewrites)
    {
        einstein_rewrite_check(ctx);
        return;
    }


    // Add PC field
    string taint_pc_field = "\"taint_introduction_pc_backtrace\": [], ";
    
    // if (!_einstein_save_taint && _einstein_last_recvfrom_backtrace != "")
    if (!_einstein_save_taint)
        taint_pc_field = "\"taint_introduction_pc_backtrace\": " + _einstein_last_recvfrom_backtrace + ", ";
        

    // If the args are untainted AND the syscall nr is untainted, this is an UNTAINTED syscall
    if (!einstein_syscalls[ctx->nr].arg_is_tainted(ctx) && tagqarr_is_empty(ctx->nr_taint))
    {
        if (!syscall_covered(ctx))
        {
            EINSTEIN_LOG("Found syscall: {"
                         "\"syscall\": \"%s\", "
                         "\"report_num\": %llu, "
                         "\"pid\": %d, \"ppid\": %d, \"tid\": %d, \"ptid\": %d, "
                         "\"tainted\": false, "
                         "\"application\": \"%s\", "
                         "\"application_testcase\": \"\", "
                         "\"application_corepath\": \"\", "
                         "\"application_corenum\": 0, "
                         "%s" // taint_pc_field
                         "\"backtrace\": %s, "
                         "\"syscall_nr_taint\": [], "
                         "\"syscall_args\": []"
                         "}\n",
                         einstein_syscalls[ctx->nr].name.c_str(),
                         report_num,
                         PIN_GetPid(), getppid(), PIN_GetTid(), PIN_GetParentTid(),
                         str_replace(application_name, "\"", "\\\"").c_str(),
                         taint_pc_field.c_str(),
                         bt_str(ctx->pinctx, true, false).c_str());
            inc_report_num();
        }
        return;
    }

    EINSTEIN_LOG("Found syscall: {"
                 "\"syscall\": \"%s\", "
                 "\"report_num\": %llu, "
                 "\"pid\": %d, \"ppid\": %d, \"tid\": %d, \"ptid\": %d, "
                 "\"tainted\": true, "
                 "\"application\": \"%s\", "
                 "\"application_testcase\": \"%s\", "
                 "\"application_corepath\": \"%s\", "
                 "\"application_corenum\": %d, "
                 "%s" // taint_pc_field
                 "\"backtrace\": %s, "
                 "\"syscall_nr_taint\": %s, "
                 "\"syscall_args\": %s"
                 "}\n",
                 einstein_syscalls[ctx->nr].name.c_str(),
                 report_num,
                 PIN_GetPid(), getppid(), PIN_GetTid(), PIN_GetParentTid(),
                 str_replace(application_name, "\"", "\\\"").c_str(),
                 str_replace(string(_libdft_debug_str), "\"", "\\\"").c_str(),
                 str_replace(memtaint_get_snapshot_path(), "\"", "\\\"").c_str(),
                 memtaint_get_snapshot_num(),
                 taint_pc_field.c_str(),
                 bt_str(ctx->pinctx, true, false).c_str(),
                 tagqarr_sprint(ctx->nr_taint).c_str(),
                 einstein_syscalls[ctx->nr].get_details(ctx).c_str());

    if (is_syscall_fd_creator(ctx->nr))
    {
        unsigned long long *this_report_num_ptr = (unsigned long long *)malloc(sizeof(unsigned long long));
        if (this_report_num_ptr == NULL)
            EINSTEIN_EXIT("Error allocating memory for this_report_num_ptr\n");
        *this_report_num_ptr = report_num;
        ctx->custom = this_report_num_ptr;
    }
    inc_report_num();
}

void einstein_post_fd_creator_hook(THREADID tid, syscall_ctx_t *ctx)
{
    sysexit_save_default_handling(tid); // If syscall succeeded, clear taint of any changed args
    if (!is_syscall_fd_creator(ctx->nr))
        return; // Sanity check

    // Load this report_num from the pre-syscall hook via ctx->custom
    unsigned long long this_report_num = 0;
    if (ctx->custom != NULL)
    {
        unsigned long long *this_report_num_ptr = (unsigned long long *)(ctx->custom);
        this_report_num = *this_report_num_ptr;
        free(this_report_num_ptr);
    }

    if ((int)ctx->ret == -1)
        return; // There was an error, so we won't track this fd

    if (ctx->nr == __NR_connect || ctx->nr == __NR_setsockopt || ctx->nr == __NR_bind)
    {
        fd_create((int)ctx->arg[0], this_report_num, ctx); // The fd is in arg 0
    }
    else if (ctx->nr == __NR_creat || ctx->nr == __NR_open || ctx->nr == __NR_openat || ctx->nr == __NR_openat2 || ctx->nr == __NR_socket)
    {
        fd_create((int)ctx->ret, this_report_num, ctx); // The fd is returned
    }
    else if (ctx->nr == __NR_socketpair)
    {
        fd_create(((int *)ctx->arg[3])[0], this_report_num, ctx); // The fds are in arg 3
        fd_create(((int *)ctx->arg[3])[1], this_report_num, ctx);
    }
    else if (ctx->nr == __NR_dup)
    {
        fd_create((int)ctx->ret, this_report_num, ctx); // The fd is returned
    }
    else if (ctx->nr == __NR_dup2 || ctx->nr == __NR_dup3)
    {
        fd_close((int)ctx->ret);                        // If newfd is already being used, it is closed by dup2/dup3
        fd_create((int)ctx->ret, this_report_num, ctx); // The fd is returned
    }
    else
    {
        EINSTEIN_LOG("ERROR: FD creator not handled by einstein_post_fd_creator_hook()!\n");
        return;
    }

}

// =====================================================================
// Instrumentation callbacks
// =====================================================================

void callbacks_einstein(void)
{
    einstein_syscalls_init();

    einstein_init_taintall_file();
    for (unsigned i = 0; i < SYSCALL_MAX; i++)
    {
        (void)syscall_set_pre(&syscall_desc[i], einstein_pre_syscall_hook);
    }

    for (unsigned i = 0; i < SYSCALL_MAX; i++)
    {
        if (is_syscall_fd_creator(i))
        {
            (void)syscall_set_post(&syscall_desc[i], einstein_post_fd_creator_hook);
        }
    }

}