#include "einstein_common.h"
#include "einstein_utils.h"
#include "einstein_syscalls.h"
#include "einstein_rewrite.h"

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
// Analysis routines
// =====================================================================
bool _einstein_track_taint_pc = false;
ADDRINT _einstein_last_taint_pc = 0;
// static bool _einstein_capture_next_return = false;

// void einstein_post_syscall_pc_capture(THREADID tid, syscall_ctx_t *ctx)
// {
//     if (_einstein_capture_next_return && _einstein_last_taint_pc == 0)
//     {
//         // We're now back in the main program after the syscall
//         ADDRINT return_pc = PIN_GetContextReg(ctx->pinctx, REG_INST_PTR);
//         _einstein_last_taint_pc = return_pc;
//         _einstein_capture_next_return = false;
//         EINSTEIN_LOG("Captured return PC in main program: %p\n", (void *)return_pc);
//     }
// }

// void setup_main_pc_capture()
// {
//     INS_AddInstrumentFunction([](INS ins, VOID *v)
//                               {
//         ADDRINT pc = INS_Address(ins);
        
//         // Only instrument instructions in your main program range
//         if ((pc >= 0x7fff00102000) && (pc <= 0x7fff00103000)) {
//             INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)capture_main_program_pc,
//                           IARG_INST_PTR, IARG_END);
//         } }, 0);
// }

// Add globals
bool _einstein_waiting_for_main_pc = false;
static ADDRINT _main_img_low = 0;
static ADDRINT _main_img_high = 0;
static bool _main_img_bounds_set = false;

// Modified auto-enable function
void einstein_auto_enable_pc_tracking(ADDRINT pc)
{
    if (!_einstein_track_taint_pc)
    {
        _einstein_track_taint_pc = true;
        _einstein_waiting_for_main_pc = true;
        EINSTEIN_LOG("Taint detected, waiting for next main program instruction\n");
    }
}

// PC capture function
void einstein_capture_main_program_pc(ADDRINT pc)
{
    if (_einstein_waiting_for_main_pc && _einstein_last_taint_pc == 0)
    {
        _einstein_last_taint_pc = pc;
        _einstein_waiting_for_main_pc = false;
        EINSTEIN_LOG("SUCCESS: Captured main program PC: %p\n", (void *)pc);
    }
}

// Image load callback - captures main executable bounds
VOID einstein_image_load_callback(IMG img, VOID *v)
{
    if (IMG_IsMainExecutable(img))
    {
        _main_img_low = IMG_LowAddress(img);
        _main_img_high = IMG_HighAddress(img);
        _main_img_bounds_set = true;

        EINSTEIN_LOG("Main executable loaded: %s\n", IMG_Name(img).c_str());
        EINSTEIN_LOG("Address range: %p - %p\n", (void *)_main_img_low, (void *)_main_img_high);
    }
}

// Instruction callback - only hooks main executable instructions
VOID einstein_instruction_callback(INS ins, VOID *v)
{
    if (_main_img_bounds_set)
    {
        ADDRINT pc = INS_Address(ins);

        // Only instrument instructions in main executable
        if (pc >= _main_img_low && pc <= _main_img_high)
        {
            INS_InsertCall(ins, IPOINT_BEFORE,
                           (AFUNPTR)einstein_capture_main_program_pc,
                           IARG_INST_PTR, IARG_END);
        }
    }
}

// Setup function
void einstein_setup_main_pc_capture_optimized()
{
    IMG_AddInstrumentFunction(einstein_image_load_callback, 0);
    INS_AddInstrumentFunction(einstein_instruction_callback, 0);
    EINSTEIN_LOG("Main PC capture instrumentation setup complete\n");
}

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

    // If we're in 'rewrite' mode, only check for this
    if (do_rewrites)
    {
        einstein_rewrite_check(ctx);
        return;
    }

    // AUTO-ENABLE PC tracking on first tainted syscall (ADD THIS SECTION)
    if (!_einstein_track_taint_pc &&
        (einstein_syscalls[ctx->nr].arg_is_tainted(ctx) || !tagqarr_is_empty(ctx->nr_taint)))
    {
        ADDRINT pc = PIN_GetContextReg(ctx->pinctx, REG_INST_PTR);
        einstein_auto_enable_pc_tracking(pc);
    }

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
                         "\"backtrace\": %s, "
                         "\"syscall_nr_taint\": [], "
                         "\"syscall_args\": []"
                         "}\n",
                         einstein_syscalls[ctx->nr].name.c_str(),
                         report_num,
                         PIN_GetPid(), getppid(), PIN_GetTid(), PIN_GetParentTid(),
                         str_replace(application_name, "\"", "\\\"").c_str(),
                         bt_str(ctx->pinctx, true, false).c_str());
            inc_report_num();
        }
        return;
    }

    // ADD PC field for tainted syscalls (ADD THIS SECTION)
    string taint_pc_field = "";
    if (_einstein_track_taint_pc && _einstein_last_taint_pc != 0)
    {
        taint_pc_field = "\"taint_introduction_pc\": \"" + ptr_to_string((void *)_einstein_last_taint_pc, true) + "\", ";
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
                 "%s" // INSERT taint_pc_field HERE
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
                 taint_pc_field.c_str(), // ADD THIS LINE
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

    // ADD THIS: Setup main PC capture instrumentation
    einstein_setup_main_pc_capture_optimized();

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
