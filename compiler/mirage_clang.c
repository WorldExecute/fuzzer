/*
  The code is modified from AFL's LLVM mode.
  afl did some minor modification on it, including:
  - add taint tracking arguments.
  - use afl's llvm passs.

   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define MIRAGE_MAIN

#ifndef WRAPPED_CLANG
#define WRAPPED_CLANG clang
#endif

#ifndef WRAPPED_CLANGXX
#define WRAPPED_CLANGXX clang++ 
#endif

#define __QUOTE(x) #x
#define __MIRAGE_STR(x) __QUOTE(x)
#define W_CLANG   __MIRAGE_STR(WRAPPED_CLANG)
#define W_CLANGXX __MIRAGE_STR(WRAPPED_CLANGXX)


#include "alloc-inl.h"
#include "debug.h"
#include "defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

static u8 *obj_path;       /* Path to runtime libraries         */
static u8 **cc_params;     /* Parameters passed to the real CC  */
static u32 cc_par_cnt = 1; /* Param count, including argv0      */
static u8 clang_type = CLANG_LAF_TYPE;
static u8 is_cxx = 0;

static void add_llvm_pass(char *pass_name)
{
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/pass/%s.so", obj_path, pass_name);
    switch (clang_type)
    {
    case CLANG_INTEG_TYPE:
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-IntegMode";
        break;
    case CLANG_PHANTOM_TYPE:
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-PhantomMode";
        break;
    case CLANG_PIN_TYPE:
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-PinMode";
        break;
    case CLANG_SOURCE_TYPE:
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-SourceMode";
        break;
    case CLANG_LAF_TYPE:
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-LafMode";
        break;
    case CLANG_AFL_TYPE:
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-AFLMode";
        break;
    
    default:
        break;
    }
    if (!!getenv("NO_LAF")) {
        cc_params[cc_par_cnt++] = "-mllvm";
        cc_params[cc_par_cnt++] = "-NoLaf";
    }
}

/* Try to find the runtime libraries. If that fails, abort. */
static void find_obj(u8 *argv0)
{
    u8 *ts_path = getenv("MIRAGE_PATH");
    u8 *slash, *tmp;

    if (ts_path)
    {

        tmp = alloc_printf("%s/runtime/libafl-rt.a", ts_path);

        if (!access(tmp, R_OK))
        {
            obj_path = ts_path;
            ck_free(tmp);
            return;
        }

        ck_free(tmp);
    }

    slash = strrchr(argv0, '/');

    if (slash)
    {
        u8 *dir;
        *slash = 0;
        dir = ck_strdup(argv0);
        *slash = '/';

        tmp = alloc_printf("%s/runtime/libafl-rt.a", dir);
        if (!access(tmp, R_OK))
        {
            obj_path = dir;
            ck_free(tmp);
            return;
        }

        ck_free(tmp);
        ck_free(dir);
    }

    FATAL("Unable to find 'libafl-rt.a'");
}

static void check_type(char *name)
{
    u8 *use_orig = getenv("USE_ORIG");
    u8 *use_phantom = getenv("USE_PHANTOM");
    u8 *use_integ = getenv("USE_INTEG");
    u8 *use_pin = getenv("USE_PIN");
    u8 *use_source = getenv("USE_SOURCE");
    u8 *use_laf = getenv("USE_LAF");
    u8 *use_test = getenv("USE_TEST");
    u8 *use_afl = getenv("USE_AFL");
    if (use_orig)
    {
        clang_type = CLANG_ORIG_TYPE;
    }
    else if (use_phantom)
    {
        clang_type = CLANG_PHANTOM_TYPE;
    }
    else if (use_pin)
    {
        clang_type = CLANG_PIN_TYPE;
    }
    else if (use_source)
    {
        clang_type = CLANG_SOURCE_TYPE;
    }
    else if (use_integ)
    {
        clang_type = CLANG_INTEG_TYPE;
    }
    else if (use_laf)
    {
        clang_type = CLANG_LAF_TYPE;
    }
    else if (use_test)
    {
        clang_type = CLANG_TEST_TYPE;
    }
    else if (use_afl) 
    {
        clang_type = CLANG_AFL_TYPE;
    }
    if (!strcmp(name, "mirage-clang++"))
    {
        is_cxx = 1;
    }
}

static u8 check_if_assembler(u32 argc, char **argv)
{
    /* Check if a file with an assembler extension ("s" or "S") appears in argv */

    u8 *cur = NULL;
    while (--argc)
    {
        cur = *(++argv);

        const u8 *ext = strrchr(cur, '.');
        if (ext && (!strcmp(ext + 1, "s") || !strcmp(ext + 1, "S")))
        {
            return 1;
        }
    }

    return 0;
}

static void add_mirage_pass()
{
    if (clang_type == CLANG_ORIG_TYPE)
    {
        return;
    }
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-disable-O0-optnone";

    switch (clang_type)
    {
    case CLANG_AFL_TYPE:
    case CLANG_LAF_TYPE:
    case CLANG_SOURCE_TYPE:
    case CLANG_PHANTOM_TYPE:
    case CLANG_PIN_TYPE:
    case CLANG_INTEG_TYPE:
        add_llvm_pass("libIntegPass");
        break;
    case CLANG_TEST_TYPE:
        add_llvm_pass("libTest");
        break;
    default:
        break;
    }

    //    if (clang_type == CLANG_DFSAN_TYPE) {
    //        cc_params[cc_par_cnt++] = "-mllvm";
    //        cc_params[cc_par_cnt++] = "-DFSanMode";
    //    } else if (clang_type == CLANG_TRACK_TYPE || clang_type == CLANG_PIN_TYPE) {
    //        cc_params[cc_par_cnt++] = "-mllvm";
    //        cc_params[cc_par_cnt++] = "-TrackMode";
    //    }
    //
    //    cc_params[cc_par_cnt++] = "-mllvm";
    //    cc_params[cc_par_cnt++] = alloc_printf(
    //            "-afl-dfsan-abilist=%s/rules/afl_abilist.txt", obj_path);
    //    cc_params[cc_par_cnt++] = "-mllvm";
    //    cc_params[cc_par_cnt++] = alloc_printf(
    //            "-afl-dfsan-abilist=%s/rules/dfsan_abilist.txt", obj_path);
    //    cc_params[cc_par_cnt++] = "-mllvm";
    //    cc_params[cc_par_cnt++] = alloc_printf(
    //            "-afl-exploitation-list=%s/rules/exploitation_list.txt", obj_path);

    //    char *rule_list = getenv(TAINT_RULE_LIST_VAR);
    //    if (rule_list) {
    //        printf("rule_list : %s\n", rule_list);
    //        cc_params[cc_par_cnt++] = "-mllvm";
    //        cc_params[cc_par_cnt++] =
    //                alloc_printf("-afl-dfsan-abilist=%s", rule_list);
    //    }
}

static void add_runtime()
{
    if (clang_type == CLANG_ORIG_TYPE)
        return;
    // cc_params[cc_par_cnt++] = "-I/${HOME}/clang+llvm/include/c++/v1";
    switch (clang_type) {
        case CLANG_SOURCE_TYPE:
            cc_params[cc_par_cnt++] =
                alloc_printf("%s/runtime/libsource-rt.a", obj_path);
            break;
        case CLANG_PHANTOM_TYPE:
            cc_params[cc_par_cnt++] =
                alloc_printf("%s/runtime/libphantom-rt.a", obj_path);
            break;
        case CLANG_PIN_TYPE:
            cc_params[cc_par_cnt++] = alloc_printf("%s/runtime/libdta-rt.a", obj_path);
            break;
        case CLANG_LAF_TYPE:
        case CLANG_AFL_TYPE:
            cc_params[cc_par_cnt++] = alloc_printf("%s/runtime/libafl-rt.a", obj_path);
            break;
    }

    cc_params[cc_par_cnt++] = "-pthread";
    if (!is_cxx)
        cc_params[cc_par_cnt++] = "-lstdc++";
    cc_params[cc_par_cnt++] = "-lrt";


    cc_params[cc_par_cnt++] = "-Wl,--no-as-needed";
    cc_params[cc_par_cnt++] = "-Wl,--gc-sections"; // if darwin -Wl, -dead_strip
    cc_params[cc_par_cnt++] = "-ldl";
    cc_params[cc_par_cnt++] = "-lpthread";
    cc_params[cc_par_cnt++] = "-lm";
}

static void edit_params(u32 argc, char **argv)
{
    if (clang_type == CLANG_ORIG_TYPE)
        return;

    u8 fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
    u8 maybe_assembler = 0;
    u8 *name;

    cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

    name = strrchr(argv[0], '/');
    if (!name)
        name = argv[0];
    else
        name++;
    check_type(name);

    if (is_cxx)
    {
        u8 *alt_cxx = getenv("MIRAGE_CXX");
        cc_params[0] = alt_cxx ? alt_cxx : (u8 *)W_CLANGXX;
    }
    else
    {
        u8 *alt_cc = getenv("MIRAGE_CC");
        cc_params[0] = alt_cc ? alt_cc : (u8 *)W_CLANG;
    }

    maybe_assembler = check_if_assembler(argc, argv);

    /* Detect stray -v calls from ./configure scripts. */
    if (argc == 1 && !strcmp(argv[1], "-v"))
        maybe_linking = 0;

    u8 c2o = 0;
    while (--argc)
    {
        u8 *cur = *(++argv);

        if (!c2o && strstr(cur, ".c"))
        {
            c2o = 1;
        }

        if (!strcmp(cur, "-O1") || !strcmp(cur, "-O2") || !strcmp(cur, "-O3"))
        {
            continue;
        }
        if (!strcmp(cur, "-m32"))
            bit_mode = 32;
        if (!strcmp(cur, "-m64"))
            bit_mode = 64;

        if (!strcmp(cur, "-x"))
            x_set = 1;

        if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
            maybe_linking = 0;

        if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
            asan_set = 1;

        if (strstr(cur, "FORTIFY_SOURCE"))
            fortify_set = 1;

        if (!strcmp(cur, "-shared"))
            maybe_linking = 0;

        if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
            continue;

        cc_params[cc_par_cnt++] = cur;
    }

    if (!maybe_assembler)
    {
        add_mirage_pass();
    }

    cc_params[cc_par_cnt++] = "-pie";
    cc_params[cc_par_cnt++] = "-fpic";
    cc_params[cc_par_cnt++] = "-Qunused-arguments";

    /*
    cc_params[cc_par_cnt++] = "-mno-mmx";
    cc_params[cc_par_cnt++] = "-mno-sse";
    cc_params[cc_par_cnt++] = "-mno-sse2";
    cc_params[cc_par_cnt++] = "-mno-avx";
    cc_params[cc_par_cnt++] = "-mno-sse3";
    cc_params[cc_par_cnt++] = "-mno-sse4.1";
    cc_params[cc_par_cnt++] = "-mno-sse4.2";
    cc_params[cc_par_cnt++] = "-mno-ssse3";
    */

    if (getenv("MIRAGE_HARDEN"))
    {
        cc_params[cc_par_cnt++] = "-fstack-protector-all";

        if (!fortify_set)
            cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";
    }

    if (!asan_set && (clang_type == CLANG_AFL_TYPE || clang_type == CLANG_LAF_TYPE))
    {
        if (getenv("USE_ASAN"))
        {
            if (getenv("USE_MSAN"))
                FATAL("ASAN and MSAN are mutually exclusive");

            if (getenv("MIRAGE_HARDEN"))
                FATAL("ASAN and MIRAGE_HARDEN are mutually exclusive");

            // OKF("Address Sanitizer Instrumentation!");
            cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
            cc_params[cc_par_cnt++] = "-fsanitize=address";
        }
        else if (getenv("USE_MSAN"))
        {

            if (getenv("USE_ASAN"))
                FATAL("ASAN and MSAN are mutually exclusive");

            if (getenv("MIRAGE_HARDEN"))
                FATAL("MSAN and MIRAGE_HARDEN are mutually exclusive");

            // OKF("Memory Sanitizer Instrumentation!");
            cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
            cc_params[cc_par_cnt++] = "-fsanitize=memory";
        }
        else if (getenv("USE_UBSAN"))
        {
            // OKF("Undefined Sanitizer Instrumentation!");
            cc_params[cc_par_cnt++] = "-fsanitize=undefined";
            cc_params[cc_par_cnt++] = "-fsanitize-undefined-trap-on-error";
            cc_params[cc_par_cnt++] = "-fno-sanitize-recover=all";
            cc_params[cc_par_cnt++] = "-fno-omit-frame-pointer";
        }
        else if (getenv("USE_TSAN"))
        {

            // OKF("Thread Sanitizer Instrumentation!");
            cc_params[cc_par_cnt++] = "-fsanitize=thread";
            cc_params[cc_par_cnt++] = "-fno-omit-frame-pointer";
        }
    }

    if (!getenv("MIRAGE_DONT_OPTIMIZE"))
    {
        cc_params[cc_par_cnt++] = "-g";
        // if (!c2o)
        cc_params[cc_par_cnt++] = "-O3";
        cc_params[cc_par_cnt++] = "-funroll-loops";
    }

    if (getenv("MIRAGE_NO_BUILTIN"))
    {

        cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
        cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    }

    if (clang_type != CLANG_PIN_TYPE)
    {
        cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";
        cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
        cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";
        /* When the user tries to use persistent or deferred forkserver modes by
           appending a single line to the program, we want to reliably inject a
           signature into the binary (to be picked up by afl-fuzz) and we want
           to call a function from the runtime .o file. This is unnecessarily
           painful for three reasons:

           1) We need to convince the compiler not to optimize out the signature.
              This is done with __attribute__((used)).

           2) We need to convince the linker, when called with -Wl,--gc-sections,
              not to do the same. This is done by forcing an assignment to a
              'volatile' pointer.

           3) We need to declare __afl_persistent_loop() in the global namespace,
              but doing this within a method in a class is hard - :: and extern "C"
              are forbidden and __attribute__((alias(...))) doesn't work. Hence the
              __asm__ aliasing trick.

         */

        cc_params[cc_par_cnt++] = "-D__AFL_LOOP(_A)="
                                  "({ static volatile char *_B __attribute__((used)); "
                                  " _B = (char*)\"" PERSIST_SIG "\"; "
#ifdef __APPLE__
                                  "__attribute__((visibility(\"default\"))) "
                                  "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
                                  "__attribute__((visibility(\"default\"))) "
                                  "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif
                                  "_L(_A); })";

        cc_params[cc_par_cnt++] = "-D__AFL_INIT()="
                                  "do { static volatile char *_A __attribute__((used)); "
                                  " _A = (char*)\"" DEFER_SIG "\"; "
#ifdef __APPLE__
                                  "__attribute__((visibility(\"default\"))) "
                                  "void _I(void) __asm__(\"___afk_manual_init\"); "
#else
                                  "__attribute__((visibility(\"default\"))) "
                                  "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif
                                  "_I(); } while (0)";

        if (x_set)
        {
            cc_params[cc_par_cnt++] = "-x";
            cc_params[cc_par_cnt++] = "none";
        }

    }
    if (maybe_linking)
    {

        if (x_set)
        {
            cc_params[cc_par_cnt++] = "-x";
            cc_params[cc_par_cnt++] = "none";
        }

        add_runtime();
        switch (bit_mode)
        {
        case 0:
            break;
        case 32:
            /* if (access(cc_params[cc_par_cnt - 1], R_OK)) */
            // FATAL("-m32 is not supported by your compiler");
            break;

        case 64:
            /* if (access(cc_params[cc_par_cnt - 1], R_OK)) */
            // FATAL("-m64 is not supported by your compiler");
            break;
        }
    }
    switch (clang_type)
    {
        case CLANG_PHANTOM_TYPE:
        case CLANG_PIN_TYPE:
            cc_params[cc_par_cnt++] = "-ludis86";
    }
    cc_params[cc_par_cnt] = NULL;
}

/* Main entry point */

int main(int argc, char **argv)
{
    if (argc == 2) {
       if(!strcmp("init", argv[1])) {
            uid_t uid = getuid();
            struct passwd *pw = getpwuid(uid);
            
            char *cmd = alloc_printf("%s/.miragefuzz", pw->pw_dir);

            printf("/bin/rm -r %s\n", cmd);
            execlp("/bin/rm", "/bin/rm", "-r", cmd, NULL);
        }
        else if (argv[1][0] == '-') {
            if (strstr(argv[0], "mirage-clang++")) {
                execlp(W_CLANGXX, W_CLANGXX, argv[1], NULL);
            }
            else {
                execlp(W_CLANG, W_CLANG, argv[1], NULL);    
            }
        }
    } 
    if (argc < 2)
    {

        SAYF("\n"
             "This is a helper application for afl-fuzz. It serves as a drop-in "
             "replacement\n"
             "for clang, letting you recompile third-party code with the required "
             "runtime\n"
             "instrumentation. A common use pattern would be one of the "
             "following:\n\n"

             "  CC=%s/afl-clang ./configure\n"
             "  CXX=%s/afl-clang++ ./configure\n\n"

             "In contrast to the traditional afl-clang tool, this version is "
             "implemented as\n"
             "an LLVM pass and tends to offer improved performance with slow "
             "programs.\n\n"

             "You can specify custom next-stage toolchain via MIRAGE_CC and "
             "MIRAGE_CXX. Setting\n"
             "MIRAGE_HARDEN enables hardening optimizations in the compiled "
             "code.\n\n",
             "xx", "xx");

        exit(1);
    }

    find_obj(argv[0]);

    edit_params(argc, argv);
    /*
    for (int i = 0; i < cc_par_cnt; i++) {
      printf("%s ", cc_params[i]);
    }
    printf("\n");
    */
    if (getenv("USE_DEBUG"))
    {
        FILE *f = fopen("debug-command.txt", "w+");
        u32 i = 0;
        char *pwd = get_current_dir_name();
        fprintf(f, "%s\n\n", pwd);
        free(pwd);
        while (i != argc)
        {
            fprintf(f, "%s \\\n", argv[i++]);
        }
        fprintf(f, "\n\n");
        char **str = (char **) cc_params;
        while (*str != NULL)
        {
            fprintf(f, "%s \\\n", *str);
            str++;
        }
        fclose(f);
    }

    execvp(cc_params[0], (char **)cc_params);

    FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

    return 0;
}
