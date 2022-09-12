//
// Created by camsyn on 2022/5/19.
//

#ifndef MIRAGE_FUZZER_DEFS_H
#define MIRAGE_FUZZER_DEFS_H

// Without taint tracking, with coverage tracking
#define CLANG_ORIG_TYPE 0
// Use mutated-if pass to plainarize nested if structure
#define CLANG_PHANTOM_TYPE 1
// Use libdft implemented by intel pin
#define CLANG_PIN_TYPE 2
// Use raw clang
#define CLANG_SOURCE_TYPE 3
// Use integrated type
#define CLANG_INTEG_TYPE 4
#define CLANG_LAF_TYPE 5
#define CLANG_TEST_TYPE 6
// Use AFL mode
#define CLANG_AFL_TYPE 7


#define CUSTOM_FN_CTX "ANGORA_CUSTOM_FN_CONTEXT"
#define GEN_ID_RANDOM_VAR "ANGORA_GEN_ID_RANDOM"
#define OUTPUT_COND_LOC_VAR "ANGORA_OUTPUT_COND_LOC"
#define TAINT_CUSTOM_RULE_VAR "ANGORA_TAINT_CUSTOM_RULE"
#define TAINT_RULE_LIST_VAR "ANGORA_TAINT_RULE_LIST"
#define FUZZING_INPUT_FILE ".cur_input"

#define COND_EQ_OP 32
#define COND_SW_TYPE 0x00FF
#define COND_SIGN_MASK 0x100
#define COND_BOOL_MASK 0x200
// #define COND_CALL_MASK 0x400
// #define COND_BR_MASK 0x800
#define COND_EXPLOIT_MASK 0x4000
#define COND_FN_TYPE 0x8002
#define COND_LEN_TYPE 0x8003

#ifdef DEBUG_INFO
// #define DEBUG_PRINTF printf
#define DEBUG_PRINTF(...)                                                      \
  do {                                                                         \
    printf(__VA_ARGS__);                                                       \
  } while (0)
#else
#define DEBUG_PRINTF(...)                                                      \
  do {                                                                         \
  } while (0)
#endif

#ifndef MIN
#define MIN(_a, _b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

#ifndef RRR
#define RRR(x) (random() % (x))
#endif

#endif //MIRAGE_FUZZER_DEFS_H
