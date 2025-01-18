#include <cstdint>

struct wow64_system_service_ex_param_t {
    std::uint64_t signature;
    std::uint64_t func;
    std::uint64_t args_count;
    std::uint64_t args;
    std::uint64_t called;
    std::uint64_t ret;
};

using wow64_system_service_ex_hook_t =
    std::uint32_t (*)(std::uint32_t syscall_num, std::uint32_t* syscall_args);

#pragma code_seg(push, r1, ".text64$a")
__declspec(allocate(".text64$a"))  //
__declspec(dllexport) std::uint64_t wow64_system_service_ex_original =
    0xD4200000D4200000;
#pragma code_seg(pop, r1)

#pragma code_seg(push, r1, ".text64$b")
__declspec(dllexport) std::uint32_t wow64_system_service_ex_hook(
    std::uint32_t syscall_num,
    std::uint32_t* syscall_args) {
    // The pointer to the original function is just above the hook.
    wow64_system_service_ex_hook_t* original =
        (wow64_system_service_ex_hook_t*)((std::uint8_t*)
                                              wow64_system_service_ex_hook -
                                          sizeof(
                                              wow64_system_service_ex_hook_t*));

    if (syscall_num != 0x0FEA) {
        return (*original)(syscall_num, syscall_args);
    }

    wow64_system_service_ex_param_t* param =
        (wow64_system_service_ex_param_t*)(std::uint64_t)syscall_args[0];

    // Chosen by fair dice roll.
    if (param->signature != 0x89E3E9BE43908223) {
        return (*original)(syscall_num, syscall_args);
    }

    using func_t = std::uint64_t (*)(...);
    func_t func = (func_t)param->func;
    std::uint64_t args_count = param->args_count;
    std::uint64_t* args = (std::uint64_t*)param->args;

#define ARGS_01 args[0]
#define ARGS_02 ARGS_01, args[1]
#define ARGS_03 ARGS_02, args[2]
#define ARGS_04 ARGS_03, args[3]
#define ARGS_05 ARGS_04, args[4]
#define ARGS_06 ARGS_05, args[5]
#define ARGS_07 ARGS_06, args[6]
#define ARGS_08 ARGS_07, args[7]
#define ARGS_09 ARGS_08, args[8]
#define ARGS_10 ARGS_09, args[9]
#define ARGS_11 ARGS_10, args[10]
#define ARGS_12 ARGS_11, args[11]
#define ARGS_13 ARGS_12, args[12]
#define ARGS_14 ARGS_13, args[13]
#define ARGS_15 ARGS_14, args[14]
#define ARGS_16 ARGS_15, args[15]
#define ARGS_17 ARGS_16, args[16]
#define ARGS_18 ARGS_17, args[17]
#define ARGS_19 ARGS_18, args[18]
#define ARGS_20 ARGS_19, args[19]

    std::uint64_t result = 0xFFFFFFFFFFFFFFFF;
    if (args_count == 0) {
        result = func();
    } else if (args_count == 1) {
        result = func(ARGS_01);
    } else if (args_count == 2) {
        result = func(ARGS_02);
    } else if (args_count == 3) {
        result = func(ARGS_03);
    } else if (args_count == 4) {
        result = func(ARGS_04);
    } else if (args_count == 5) {
        result = func(ARGS_05);
    } else if (args_count == 6) {
        result = func(ARGS_06);
    } else if (args_count == 7) {
        result = func(ARGS_07);
    } else if (args_count == 8) {
        result = func(ARGS_08);
    } else if (args_count == 9) {
        result = func(ARGS_09);
    } else if (args_count == 10) {
        result = func(ARGS_10);
    } else if (args_count == 11) {
        result = func(ARGS_11);
    } else if (args_count == 12) {
        result = func(ARGS_12);
    } else if (args_count == 13) {
        result = func(ARGS_13);
    } else if (args_count == 14) {
        result = func(ARGS_14);
    } else if (args_count == 15) {
        result = func(ARGS_15);
    } else if (args_count == 16) {
        result = func(ARGS_16);
    } else if (args_count == 17) {
        result = func(ARGS_17);
    } else if (args_count == 18) {
        result = func(ARGS_18);
    } else if (args_count == 19) {
        result = func(ARGS_19);
    } else if (args_count == 20) {
        result = func(ARGS_20);
    }

    param->called = 1;
    param->ret = result;
    return 0;
}
#pragma code_seg(pop, r1)

int main() {
    // Silence is golden.
}
