// case5_switch.c — switch语句 & 复杂条件
// Tests: switch-case, compound conditions, ternary-like

#include <stdint.h>

// switch语句 (编译器可能生成跳转表或if-else链)
int32_t grade(int32_t score) {
    switch (score / 10) {
        case 10:
        case 9:  return 4;  // A
        case 8:  return 3;  // B
        case 7:  return 2;  // C
        case 6:  return 1;  // D
        default: return 0;  // F
    }
}

// 复合条件表达式
int32_t clamp(int32_t val, int32_t lo, int32_t hi) {
    if (val < lo) return lo;
    if (val > hi) return hi;
    return val;
}

// 多路分支 + 位操作
uint32_t encode_flags(int32_t a, int32_t b, int32_t c) {
    uint32_t flags = 0;
    if (a > 0)  flags |= 1;
    if (b > 0)  flags |= 2;
    if (c > 0)  flags |= 4;
    if (a > b)  flags |= 8;
    if (b > c)  flags |= 16;
    return flags;
}

// 短路求值
int32_t safe_div(int32_t a, int32_t b) {
    if (b != 0 && a / b > 10) {
        return a / b;
    }
    return 0;
}

int main(void) {
    return grade(85) + clamp(50, 0, 100) + encode_flags(1, -1, 3) + safe_div(100, 5);
}
