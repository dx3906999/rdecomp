// case4_loops.c — 各类循环模式
// Tests: for, do-while, nested loops, early exit, countdown

#include <stdint.h>

// 简单for循环 (do-while形式)
int32_t sum_squares(int32_t n) {
    int32_t result = 0;
    for (int32_t i = 1; i <= n; i++) {
        result += i * i;
    }
    return result;
}

// do-while循环
int32_t count_bits(uint32_t x) {
    int32_t count = 0;
    do {
        if (x & 1) count++;
        x >>= 1;
    } while (x != 0);
    return count;
}

// 嵌套循环 + 早期退出
int32_t find_pair_sum(int32_t *arr, int32_t len, int32_t target) {
    for (int32_t i = 0; i < len; i++) {
        for (int32_t j = i + 1; j < len; j++) {
            if (arr[i] + arr[j] == target) {
                return i * 100 + j;
            }
        }
    }
    return -1;
}

// 倒数循环
int32_t reverse_sum(int32_t *arr, int32_t len) {
    int32_t sum = 0;
    for (int32_t i = len - 1; i >= 0; i--) {
        sum += arr[i];
    }
    return sum;
}

int main(void) {
    int32_t arr[] = {1, 2, 3, 4, 5};
    return sum_squares(3) + count_bits(0xff) + find_pair_sum(arr, 5, 5) + reverse_sum(arr, 5);
}
