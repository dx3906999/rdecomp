// case6_string.c — 字符串 & 数组遍历
// Tests: string ops, pointer arithmetic, global data

#include <stdint.h>
#include <stddef.h>

// 手写strlen
size_t my_strlen(const char *s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

// 字符串比较 (返回差值)
int32_t my_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int32_t)((unsigned char)*a - (unsigned char)*b);
}

// 简单哈希函数
uint32_t djb2_hash(const char *str) {
    uint32_t hash = 5381;
    int32_t c;
    while ((c = *str++) != 0) {
        hash = hash * 33 + c;
    }
    return hash;
}

// 数组求最大值
int32_t array_max(int32_t *arr, int32_t len) {
    if (len <= 0) return 0;
    int32_t max = arr[0];
    for (int32_t i = 1; i < len; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

int main(void) {
    int32_t arr[] = {3, 1, 4, 1, 5};
    return (int)my_strlen("hello") + my_strcmp("a", "b") + djb2_hash("test") + array_max(arr, 5);
}
