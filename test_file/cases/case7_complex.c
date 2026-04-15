// case7_complex.c — 复杂控制流 + 数据结构
// Tests: linked list, recursion, complex expressions, goto-like patterns

#include <stdint.h>
#include <stdlib.h>

// ── 链表操作 ──────────────────────────────────────────────────

typedef struct Node {
    int32_t value;
    struct Node *next;
} Node;

// 创建节点
Node *create_node(int32_t val) {
    Node *n = (Node *)malloc(sizeof(Node));
    if (n) {
        n->value = val;
        n->next = NULL;
    }
    return n;
}

// 链表求和 (迭代)
int32_t list_sum(Node *head) {
    int32_t sum = 0;
    Node *cur = head;
    while (cur != NULL) {
        sum += cur->value;
        cur = cur->next;
    }
    return sum;
}

// 链表反转
Node *list_reverse(Node *head) {
    Node *prev = NULL;
    Node *cur = head;
    while (cur != NULL) {
        Node *next = cur->next;
        cur->next = prev;
        prev = cur;
        cur = next;
    }
    return prev;
}

// 链表长度（递归）
int32_t list_length(Node *head) {
    if (head == NULL)
        return 0;
    return 1 + list_length(head->next);
}

// ── 递归算法 ──────────────────────────────────────────────────

// 斐波那契 (递归, 有大量重复计算)
int64_t fibonacci(int32_t n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// 快速幂
int64_t power(int64_t base, int32_t exp) {
    if (exp == 0) return 1;
    if (exp % 2 == 0) {
        int64_t half = power(base, exp / 2);
        return half * half;
    }
    return base * power(base, exp - 1);
}

// 汉诺塔 (递归, 多参数)
int32_t hanoi_count;
void hanoi(int32_t n, int32_t from, int32_t to, int32_t aux) {
    if (n == 0) return;
    hanoi(n - 1, from, aux, to);
    hanoi_count++;
    hanoi(n - 1, aux, to, from);
}

// ── 复杂表达式 ────────────────────────────────────────────────

// 多重短路求值
int32_t complex_condition(int32_t a, int32_t b, int32_t c, int32_t d) {
    if ((a > 0 && b > 0) || (c > 0 && d > 0)) {
        if (a + b > c + d && a * b != 0) {
            return 1;
        }
        return 2;
    }
    return 0;
}

// 三元运算符链
int32_t ternary_chain(int32_t x) {
    return (x > 100) ? 4
         : (x > 50)  ? 3
         : (x > 10)  ? 2
         : (x > 0)   ? 1
         : 0;
}

// ── 位操作 ────────────────────────────────────────────────────

// 计算汉明距离
int32_t hamming_distance(uint32_t a, uint32_t b) {
    uint32_t xor = a ^ b;
    int32_t count = 0;
    while (xor) {
        count += xor & 1;
        xor >>= 1;
    }
    return count;
}

// 位反转 (32-bit)
uint32_t reverse_bits(uint32_t n) {
    uint32_t result = 0;
    for (int i = 0; i < 32; i++) {
        result = (result << 1) | (n & 1);
        n >>= 1;
    }
    return result;
}

// ── 数组+排序 ─────────────────────────────────────────────────

// 冒泡排序
void bubble_sort(int32_t *arr, int32_t len) {
    for (int32_t i = 0; i < len - 1; i++) {
        int32_t swapped = 0;
        for (int32_t j = 0; j < len - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                int32_t tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
                swapped = 1;
            }
        }
        if (!swapped) break;
    }
}

// 二分查找
int32_t binary_search(int32_t *arr, int32_t len, int32_t target) {
    int32_t lo = 0, hi = len - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) return mid;
        if (arr[mid] < target)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -1;
}

int main(void) {
    // 链表
    Node *a = create_node(1);
    Node *b = create_node(2);
    Node *c = create_node(3);
    a->next = b;
    b->next = c;
    int32_t s = list_sum(a);
    a = list_reverse(a);
    int32_t len = list_length(a);

    // 递归
    int64_t fib = fibonacci(10);
    int64_t pw = power(2, 10);
    hanoi_count = 0;
    hanoi(3, 1, 3, 2);

    // 复杂表达式
    int32_t cc = complex_condition(1, 2, 3, 4);
    int32_t tc = ternary_chain(42);

    // 位操作
    int32_t hd = hamming_distance(0x55, 0xAA);
    uint32_t rb = reverse_bits(0x12345678);

    // 排序+搜索
    int32_t arr[] = {5, 3, 1, 4, 2};
    bubble_sort(arr, 5);
    int32_t idx = binary_search(arr, 5, 3);

    return (int32_t)(s + len + fib + pw + hanoi_count + cc + tc + hd + rb + idx);
}
