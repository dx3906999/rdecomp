// case10_mixed.c — 综合测试: 函数指针, setjmp-like, 复杂类型
// Tests: function pointers, callback patterns, union, volatile, goto

#include <stdint.h>
#include <string.h>

// ── 函数指针 + 回调 ────────────────────────────────────────

typedef int32_t (*transform_fn)(int32_t);

int32_t double_it(int32_t x) { return x * 2; }
int32_t square_it(int32_t x) { return x * x; }
int32_t negate_it(int32_t x) { return -x; }

// 对数组每个元素应用函数指针
void array_map(int32_t *arr, int32_t len, transform_fn fn) {
    for (int32_t i = 0; i < len; i++) {
        arr[i] = fn(arr[i]);
    }
}

// 函数指针表 (模拟 vtable)
int32_t dispatch(int32_t op, int32_t val) {
    transform_fn ops[] = {double_it, square_it, negate_it};
    if (op >= 0 && op < 3)
        return ops[op](val);
    return val;
}

// ── 联合体 + 类型双关 ────────────────────────────────────

typedef union {
    float    f;
    uint32_t u;
} FloatBits;

// 快速平方根倒数 (Quake III algorithm)
float fast_inv_sqrt(float number) {
    FloatBits conv;
    float x2 = number * 0.5f;
    conv.f = number;
    conv.u = 0x5f3759df - (conv.u >> 1);
    conv.f = conv.f * (1.5f - (x2 * conv.f * conv.f));
    return conv.f;
}

// ── goto 模式 ─────────────────────────────────────────────

// 错误处理中常见的 goto cleanup 模式
int32_t resource_init(int32_t flags) {
    int32_t *buffer1 = NULL;
    int32_t *buffer2 = NULL;
    int32_t result = -1;

    buffer1 = (int32_t *)__builtin_alloca(64);
    if (!buffer1)
        goto cleanup;

    if (flags & 1) {
        buffer2 = (int32_t *)__builtin_alloca(128);
        if (!buffer2)
            goto cleanup;
    }

    // 初始化
    memset(buffer1, 0, 64);
    if (buffer2)
        memset(buffer2, 0, 128);

    if (flags & 2) {
        buffer1[0] = 0x42;
        if (buffer2)
            buffer2[0] = 0x43;
    }

    result = buffer1[0];
    if (buffer2)
        result += buffer2[0];

cleanup:
    return result;
}

// ── 复杂结构体嵌套 ───────────────────────────────────────

typedef struct {
    int32_t x, y;
} Point;

typedef struct {
    Point top_left;
    Point bottom_right;
} Rect;

int32_t rect_area(Rect *r) {
    int32_t w = r->bottom_right.x - r->top_left.x;
    int32_t h = r->bottom_right.y - r->top_left.y;
    if (w < 0) w = -w;
    if (h < 0) h = -h;
    return w * h;
}

int32_t rect_contains(Rect *r, Point *p) {
    return p->x >= r->top_left.x
        && p->x <= r->bottom_right.x
        && p->y >= r->top_left.y
        && p->y <= r->bottom_right.y;
}

int32_t rects_overlap(Rect *a, Rect *b) {
    if (a->top_left.x > b->bottom_right.x || b->top_left.x > a->bottom_right.x)
        return 0;
    if (a->top_left.y > b->bottom_right.y || b->top_left.y > a->bottom_right.y)
        return 0;
    return 1;
}

// ── 循环展开 / SIMD-like ──────────────────────────────────

// 向量点积 (展开 4 元素)
int32_t dot_product(int32_t *a, int32_t *b, int32_t len) {
    int32_t sum = 0;
    int32_t i = 0;

    // 4-way unrolled
    for (; i + 3 < len; i += 4) {
        sum += a[i]   * b[i];
        sum += a[i+1] * b[i+1];
        sum += a[i+2] * b[i+2];
        sum += a[i+3] * b[i+3];
    }
    // remainder
    for (; i < len; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

// ── 多重循环 + break/continue ─────────────────────────────

// 在二维数组中查找特定值
int32_t find_2d(int32_t mat[][4], int32_t rows, int32_t cols, int32_t target) {
    for (int32_t i = 0; i < rows; i++) {
        for (int32_t j = 0; j < cols; j++) {
            if (mat[i][j] == target)
                return i * 100 + j;
        }
    }
    return -1;
}

// 素数筛 (Eratosthenes)
int32_t count_primes(int32_t limit) {
    if (limit < 2) return 0;
    if (limit > 100) limit = 100;

    uint8_t sieve[100];
    memset(sieve, 1, sizeof(sieve));
    sieve[0] = sieve[1] = 0;

    for (int32_t i = 2; i * i < limit; i++) {
        if (sieve[i]) {
            for (int32_t j = i * i; j < limit; j += i) {
                sieve[j] = 0;
            }
        }
    }

    int32_t count = 0;
    for (int32_t i = 0; i < limit; i++) {
        if (sieve[i]) count++;
    }
    return count;
}

int main(void) {
    // 函数指针
    int32_t arr[] = {1, 2, 3, 4, 5};
    array_map(arr, 5, double_it);
    int32_t d = dispatch(1, 7);  // square(7) = 49

    // 结构体
    Rect r = {{0, 0}, {10, 20}};
    int32_t area = rect_area(&r);
    Point p = {5, 5};
    int32_t contains = rect_contains(&r, &p);

    Rect r2 = {{5, 5}, {15, 25}};
    int32_t overlaps = rects_overlap(&r, &r2);

    // goto cleanup
    int32_t res = resource_init(3);

    // 向量
    int32_t va[] = {1, 2, 3, 4, 5, 6};
    int32_t vb[] = {6, 5, 4, 3, 2, 1};
    int32_t dot = dot_product(va, vb, 6);

    // 二维搜索
    int32_t mat[3][4] = {{1,2,3,4},{5,6,7,8},{9,10,11,12}};
    int32_t found = find_2d(mat, 3, 4, 7);

    // 素数筛
    int32_t primes = count_primes(50);

    return arr[0] + d + area + contains + overlaps + res + dot + found + primes;
}
