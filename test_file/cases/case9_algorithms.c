// case9_algorithms.c — 经典算法
// Tests: hash table, string algorithms, graph BFS, dynamic programming

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ── 简单哈希表 (开放寻址) ────────────────────────────────────

#define HT_SIZE 16
#define HT_EMPTY  -1
#define HT_DELETED -2

typedef struct {
    int32_t keys[HT_SIZE];
    int32_t vals[HT_SIZE];
} HashTable;

void ht_init(HashTable *ht) {
    for (int i = 0; i < HT_SIZE; i++) {
        ht->keys[i] = HT_EMPTY;
        ht->vals[i] = 0;
    }
}

uint32_t ht_hash(int32_t key) {
    uint32_t h = (uint32_t)key;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = (h >> 16) ^ h;
    return h % HT_SIZE;
}

int32_t ht_insert(HashTable *ht, int32_t key, int32_t val) {
    uint32_t idx = ht_hash(key);
    for (int i = 0; i < HT_SIZE; i++) {
        uint32_t probe = (idx + i) % HT_SIZE;
        if (ht->keys[probe] == HT_EMPTY || ht->keys[probe] == HT_DELETED) {
            ht->keys[probe] = key;
            ht->vals[probe] = val;
            return 1;
        }
        if (ht->keys[probe] == key) {
            ht->vals[probe] = val;  // 覆盖
            return 1;
        }
    }
    return 0;  // full
}

int32_t ht_get(HashTable *ht, int32_t key, int32_t *out_val) {
    uint32_t idx = ht_hash(key);
    for (int i = 0; i < HT_SIZE; i++) {
        uint32_t probe = (idx + i) % HT_SIZE;
        if (ht->keys[probe] == HT_EMPTY)
            return 0;  // not found
        if (ht->keys[probe] == key) {
            *out_val = ht->vals[probe];
            return 1;
        }
    }
    return 0;
}

// ── 字符串算法 ────────────────────────────────────────────────

// KMP 前缀函数
void compute_prefix(const char *pattern, int32_t *prefix, int32_t m) {
    prefix[0] = 0;
    int32_t k = 0;
    for (int32_t q = 1; q < m; q++) {
        while (k > 0 && pattern[k] != pattern[q])
            k = prefix[k - 1];
        if (pattern[k] == pattern[q])
            k++;
        prefix[q] = k;
    }
}

// KMP 搜索 — 返回首次匹配位置，不存在返回 -1
int32_t kmp_search(const char *text, const char *pattern) {
    int32_t n = strlen(text);
    int32_t m = strlen(pattern);
    if (m == 0) return 0;
    if (m > n) return -1;

    int32_t prefix[64]; // max pattern length
    if (m > 64) return -1;
    compute_prefix(pattern, prefix, m);

    int32_t q = 0;
    for (int32_t i = 0; i < n; i++) {
        while (q > 0 && pattern[q] != text[i])
            q = prefix[q - 1];
        if (pattern[q] == text[i])
            q++;
        if (q == m)
            return i - m + 1;
    }
    return -1;
}

// 字符串是否为回文
int32_t is_palindrome(const char *s) {
    int32_t len = strlen(s);
    int32_t lo = 0, hi = len - 1;
    while (lo < hi) {
        if (s[lo] != s[hi])
            return 0;
        lo++;
        hi--;
    }
    return 1;
}

// ── 动态规划 ──────────────────────────────────────────────────

// 最长公共子序列长度
int32_t lcs_length(const char *a, const char *b) {
    int32_t m = strlen(a);
    int32_t n = strlen(b);
    // 用滚动数组优化空间
    int32_t prev[64] = {0};
    int32_t curr[64] = {0};
    if (n > 63) n = 63;

    for (int32_t i = 1; i <= m; i++) {
        for (int32_t j = 1; j <= n; j++) {
            if (a[i-1] == b[j-1])
                curr[j] = prev[j-1] + 1;
            else
                curr[j] = (prev[j] > curr[j-1]) ? prev[j] : curr[j-1];
        }
        for (int32_t j = 0; j <= n; j++) {
            prev[j] = curr[j];
            curr[j] = 0;
        }
    }
    return prev[n];
}

// 0-1 背包问题
int32_t knapsack(int32_t weights[], int32_t values[], int32_t n, int32_t capacity) {
    int32_t dp[64] = {0};
    if (capacity > 63) capacity = 63;

    for (int32_t i = 0; i < n; i++) {
        for (int32_t w = capacity; w >= weights[i]; w--) {
            int32_t with_item = dp[w - weights[i]] + values[i];
            if (with_item > dp[w])
                dp[w] = with_item;
        }
    }
    return dp[capacity];
}

// ── 简单图 BFS ────────────────────────────────────────────────

#define MAX_NODES 8
#define MAX_EDGES 16

typedef struct {
    int32_t adj[MAX_NODES][MAX_NODES];
    int32_t node_count;
} Graph;

void graph_init(Graph *g, int32_t nodes) {
    g->node_count = nodes;
    for (int i = 0; i < MAX_NODES; i++)
        for (int j = 0; j < MAX_NODES; j++)
            g->adj[i][j] = 0;
}

void graph_add_edge(Graph *g, int32_t u, int32_t v) {
    if (u < MAX_NODES && v < MAX_NODES) {
        g->adj[u][v] = 1;
        g->adj[v][u] = 1;
    }
}

// BFS 最短路径 (无权图)
int32_t bfs_shortest(Graph *g, int32_t start, int32_t end) {
    if (start == end) return 0;

    int32_t visited[MAX_NODES] = {0};
    int32_t dist[MAX_NODES] = {0};
    int32_t queue[MAX_NODES];
    int32_t front = 0, rear = 0;

    visited[start] = 1;
    queue[rear++] = start;

    while (front < rear) {
        int32_t cur = queue[front++];
        for (int32_t i = 0; i < g->node_count; i++) {
            if (g->adj[cur][i] && !visited[i]) {
                visited[i] = 1;
                dist[i] = dist[cur] + 1;
                if (i == end) return dist[i];
                queue[rear++] = i;
            }
        }
    }
    return -1;  // unreachable
}

int main(void) {
    // 哈希表
    HashTable ht;
    ht_init(&ht);
    ht_insert(&ht, 42, 100);
    ht_insert(&ht, 17, 200);
    int32_t val;
    int32_t found = ht_get(&ht, 42, &val);

    // KMP
    int32_t pos = kmp_search("hello world", "world");

    // 回文
    int32_t pal = is_palindrome("racecar");

    // LCS
    int32_t lcs = lcs_length("ABCBDAB", "BDCAB");

    // 背包
    int32_t w[] = {2, 3, 4, 5};
    int32_t v[] = {3, 4, 5, 6};
    int32_t ks = knapsack(w, v, 4, 10);

    // 图
    Graph g;
    graph_init(&g, 5);
    graph_add_edge(&g, 0, 1);
    graph_add_edge(&g, 1, 2);
    graph_add_edge(&g, 2, 3);
    graph_add_edge(&g, 3, 4);
    graph_add_edge(&g, 0, 3);
    int32_t sp = bfs_shortest(&g, 0, 4);

    return found + pos + pal + lcs + ks + sp;
}
