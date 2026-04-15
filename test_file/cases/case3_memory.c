#include <stdio.h>

typedef struct Pair {
    int left;
    int right;
} Pair;

int update_pair(Pair* p, int x) {
    p->left += x;
    p->right = p->left * 2;
    return p->right;
}

int stack_mix(int x) {
    int arr[4] = {1, 2, 3, 4};
    int y = arr[x & 3];
    return y + x * 5;
}

int main(void) {
    Pair p = {3, 8};
    volatile int a = update_pair(&p, 7);
    volatile int b = stack_mix(6);
    return a + b;
}
