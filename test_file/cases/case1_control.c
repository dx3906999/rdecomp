#include <stdio.h>

int classify(int x) {
    if (x < 0) {
        return -1;
    }
    if (x == 0) {
        return 0;
    }
    if (x < 10) {
        return 1;
    }
    return 2;
}

int sum_to_n(int n) {
    int sum = 0;
    for (int i = 0; i <= n; ++i) {
        sum += i;
    }
    return sum;
}

int main(void) {
    volatile int a = classify(7);
    volatile int b = sum_to_n(9);
    return a + b;
}
