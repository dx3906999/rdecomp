#include <stdio.h>

int helper(int a, int b) {
    return (a * 3 + b) ^ 0x55;
}

int pipeline(int a, int b) {
    int t1 = helper(a, b);
    int t2 = helper(t1, a - b);
    if ((t2 & 1) != 0) {
        return t2 + b;
    }
    return t2 - a;
}

int main(void) {
    volatile int out = pipeline(11, 4);
    return out;
}
