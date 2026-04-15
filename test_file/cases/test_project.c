// test_project.c — test case for project cache + cross-platform decompilation
// Compile:
//   Linux x64:  gcc -O0 -o test_project_linux64 test_project.c
//   Linux x86:  gcc -m32 -O0 -o test_project_linux32 test_project.c
//   Win x64:    cl /Od /Fe:test_project_win64.exe test_project.c
//   Win x86:    cl /Od /Fe:test_project_win32.exe test_project.c (from x86 prompt)

#include <stdio.h>
#include <string.h>

int fibonacci(int n) {
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return b;
}

int sum_array(int *arr, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) {
        total += arr[i];
    }
    return total;
}

void reverse_string(char *s) {
    int len = strlen(s);
    for (int i = 0; i < len / 2; i++) {
        char tmp = s[i];
        s[i] = s[len - 1 - i];
        s[len - 1 - i] = tmp;
    }
}

int classify(int x) {
    if (x > 100) return 3;
    if (x > 50)  return 2;
    if (x > 0)   return 1;
    if (x == 0)  return 0;
    return -1;
}

int main(void) {
    int fib10 = fibonacci(10);
    int arr[] = {1, 2, 3, 4, 5};
    int s = sum_array(arr, 5);

    char buf[32];
    strcpy(buf, "hello");
    reverse_string(buf);

    int c = classify(fib10);
    return c + s;
}
