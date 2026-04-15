// case8_state_machine.c — 状态机 + 有限自动机模式
// Tests: enum-driven state machine, string parsing, computed goto-like

#include <stdint.h>
#include <string.h>

// ── 简单状态机: 协议解析 ──────────────────────────────────────

typedef enum {
    STATE_IDLE,
    STATE_HEADER,
    STATE_BODY,
    STATE_CHECKSUM,
    STATE_ERROR,
    STATE_DONE
} State;

typedef struct {
    State state;
    int32_t header_len;
    int32_t body_len;
    uint8_t checksum;
    int32_t bytes_read;
} Parser;

void parser_init(Parser *p) {
    p->state = STATE_IDLE;
    p->header_len = 0;
    p->body_len = 0;
    p->checksum = 0;
    p->bytes_read = 0;
}

// 状态机驱动的字节解析器
int32_t parser_feed(Parser *p, uint8_t byte) {
    switch (p->state) {
        case STATE_IDLE:
            if (byte == 0xAA) {  // 同步字节
                p->state = STATE_HEADER;
                p->bytes_read = 0;
            }
            break;

        case STATE_HEADER:
            if (p->bytes_read == 0) {
                p->header_len = byte;
                p->bytes_read++;
            } else if (p->bytes_read == 1) {
                p->body_len = byte;
                p->bytes_read++;
                if (p->body_len > 0) {
                    p->state = STATE_BODY;
                    p->bytes_read = 0;
                } else {
                    p->state = STATE_CHECKSUM;
                }
            }
            break;

        case STATE_BODY:
            p->checksum ^= byte;
            p->bytes_read++;
            if (p->bytes_read >= p->body_len) {
                p->state = STATE_CHECKSUM;
            }
            break;

        case STATE_CHECKSUM:
            if (byte == p->checksum) {
                p->state = STATE_DONE;
                return 1;  // 成功
            } else {
                p->state = STATE_ERROR;
                return -1; // 校验失败
            }

        case STATE_ERROR:
        case STATE_DONE:
            // 终态，不再处理
            break;
    }
    return 0;  // 继续
}

// ── 手写词法分析器 (简单整数表达式) ────────────────────────────

typedef enum {
    TOK_NUM,
    TOK_PLUS,
    TOK_MINUS,
    TOK_MUL,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_END,
    TOK_ERR,
} TokenType;

typedef struct {
    TokenType type;
    int32_t value;
} Token;

// 跳过空白
const char *skip_ws(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n')
        s++;
    return s;
}

// 词法分析: 返回下一个 token
Token next_token(const char **input) {
    const char *s = skip_ws(*input);
    Token tok = {TOK_END, 0};

    if (*s == '\0') {
        *input = s;
        return tok;
    }

    if (*s >= '0' && *s <= '9') {
        int32_t val = 0;
        while (*s >= '0' && *s <= '9') {
            val = val * 10 + (*s - '0');
            s++;
        }
        tok.type = TOK_NUM;
        tok.value = val;
        *input = s;
        return tok;
    }

    switch (*s) {
        case '+': tok.type = TOK_PLUS; break;
        case '-': tok.type = TOK_MINUS; break;
        case '*': tok.type = TOK_MUL; break;
        case '(': tok.type = TOK_LPAREN; break;
        case ')': tok.type = TOK_RPAREN; break;
        default: tok.type = TOK_ERR; break;
    }
    *input = s + 1;
    return tok;
}

// ── 递归下降解析器 (计算结果) ───────────────────────────────

// Forward declarations
int32_t parse_expr(const char **input);
int32_t parse_term(const char **input);
int32_t parse_factor(const char **input);

int32_t parse_factor(const char **input) {
    const char *saved = *input;
    Token tok = next_token(input);
    if (tok.type == TOK_NUM)
        return tok.value;
    if (tok.type == TOK_LPAREN) {
        int32_t val = parse_expr(input);
        next_token(input); // consume ')'
        return val;
    }
    if (tok.type == TOK_MINUS) {
        return -parse_factor(input);
    }
    *input = saved;
    return 0;
}

int32_t parse_term(const char **input) {
    int32_t left = parse_factor(input);
    for (;;) {
        const char *saved = *input;
        Token tok = next_token(input);
        if (tok.type == TOK_MUL) {
            left *= parse_factor(input);
        } else {
            *input = saved;
            break;
        }
    }
    return left;
}

int32_t parse_expr(const char **input) {
    int32_t left = parse_term(input);
    for (;;) {
        const char *saved = *input;
        Token tok = next_token(input);
        if (tok.type == TOK_PLUS)
            left += parse_term(input);
        else if (tok.type == TOK_MINUS)
            left -= parse_term(input);
        else {
            *input = saved;
            break;
        }
    }
    return left;
}

// ── 多层嵌套条件 + 循环 ────────────────────────────────────

int32_t matrix_trace(int32_t mat[4][4], int32_t n) {
    int32_t trace = 0;
    for (int32_t i = 0; i < n && i < 4; i++) {
        trace += mat[i][i];
    }
    return trace;
}

int32_t find_saddle_point(int32_t mat[4][4], int32_t rows, int32_t cols) {
    for (int32_t i = 0; i < rows; i++) {
        // 找行最小值
        int32_t row_min = mat[i][0];
        int32_t min_col = 0;
        for (int32_t j = 1; j < cols; j++) {
            if (mat[i][j] < row_min) {
                row_min = mat[i][j];
                min_col = j;
            }
        }
        // 检查是否为列最大值
        int32_t is_col_max = 1;
        for (int32_t k = 0; k < rows; k++) {
            if (mat[k][min_col] > row_min) {
                is_col_max = 0;
                break;
            }
        }
        if (is_col_max) {
            return i * 10 + min_col;
        }
    }
    return -1;
}

int main(void) {
    // 状态机
    Parser p;
    parser_init(&p);
    uint8_t packet[] = {0xAA, 2, 3, 0x11, 0x22, 0x33, 0x11^0x22^0x33};
    int32_t result = 0;
    for (int i = 0; i < 7; i++) {
        result = parser_feed(&p, packet[i]);
    }

    // 词法分析 + 解析
    const char *expr = "3 + 4 * (2 - 1)";
    int32_t eval_result = parse_expr(&expr);

    // 矩阵
    int32_t mat[4][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12},
        {13, 14, 15, 16}
    };
    int32_t tr = matrix_trace(mat, 4);
    int32_t sp = find_saddle_point(mat, 4, 4);

    return result + eval_result + tr + sp;
}
