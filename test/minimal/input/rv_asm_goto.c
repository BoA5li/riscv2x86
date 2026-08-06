int rv_asm_goto(int x) {
    __asm__ goto(
        "beqz %0, %l[zero]"
        :
        : "r"(x)
        :
        : zero
    );

    return 1;

zero:
    return 0;
}

int main(void) {
    return rv_asm_goto(0) != 0 || rv_asm_goto(1) != 1;
}