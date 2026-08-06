#include <stdio.h>
extern int amo_add(int *p, int v);
extern void barrier(void);

extern int cas_strong(int *p, int expected, int desired);
extern int cas_weak(int *p, int expected, int desired);

extern long simple_add(long,long);
extern int  addw_sx(int,int);
extern int  load_off(const int*);
extern void store_off(int*,int);
extern long sllw_neg(long);


static void test_intblock(void) {
    printf("simple_add 0x%lx\n", simple_add(0x1, 0x100000000L));
    printf("addw_sx    0x%x\n",  addw_sx(0x7fffffff, 1));      // 溢出符号扩展
    int arr[8] = {0,1,2,3,4,5,6,7};
    printf("load_off   %d\n", load_off(arr));                  // arr[2]=2
    store_off(arr, 42);
    printf("after_store %d\n", arr[0]);
    printf("sllw_neg   0x%lx\n", sllw_neg(0x80000000L));       // 应为
                                                                // (int64)(int32)(0)=0
}

static void test_cas(void) {
    int x, old;

    x = 100;
    old = cas_strong(&x, 100, 200);
    printf("strong-hit  old=%d x=%d\n", old, x);

    x = 100;
    old = cas_strong(&x, 0, 200);
    printf("strong-miss old=%d x=%d\n", old, x);

    x = 100;
    old = cas_weak(&x, 100, 200);
    printf("weak-hit    old=%d x=%d\n", old, x);

    x = 100;
    old = cas_weak(&x, 0, 200);
    printf("weak-miss   old=%d x=%d\n", old, x);
}

int main(void){
    int x = 100;
    for (int i = 0; i < 5; ++i) {
        int old = amo_add(&x, i);
        barrier();
        printf("old=%d x=%d\n", old, x);
    }

    test_cas();
    return 0;
}