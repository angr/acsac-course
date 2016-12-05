#include <stdio.h>

int return_0()
{
    /* This function always returns 0 */
    printf("This function always returns 0.\n");
    return 0;
}

int return_1()
{
    /* This function always returns 1 */
    printf("This function always returns 1.\n");
    return 1;
}

int return_2()
{
    /* This function always returns 2 */
    printf("This function always returns 2.\n");
    return 2;
}

int main()
{
    int r;

    r = return_0();
    r = return_1();
    r = return_2();
}
