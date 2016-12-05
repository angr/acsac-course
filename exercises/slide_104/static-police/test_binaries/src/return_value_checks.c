#include <stdio.h>

int return_1()
{
    printf("This function returns 1.\n");

    return 1;
}

int main()
{
    int r = return_1();
    if (r != 1)
    {
        printf("The function does not return 1.\n");
    }
    else
    {
        printf("The function returns 1.\n");
    }
}

