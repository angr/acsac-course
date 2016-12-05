#include <stdio.h>
#include <unistd.h>

int heaven(char* buf, int bytes_to_read)
{
    printf("Reading %d bytes...\n", bytes_to_read);
    return fread(buf, 1, bytes_to_read, stdin);
}

int hell(char* buf, int bytes_to_read)
{
    printf("Reading %d bytes... but you cannot do whatever you want in hell!\n", bytes_to_read);
    bytes_to_read = 10;
    return fread(buf, 1, bytes_to_read, stdin);
}

int main()
{
    char buf[128];
    unsigned int choice;
    unsigned char size;

    puts("PICK YOUR FATE:");
    scanf("%d", &choice);

    if (choice == 0) {
        puts("HEAVEN!");
        size = heaven(buf, 512);
    } else {
        puts("HELL...");
        size = hell(buf, 256);
    }

    printf("Received: %d bytes.\n", size);
}
