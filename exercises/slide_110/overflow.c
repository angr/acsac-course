#include <stdio.h>
#include <unistd.h>

int main()
{
	char buf[128];
	unsigned char size;

	printf("How much to read? ");
	scanf("%hhd\n", &size);

	if (size > 128) printf("Uh oh, reading up to %d bytes...\n", size);
	printf("Received: %d bytes.\n", fread(buf, 1, size, stdin));
}
