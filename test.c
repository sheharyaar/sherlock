#include <stdio.h>
#include <unistd.h>

/* Simple program to test my tracer implementation */
int main()
{
	printf("pid: %d\n", getpid());
	sleep(7);
	printf("Hello world!\n");
	return 0;
}
