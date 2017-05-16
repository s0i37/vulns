#include <stdio.h>
#include <string.h>

void test_MemoryLeak(void)
{
	void * ptr = malloc(0x1000);
}

void test_UWC(void)
{
	void * ptr = malloc(0x1000);
	*((char *)ptr) = 'A';
}

int test_Non_init_var(void)
{
	int a;
	return a;
}

void test_DoubleFree(void)
{
	void * ptr = malloc(0x1000);
	if(! ptr)
		return;
	free(ptr);
	free(ptr);
}

void test_UAF(void)
{
	void * ptr = malloc(0x1000);
	if(! ptr)
		return;
	free(ptr);
	( (char *)ptr )[5] = '\x00';
}

void test_BoF_heap(void)
{
	void * ptr = malloc(0x1000);
	unsigned int i;
	if(! ptr)
		return;
	for( i = 0; i < 0x1004; i++ )
		( (char *) ptr )[i] = '\x00';
	free(ptr);
}

void test_OoB(void)
{
	void * ptr = malloc(0x100);
	char a;
	unsigned int i;
	if(! ptr)
		return;
	for( i = 0; i < 0x104; i++ )
		a = ( (char *) ptr )[i];
	free(ptr);
}

void test_BoF_stack(void)
{
	char buf[0x10];
	unsigned int i;
	for( i = 0; i < 0x20; i++ )
		( (char *) buf )[i] = '\x41';
}

void test_HoF(void)
{
	void * ptr;
	do
	{
		ptr = malloc(65535);
	}
	while(ptr);
}

void test_SoF(void)
{
	test_SoF();
}

void test_Format_string(char * fmt)
{
	printf(fmt);
}

int main(int a, char ** b)
{
	test_Non_init_var();
	test_MemoryLeak();
	test_UWC();
	test_UAF();
	test_BoF_heap();
	test_OoB();
	test_Format_string("%s");

	test_DoubleFree();
	test_BoF_stack();
	test_HoF();
	test_SoF();
	return 0;
}