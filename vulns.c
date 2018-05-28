#include <stdio.h>
#include <stdlib.h>
#include <signal.h>


int test_ACCESS_VIOLATION(void)
{
	return * (int *)0xAABBCCDD;
}

void test_MemoryLeak(void)
{
	void * ptr = malloc(0x1000);
}

/* UWC - Use Without Check */
void test_UWC(void)
{
	void * ptr = malloc(0x1000);
	*((char *)ptr) = 'A';
	if(ptr)
		free(ptr);
}

/* UMR - Uninitialized Memory Read */
void test_UMR_stack(void)
{
	int a;
	int b = a;
}

/* UMR - Uninitialized Memory Read */
int test_UMR_heap(void)
{
	int a;
	void *ptr;
	ptr = malloc(10);
	if(!ptr)
		return 0;
	a = ((int *)ptr)[0];
	free(ptr);
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

/* dangling pointer */
void test_UAF(void)
{
	void * ptr = malloc(0x1000);
	if(! ptr)
		return;
	free(ptr);
	( (char *)ptr )[5] = '\x00';
}

/* UAS/UAR - Use After Scope/Return */
char * __test_UAR(void)
{
	char buf[4];
	buf[0] = 'a';
	return (char *)buf;
}
void test_UAR(void)
{
	char a;
	a = __test_UAR()[0];
}

/* IOF - Integer overflow */
int test_IoF()
{
	int a = 0x7fffffff;
	return ++a;
}

/* OOB - Out Of Bounds read heap */
void test_OOB_read_heap(void)
{
	void *ptr = malloc(0x1000);
	unsigned int i;
	char a;
	if(! ptr)
		return;
	for( i = 0; i < 0x1000; i++ )		// init heap area
		( (char *) ptr )[i] = '\x00';
	for( i = 0; i < 0x1004; i++ )
		a = ( (char *) ptr )[i];
	free(ptr);
}

/* OOB - Out Of Bounds write heap */
void test_OOB_write_heap(void)
{
	void *ptr = malloc(0x1000);
	unsigned int i;
	if(! ptr)
		return;
	for( i = 0; i < 0x1004; i++ )
		( (char *) ptr )[i] = '\x00';
	free(ptr);
}

/* OOB - Out Of Bounds read stack */
void test_OOB_read_stack(void)
{
	char buf[0x100];
	char a;
	unsigned int i;
	for( i = 0; i < 0x100; i++ )		// init stack area
		( (char *) buf )[i] = '\x00';
	for( i = 0; i < 0x104; i++ )
		a = ( (char *) buf )[i];
}

/* OOB - Out Of Bounds write stack */
void test_OOB_write_stack(void)
{
	char buf[0x100];
	unsigned int i;
	for( i = 0; i < 0x104; i++ )
		( (char *) buf )[i] = '\x41';
}

/* HOF - Heap Overflow */
void test_HoF(void)
{
	void * ptr;
	do
	{
		ptr = malloc(65535);
	}
	while(ptr);
}

/* SOF - Stack Overflow */
void test_SoF(void)
{
	char a[0x1000];
	test_SoF();
}

void test_Format_string(char * fmt)
{
	printf(fmt);
}


void __on_signal(int signal)
{
	printf("done\n");
	exit(1);
}

int main(int a, char ** b)
{
	signal(SIGSEGV , __on_signal);
	/* non crashable */
	test_MemoryLeak();					// ASAN
	test_UMR_stack();					// ASAN/MSAN
	test_UMR_heap();					// MSAN
	test_UWC();							// ?SAN
	test_UAF();							// ASAN
	test_UAR();							// ASAN
	test_IoF();  						// UBSAN https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
	test_OOB_read_heap();				// ASAN
	test_OOB_write_heap();				// ASAN
	test_OOB_read_stack();				// ASAN
	/* crashable */
	test_OOB_write_stack();
	/* TODO */							// TSAN  https://github.com/google/sanitizers/wiki/ThreadSanitizerDetectableBugs
	test_ACCESS_VIOLATION();
	return 0;
	/* non crashable (win) - crashable (lin) */
	test_DoubleFree();
	/* crashable */
	test_HoF();
	test_SoF();

	/* special */
	test_Format_string("%s");
	return 0;
}