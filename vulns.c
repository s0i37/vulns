#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int was_tested_ACCESS_VIOLATION = 0;
int test_ACCESS_VIOLATION(void)
{
	if(was_tested_ACCESS_VIOLATION)
		return
	was_tested_ACCESS_VIOLATION = 1;

	printf("try ACCESS_VIOLATION\n");
	return * (int *)0xAABBCCDD;
}

void test_MemoryLeak(void)
{
	void * ptr;
	printf("try MemoryLeak\n");
	ptr = malloc(0x1000);
}

/* UWC - Use Without Check */
void test_UWC(void)
{
	void * ptr;
	printf("try UWC\n");
	ptr = malloc(0x1000);
	*((char *)ptr) = 'A';
	if(ptr)
		free(ptr);
}

/* UMR - Uninitialized Memory Read */
void test_UMR_stack(void)
{
	int a;
	int b;
	printf("try UMR_stack\n");
	b = a;
}

/* UMR - Uninitialized Memory Read */
int test_UMR_heap(void)
{
	int a;
	void *ptr;
	printf("try UMR_heap\n");
	ptr = malloc(10);
	if(!ptr)
		return 0;
	a = ((int *)ptr)[0];
	free(ptr);
	return a;
}

void test_DoubleFree(void)
{
	void * ptr;
	printf("try DoubleFree\n");
	ptr = malloc(0x1000);
	if(! ptr)
		return;
	free(ptr);
	free(ptr);
}

/* dangling pointer */
void test_UAF(void)
{
	void * ptr;
	printf("try UAF\n");
	ptr = malloc(0x1000);
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
	printf("try UAR\n");
	a = __test_UAR()[0];
}

/* IOF - Integer overflow */
int test_IoF()
{
	signed int a = 0x7fffffff;
	printf("try IoF\n");
	return ++a;
}

/* OOB - Out Of Bounds read heap */
int was_tested_OOB_read_heap = 0;
void test_OOB_read_heap()
{
	void *ptr;
	unsigned int i;
	char a;
	if(was_tested_OOB_read_heap)
		return;
	was_tested_OOB_read_heap = 1;
	printf("try OOB_read_heap\n");
	ptr = malloc(0x1000);
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
	void *ptr;
	unsigned int i;
	printf("try OOB_write_heap\n");
	ptr = malloc(0x1000);
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
	printf("try OOB_read_stack\n");
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
	printf("try OOB_write_stack\n");
	for( i = 0; i < 0x104; i++ )
		( (char *) buf )[i] = '\x41';
}

/* HOF - Heap Overflow */
void test_HoF(void)
{
	void * ptr;
	printf("try HoF\n");
	do
	{
		ptr = malloc(65535);
		if(ptr)
			* (int *)ptr = ptr;
	}
	while(ptr);
}

/* SOF - Stack Overflow */
void test_SoF(void)
{
	char buf[0x1000];
	printf("try SoF\n");
	test_SoF();
}

void test_Format_string(char * fmt)
{
	printf("try Format_string\n");
	printf(fmt);
}

#if defined __linux__
void __on_signal(int signal)
{
	printf("[*] exception\n");
	exit(1);
}
#endif

int main(int a, char ** b)
{
#if defined(_WIN64) || defined(_WIN32)
	__try {
#elif defined(__linux__)
	signal(SIGSEGV , __on_signal);
#endif
/*======non crashable======*/
/*1*/	test_MemoryLeak();					// ASAN
/*2*/	test_UMR_stack();					// ASAN/MSAN
/*3*/	test_UMR_heap();					// MSAN
/*4*/	test_UWC();							// ?SAN
/*5*/	test_UAF();							// ASAN
/*6*/	test_UAR();							// ASAN
/*7*/	test_IoF();  						// UBSAN https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
/*8*/	test_OOB_read_heap();				// ASAN
		test_OOB_write_heap();				// ASAN
		test_OOB_read_stack();				// ASAN

/*======crashable======*/
		test_OOB_write_stack();
/*9*/	test_ACCESS_VIOLATION();
/*10*/	test_SoF();
/*11*/	//test_HoF();

/*======crashable (lin) - non crashable (win)======*/
/*12*/	test_DoubleFree();

/*======special======*/
/*13*/	test_Format_string("%s");
	
/* TODO */							// TSAN  https://github.com/google/sanitizers/wiki/ThreadSanitizerDetectableBugs

#if defined(_WIN64) || defined(_WIN32)
	} __except(1) { printf("[*] exception\n"); }
#endif
	return 0;
}