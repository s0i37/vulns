#include <stdio.h>
#include <stdlib.h>
#include <signal.h>


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

/* UMR - Uninitialized Memory Read (uninitialized access) */
int test_UMR_stack(void)
{
	int a;
	int b;
	printf("try UMR_stack\n");
	b = a;
	if(b) /* need some action with uninitialized data */
		return 1;
	else
		return 0;
}

/* UMR - Uninitialized Memory Read (uninitialized access) */
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
	if(a) /* need some action with uninitialized data */
		return 1;
	else
		return 0;
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
/* warning: function returns address of local variable [-Wreturn-local-addr] */
char * __test_UAR(void)
{
	char buf[4];
	char *ptr;
	buf[0] = 'a';
	ptr = &buf;
	return ptr;
}
void __test_UAR_rewrite(void)
{
	char buf[8];
	for(unsigned int i = 0; i < 8; i++)
		buf[i] = '\x00';
}
int test_UAR(void)
{
	char a;
	char *ptr;
	printf("try UAR\n");
	ptr = __test_UAR();
	__test_UAR_rewrite();
	a = ptr[0];
	if(a)
		return 1;
	else
		return 0;
}

/* IOF - Integer overflow (signed) */
int test_IoF()
{
	signed int a = 0x7fffffff;
	printf("try IoF\n");
	a++;
	if(a > 0)
		return 1;
	else
		return 0;
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
	char in_buf[0x100];		// rbp-0x110
	char out_buf[0x120]; 	// rbp-0x230
	FILE *f; 				// rbp-0x10
	unsigned int i; 		// rbp-0x4
	printf("try OOB_read_stack\n");
	for( i = 0; i < 0x100; i++ )		// init stack area
		in_buf[i] = '\x00';
	for( i = 0; i < 0x120; i++ ) 		// behind stack frame
		out_buf[i] = in_buf[i];
	f = fopen("/tmp/OOB_read_stack_leak.txt","wb");
	fwrite(out_buf, 0x120, 1, f);
	fclose(f);
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
			*(int *)ptr = (int)ptr;
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

void test_race_condition(void)
{
	/* TODO */
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
/*      					 				   Windows			Linux 				DrMemory	clang 	*/
/*1*/	//test_OOB_write_heap();			/* gflags			libdislocator		+			ASAN 	*/	/*RCE*/
/*2*/	//test_UAF();						/* gflags			libdislocator		+			ASAN 	*/	/*RCE*/
/*3*/	//test_DoubleFree(); 				/* --				crash 				 					*/	/*RCE*/
/*4*/	//test_OOB_write_stack(); 			/* crash 			crash 				 					*/	/*RCE*/

/*5*/	//test_OOB_read_heap();				/* gflags			libdislocator		+			ASAN 	*/	/*mem leak*/
/*6*/	//test_OOB_read_stack();			/* -				-					+			ASAN 	*/	/*mem leak*/

/*7*/	//return test_IoF();				/* -				-					-			UBSAN	*/	/*undefined*/
/*8*/	//test_UMR_stack();					/* - 				-					+			MSAN	*/	/*undefined*/
/*9*/	//test_UMR_heap();					/* -				-					+			MSAN	*/	/*undefined*/
/*10*/	//return test_UAR();				/* -				-	 				+(x32)		- 		*/	/*undefined*/
/*11*/	//test_race_condition();			/* -				-										*/	/*undefined*/

/*12*/	//test_UWC();						/* -				libdislocator		-			- 		*/	/*DoS*/
/*13*/	//test_MemoryLeak();				/* procexp 			htop				+			ASAN 	*/ 	/*DoS*/


/*14*/	//test_SoF(); 						/* crash 			crash 				 					*/ 	/*DoS*/
/*15*/	//test_HoF(); 						/* timeout			timeout				 					*/ 	/*DoS*/


/*16*/	//test_Format_string("%s"); 		/* crash 			crash 				 					*/ 	/*RCE*/	

#if defined(_WIN64) || defined(_WIN32)
	} __except(1) { printf("[*] exception\n"); }
#endif
	return 0;
}