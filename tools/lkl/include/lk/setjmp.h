#ifndef _LK_SETJMP_H
#define _LK_SETJMP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lk/sys/types.h>

#include <lk/arch/x86.h>

typedef struct __jmp_buf_tag {
	__jmp_buf __jb;
	unsigned long __fl;
	unsigned long __ss[128/sizeof(long)];
} jmp_buf[1];

int setjmp(jmp_buf);
_Noreturn void longjmp(jmp_buf, int);

#define setjmp setjmp

#ifdef __cplusplus
}
#endif

#endif
