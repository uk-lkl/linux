#include <lk/sys/types.h>
#include <lk/arch/x86.h>
#include <lk/arch/fpu.h>
#include <lk/kernel/thread.h>
#include <lk/kernel/timer.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define ROUNDDOWN(a, b) ((a) & ~((b)-1))

struct thread *_current_thread = NULL;
int ints_enabled = 0;
int fiqs_enabled = 0;

static void initial_thread_func(void)
{
    int ret;

    /* release the thread lock that was implicitly held across the reschedule */
    spin_unlock(&thread_lock);

    thread_t *ct = get_current_thread();
    ret = ct->entry(ct->arg);

    thread_exit(ret);
}

void arch_thread_initialize(struct thread* t) {
    vaddr_t stack_top = (vaddr_t)t->stack + t->stack_size;

    stack_top = ROUNDDOWN(stack_top, 16);

    stack_top -= 8;
    struct x86_64_context_switch_frame *frame = (struct x86_64_context_switch_frame *)(stack_top);

    frame--;
    memset(frame, 0, sizeof(*frame));

    frame->rip = (vaddr_t)&initial_thread_func;
    frame->rflags = 0x3002;

    fpu_init_thread_states(t);

    t->arch.sp = (vaddr_t)frame;
}

void arch_context_switch(struct thread *oldthread, struct thread *newthread) {
    fpu_context_switch(oldthread, newthread);

    x86_64_context_switch(&oldthread->arch.sp, newthread->arch.sp);
}

void arch_idle(void) {
    thread_preempt();
}

void arch_dump_thread(thread_t *t) {
}

#if 0
void timer_initialize(lk_timer_t *timer) {
    assert(0);
}
void timer_set_oneshot(lk_timer_t *timer, lk_time_t delay, timer_callback callback, void *arg) {
    assert(0);
}
void timer_cancel(lk_timer_t *timer) {
    assert(0);
}
void timer_set_periodic(lk_timer_t *timer, lk_time_t period, timer_callback callback, void *arg) {
    assert(0);
}
#endif
