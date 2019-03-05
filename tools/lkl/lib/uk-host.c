#include <uk/assert.h>
#include <uk/config.h>
#include <uk/plat/time.h>
#include <lk/kernel/semaphore.h>
#include <lk/kernel/mutex.h>
#include <lk/kernel/thread.h>
#include <lk/kernel/event.h>
#include <lk/kernel/timer.h>

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <lkl_host.h>
#include "iomem.h"
#include "jmp_buf.h"

static void print(const char *str, int len)
{
	int ret __attribute__((unused));

	ret = write(STDOUT_FILENO, str, len);
}

struct lkl_mutex {
       int recursive;
       mutex_t mutex;
       semaphore_t sem;
};

struct lkl_sem {
        semaphore_t sem;
};

struct lkl_tls_key {
        uint key;
};

#define WARN_UNLESS(exp) do {						\
		if (exp < 0)						\
			lkl_printf("%s: %d\n", #exp, errno);	        \
	} while (0)

static struct lkl_sem *lkl_sem_alloc(int count)
{
	struct lkl_sem *sem;

	sem = malloc(sizeof(*sem));
	if (!sem)
		return NULL;

        sem_init(&sem->sem, count);

	return sem;
}

static void lkl_sem_free(struct lkl_sem *sem)
{
        sem_destroy(&sem->sem);
	free(sem);
}

static void lkl_sem_up(struct lkl_sem *sem)
{
        sem_post(&sem->sem, 1);
}

static void lkl_sem_down(struct lkl_sem *sem)
{
        int err;
        do {
                thread_yield();
                err = sem_wait(&sem->sem);
        } while (err < 0);
}

static struct lkl_mutex *lkl_mutex_alloc(int recursive)
{
	struct lkl_mutex *_mutex = malloc(sizeof(struct lkl_mutex));

        if (!_mutex)
                return NULL;

        if (recursive)
                mutex_init(&_mutex->mutex);
        else
                sem_init(&_mutex->sem, 1);
        _mutex->recursive = recursive;

	return _mutex;
}

static void lkl_mutex_lock(struct lkl_mutex *mutex)
{
        int err;

        if (mutex->recursive) {
                if (!is_mutex_held(&mutex->mutex))
                        mutex_acquire(&mutex->mutex);
        } else {
                do {
                        thread_yield();
                        err = sem_wait(&mutex->sem);
                } while (err < 0);
        }
}

static void lkl_mutex_unlock(struct lkl_mutex *_mutex)
{
        if (_mutex->recursive) {
                if (!is_mutex_held(&_mutex->mutex))
                        mutex_release(&_mutex->mutex);
        } else
                sem_post(&_mutex->sem, 1);
}

static void lkl_mutex_free(struct lkl_mutex *_mutex)
{
        if (_mutex->recursive)
                mutex_destroy(&_mutex->mutex);
        else
                sem_destroy(&_mutex->sem);

	free(_mutex);
}

static volatile lk_time_t ticks = 0;

static void lkl_timer_callback(void *arg __unused)
{
        ticks += UKPLAT_TIME_TICK_NSEC;
        if (thread_timer_tick()==INT_RESCHEDULE)
                thread_preempt();
}

lk_time_t current_time(void)
{
        return ukplat_monotonic_clock();
}

lk_bigtime_t current_time_hires(void)
{
        return (lk_bigtime_t)ukplat_monotonic_clock() * 1000;
}

void lkl_thread_init(void)
{
        thread_init_early();
        thread_init();
        timer_init();
        thread_create_idle();
        thread_set_priority(DEFAULT_PRIORITY);
        ukplat_timer_callback_register(lkl_timer_callback, NULL);
}

static lkl_thread_t lkl_thread_create(void (*fn)(void *), void *arg)
{
        thread_t *thread = thread_create("lkl", (int (*)(void *))fn, arg, DEFAULT_PRIORITY, 2*1024*1024);
        if (!thread) {
                return 0;
        } else {
                thread_resume(thread);
                return (lkl_thread_t) thread;
        }
}

static void lkl_thread_detach(void)
{
        thread_detach(get_current_thread());
}

static void lkl_thread_exit(void)
{
        thread_exit(0);
}

static int lkl_thread_join(lkl_thread_t tid)
{
        if (thread_join((thread_t *)tid, NULL, INFINITE_TIME))
		return -1;
	else
		return 0;
}

static lkl_thread_t lkl_thread_self(void)
{
        return (lkl_thread_t)get_current_thread();
}

static int lkl_thread_equal(lkl_thread_t a, lkl_thread_t b)
{
        return a==b;
}

static struct lkl_tls_key *tls_alloc(void (*destructor)(void *))
{
	struct lkl_tls_key *ret = malloc(sizeof(struct lkl_tls_key));
        memset(ret, 0, sizeof(struct lkl_tls_key));
        get_current_thread()->tls[ret->key] = (uintptr_t)ret;

	return ret;
}

static void tls_free(struct lkl_tls_key *key)
{
        get_current_thread()->tls[key->key] = (uintptr_t)NULL;

	free(key);
}

static int tls_set(struct lkl_tls_key *key, void *data)
{
        get_current_thread()->tls[key->key] = (uintptr_t)data;

	return 0;
}

static void *tls_get(struct lkl_tls_key *key)
{
        return (void *)get_current_thread()->tls[key->key];
}

static unsigned long long time_ns(void)
{
        return current_time()*1000000UL;
}

static void *lkl_timer_alloc(void (*fn)(void *), void *arg)
{
        lk_timer_t *timer = malloc(sizeof(lk_timer_t));

        if (!timer) {
                lkl_printf("malloc: %d\n", errno);
                return NULL;
        }

        timer_initialize(timer);

        timer->callback = fn;
        timer->arg = arg;

        return (void *)timer;
}

static int lkl_timer_set_oneshot(void *_timer, unsigned long ns)
{
        lk_timer_t *timer = _timer;
        lk_time_t delay = ns / 1000000;

        timer_set_oneshot(timer, delay, timer->callback, timer->arg);

        return 0;
}

static void lkl_timer_free(void *_timer)
{
        lk_timer_t *timer = _timer;

        timer_cancel(timer);
}

static void lkl_panic(void)
{
	UK_ASSERT(0);
}

static long _gettid(void)
{
        return (long)get_current_thread();
}

struct lkl_host_operations lkl_host_ops = {
	.panic = lkl_panic,
	.thread_create = lkl_thread_create,
	.thread_detach = lkl_thread_detach,
	.thread_exit = lkl_thread_exit,
	.thread_join = lkl_thread_join,
	.thread_self = lkl_thread_self,
	.thread_equal = lkl_thread_equal,
	.sem_alloc = lkl_sem_alloc,
	.sem_free = lkl_sem_free,
	.sem_up = lkl_sem_up,
	.sem_down = lkl_sem_down,
	.mutex_alloc = lkl_mutex_alloc,
	.mutex_free = lkl_mutex_free,
	.mutex_lock = lkl_mutex_lock,
	.mutex_unlock = lkl_mutex_unlock,
	.tls_alloc = tls_alloc,
	.tls_free = tls_free,
	.tls_set = tls_set,
	.tls_get = tls_get,
	.time = time_ns,
	.timer_alloc = lkl_timer_alloc,
	.timer_set_oneshot = lkl_timer_set_oneshot,
	.timer_free = lkl_timer_free,
	.print = print,
	.mem_alloc = malloc,
	.mem_free = free,
	.ioremap = lkl_ioremap,
	.iomem_access = lkl_iomem_access,
	.virtio_devices = NULL,
	.gettid = _gettid,
	.jmp_buf_set = jmp_buf_set,
	.jmp_buf_longjmp = jmp_buf_longjmp,
};

#if 0
static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
	off_t off;

	off = lseek(disk.fd, 0, SEEK_END);
	if (off < 0)
		return -1;

	*res = off;
	return 0;
}

static int do_rw(ssize_t (*fn)(), struct lkl_disk disk, struct lkl_blk_req *req)
{
	off_t off = req->sector * 512;
	void *addr;
	int len;
	int i;
	int ret = 0;

	for (i = 0; i < req->count; i++) {

		addr = req->buf[i].iov_base;
		len = req->buf[i].iov_len;

		do {
			ret = fn(disk.fd, addr, len, off);

			if (ret <= 0) {
				ret = -1;
				goto out;
			}

			addr += ret;
			len -= ret;
			off += ret;

		} while (len);
	}

out:
	return ret;
}

static int blk_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
	int err = 0;

	switch (req->type) {
	case LKL_DEV_BLK_TYPE_READ:
		err = do_rw(pread, disk, req);
		break;
	case LKL_DEV_BLK_TYPE_WRITE:
		err = do_rw(pwrite, disk, req);
		break;
	case LKL_DEV_BLK_TYPE_FLUSH:
	case LKL_DEV_BLK_TYPE_FLUSH_OUT:
#ifdef __linux__
		err = fdatasync(disk.fd);
#else
		err = fsync(disk.fd);
#endif
		break;
	default:
		return LKL_DEV_BLK_STATUS_UNSUP;
	}

	if (err < 0)
		return LKL_DEV_BLK_STATUS_IOERR;

	return LKL_DEV_BLK_STATUS_OK;
}
#endif

struct lkl_dev_blk_ops lkl_dev_blk_ops = {
	.get_capacity = NULL,
	.request = NULL,
};

