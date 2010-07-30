#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "genstack.h"

struct genstack {
	void *addr;  /* Return value from mmap. Accessors must account
		      * for guard pages at both ends.
		      */
	size_t size; /* Size of the region as passed to mmap. */
};

static size_t page_size(void)
{
	return sysconf(_SC_PAGESIZE);
}

/* Allocate a stack region with guard pages (PROT_NONE) at both ends.
 * The size requested will be rounded up to the system page size.
 * Callers must check for errors with genstack_err().
 */
struct genstack *genstack_alloc(size_t sz)
{
	struct genstack *stk;
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int mmap_prot = PROT_READ | PROT_WRITE;
	void *addr;

	/* Align requested size up to page boundary */
	sz = (sz + page_size() - 1) & (~(page_size() - 1));

	if (sz == 0)
		return NULL;

	/*
	 * This is clearly an overkill; however, we must not use
	 * malloc because it may not be thread-safe!
	 */
	stk = mmap(NULL, page_size(), mmap_prot, mmap_flags, -1, 0);
	if (!stk)
		return NULL;

	/* Make space for guard pages */
	sz += page_size() * 2;

	addr = mmap(NULL, sz, mmap_prot, mmap_flags, -1, 0);
	if (addr == MAP_FAILED) {
		munmap(stk->addr, page_size());
		return NULL;
	}

	/* guard pages */
	mprotect(addr, page_size(), PROT_NONE);
	mprotect(addr + sz - page_size(), page_size(), PROT_NONE);

	stk->addr = addr;
	stk->size = sz;

	return stk;
}

/* Unmap the stack region. */
void genstack_release(struct genstack *stk)
{
	munmap(stk->addr, stk->size);
	munmap(stk, page_size());
}

/* Return the size of the usable stack region.  Suitable for providing
 * the child_stack_size value for struct clone_args.
 */
size_t genstack_size(const struct genstack *stk)
{
	return stk->size - (page_size() * 2);
}

/* Return the lowest usable address in the stack region.  Suitable for
 * providing the child_stack value for struct clone_args.
 */
void *genstack_base(const struct genstack *stk)
{
	return stk->addr + page_size();
}

/* Return a suitable stack pointer value for passing to clone(2),
 * accounting for platform differences in stack behavior.
 */
void *genstack_sp(const struct  genstack *stk)
{
#ifdef __hppa__
	/*
	 * If stack grows upwards, return the lowest address between
	 * the guard pages.
	 */
	return stk->addr + page_size();
#else
	/*
	 * Otherwise return the highest address between the guard pages.
	 * glibc's clone wrappers apply any necessary alignment.
	 */
	return (stk->addr + stk->size - page_size()) - 1;
#endif
}
