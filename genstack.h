#ifndef _GENSTACK_H_
#define _GENSTACK_H_

#include <stdbool.h>
#include <stdint.h>

/* A generic stack API. */

struct genstack;
typedef struct genstack *genstack;

extern struct genstack *genstack_alloc(size_t size);

extern void genstack_release(struct genstack *stack);

extern size_t genstack_size(const struct genstack *stack);

extern void *genstack_base(const struct genstack *stack);

extern void *genstack_sp(const struct genstack *stack);

#endif
