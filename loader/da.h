#include <assert.h>

#define __da_assert_init(da) (assert((da)->cap > 0 && "da->cap shall be more than zero"), assert((da)->items && "shall initialize da->items"))

#define da_append(da, item) (__da_assert_init((da)), (((da)->len == (da)->cap) ? ((da)->items = realloc((da)->items, (da)->cap * sizeof *(da)->items * 2)), ((da)->cap *= 2), ((da)->items[(da)->len++] = (item)), (item) : ((da)->items[(da)->len++] = (item)), (item)))

#define da_get(da, index) (__da_assert_init((da)), assert((da)->len > index && "out of bounds da access"), (da)->items[(index)])
