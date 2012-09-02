/*
 * magazine.h
 * Purpose: caching malloc/free wrapper
 *
 * Copyright (c) 2012, TortoiseLabs LLC.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __MAGAZINE_H
#define __MAGAZINE_H

typedef struct {
	mowgli_heap_t *heap;
	size_t object_size;
} magazine_t;

#define MAGAZINE_INIT(size) (magazine_t){ .heap = NULL, .object_size = (size) }

#ifndef NEVER_USE_MAGAZINE

static inline void *magazine_alloc(magazine_t *mag)
{
	if (mag->heap == NULL)
	{
		DPRINTF("%s\n", "magazine_alloc() is deprecated, use mowgli_heap_alloc() instead.");
		mag->heap = mowgli_heap_create(mag->object_size, 1024, BH_NOW);
	}

	return mowgli_heap_alloc(mag->heap);
}

static inline void magazine_release(magazine_t *mag, void *addr)
{
	mowgli_heap_free(mag->heap, addr);
}

#else

static inline void *magazine_alloc(magazine_t *mag)
{
	return calloc(mag->object_size, 1);
}

static inline void magazine_release(magazine_t *mag, void *addr)
{
	free(addr);
}

#endif

#endif
