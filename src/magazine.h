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
	void **data;
	size_t object_size;
	size_t object_count;
	size_t object_position;
} magazine_t;

#define MAGAZINE_INIT(size) \
	(magazine_t){ .data = NULL, .object_size = (size), .object_count = 0, .object_position = 0 }

#ifndef NEVER_USE_MAGAZINE

static inline void *magazine_alloc(magazine_t *mag)
{
	void *ptr;

	if (mag->object_count == mag->object_position)
	{
		mag->object_count += 1;
		mag->data = realloc(mag->data, sizeof (void *) * mag->object_count);
		mag->data[mag->object_position] = malloc(mag->object_size);
	}

	ptr = mag->data[mag->object_position];
	mag->object_position++;

	memset(ptr, 0, mag->object_size);

	return ptr;
}

static inline void magazine_release(magazine_t *mag, void *addr)
{
	mag->object_position--;
	mag->data[mag->object_position] = addr;
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
