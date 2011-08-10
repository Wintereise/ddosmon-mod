/*
 * strlcpy.c
 */

#include "stdinc.h"

size_t strlcat(char *dest, const char *src, size_t count)
{
        size_t dsize = strlen(dest);
        size_t len = strlen(src);
        size_t res = dsize + len;

        dest += dsize;
        count -= dsize;
        if (len >= count)
                len = count - 1;
        memcpy(dest, src, len);
        dest[len] = 0;
        return res;
}

size_t strlcpy(char *dest, const char *src, size_t size)
{
        size_t ret = strlen(src);

        if (size)
        {
                size_t len = (ret >= size) ? size - 1 : ret;
                memcpy(dest, src, len);
                dest[len] = '\0';
        }
        return ret;
}
