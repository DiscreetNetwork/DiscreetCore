#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_EXPLICIT_BZERO
#include <strings.h>
#endif
#include "util/memwipe.h"

#if defined(_WIN64)
#define SCARECROW
#elif defined (_WIN32)
#define SCARECROW \
    __asm{};
#else
#define SCARECROW \
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif

#ifdef __STDC_LIB_EXT1__

void *memwipe(void *ptr, size_t n)
{
  if (n > 0 && memset_s(ptr, n, 0, n))
  {
#ifdef NDEBUG
    fprintf(stderr, "Error: memset_s failed\n");
    _exit(1);
#else
    abort();
#endif
  }
  SCARECROW // might as well...
  return ptr;
}

#elif defined HAVE_EXPLICIT_BZERO

void *memwipe(void *ptr, size_t n)
{
  if (n > 0)
    explicit_bzero(ptr, n);
  SCARECROW
  return ptr;
}

#else

/* The memory_cleanse implementation is taken from Bitcoin */

/* Compilers have a bad habit of removing "superfluous" memset calls that
 * are trying to zero memory. For example, when memset()ing a buffer and
 * then free()ing it, the compiler might decide that the memset is
 * unobservable and thus can be removed.
 *
 * Previously we used OpenSSL which tried to stop this by a) implementing
 * memset in assembly on x86 and b) putting the function in its own file
 * for other platforms.
 *
 * This change removes those tricks in favour of using asm directives to
 * scare the compiler away. As best as our compiler folks can tell, this is
 * sufficient and will continue to be so.
 *
 * Adam Langley <agl@google.com>
 * Commit: ad1907fe73334d6c696c8539646c21b11178f20f
 * BoringSSL (LICENSE: ISC)
 */

/* the following code seems to fix the problem on x64. Thank you, Robert Seacord. */
void* erase_from_memory(void* pointer, size_t size_data, size_t size_to_remove) {
    if (size_to_remove > size_data) size_to_remove = size_data;
    volatile unsigned char* p = pointer;
    while (size_to_remove--) {
        *p++ = 0;
    }
    return pointer;
}

static void memory_cleanse(void *ptr, size_t len)
{
#if defined(_WIN64)
    erase_from_memory(ptr, len, len);
#else
    memset(ptr, 0, len);
#endif
    /* As best as we can tell, this is sufficient to break any optimisations that
       might try to eliminate "superfluous" memsets. If there's an easy way to
       detect memset_s, it would be better to use that. */
    SCARECROW
}

void *memwipe(void *ptr, size_t n)
{
  if (n > 0)
    memory_cleanse(ptr, n);
  SCARECROW
  return ptr;
}

#endif