#pragma once 

#include <stddef.h>


void *aligned_malloc(size_t bytes, size_t align);
void *aligned_realloc(void *ptr, size_t bytes, size_t align);
void aligned_free(void *ptr);

