#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"

/* Buffer Caches. */
#define BUFFER_CACHE_SIZE 64

struct buffer_cache_entry_t {
  bool valid_bit;
  bool reference_bit;
  bool dirty_bit; 
  block_sector_t disk_sector;
  uint8_t buffer[BLOCK_SECTOR_SIZE];   
};

struct buffer_cache_entry_t cache[BUFFER_CACHE_SIZE];


void buffer_cache_init (void);
void buffer_cache_close (void);
void buffer_cache_read (block_sector_t sector, void *target);
void buffer_cache_write (block_sector_t sector, const void *source);
void buffer_cache_flush (struct buffer_cache_entry_t *entry);
struct buffer_cache_entry_t* buffer_cache_lookup (block_sector_t sector);
struct buffer_cache_entry_t* buffer_cache_evict (void);


#endif
