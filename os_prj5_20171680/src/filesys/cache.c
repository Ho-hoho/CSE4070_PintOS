#include <debug.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

static struct lock buffer_cache_lock;

void
buffer_cache_init (void)
{
  lock_init (&buffer_cache_lock);
  size_t i;
  for (i = 0; i < BUFFER_CACHE_SIZE; i++)
  {
    cache[i].valid_bit = true;
  }
}

void
buffer_cache_close (void)
{
  lock_acquire (&buffer_cache_lock);

  size_t i;
  for (i = 0; i < BUFFER_CACHE_SIZE; i++){
    if (cache[i].valid_bit == true) 
      continue;
    buffer_cache_flush( &(cache[i]) );
  }

  lock_release (&buffer_cache_lock);
}

void
buffer_cache_read (block_sector_t sector, void *target)
{
  lock_acquire (&buffer_cache_lock);

  struct buffer_cache_entry_t *slot = buffer_cache_lookup (sector);
  if (slot == NULL) {
    slot = buffer_cache_evict ();
    ASSERT (slot != NULL && slot->valid_bit == true);

    slot->valid_bit = false;
    slot->disk_sector = sector;
    slot->dirty_bit = false;
    block_read (fs_device, sector, slot->buffer);
  }

  slot->reference_bit = true;
  memcpy (target, slot->buffer, BLOCK_SECTOR_SIZE);

  lock_release (&buffer_cache_lock);
}

void
buffer_cache_write (block_sector_t sector, const void *source)
{
  lock_acquire (&buffer_cache_lock);

  struct buffer_cache_entry_t *slot = buffer_cache_lookup (sector);
  if (slot == NULL) {
    slot = buffer_cache_evict ();
    ASSERT (slot != NULL && slot->valid_bit == true);

    slot->valid_bit = false;
    slot->disk_sector = sector;
    slot->dirty_bit = false;
    block_read (fs_device, sector, slot->buffer);
  }

  slot->reference_bit = true;
  slot->dirty_bit = true;
  memcpy (slot->buffer, source, BLOCK_SECTOR_SIZE);

  lock_release (&buffer_cache_lock);
}

void
buffer_cache_flush (struct buffer_cache_entry_t *entry)
{
  ASSERT (lock_held_by_current_thread(&buffer_cache_lock));
  ASSERT (entry != NULL && entry->valid_bit == false);

  if (entry->dirty_bit) {
    block_write (fs_device, entry->disk_sector, entry->buffer);
    entry->dirty_bit = false;
  }
}

struct buffer_cache_entry_t*
buffer_cache_lookup (block_sector_t sector)
{
  size_t i;
  for (i = 0; i < BUFFER_CACHE_SIZE; i++)
  {
    if (cache[i].valid_bit == true) 
      continue;
    if (cache[i].disk_sector == sector) {
      return &(cache[i]);
    }
  }
  return NULL; 
}

struct buffer_cache_entry_t*
buffer_cache_evict (void)
{
  ASSERT (lock_held_by_current_thread(&buffer_cache_lock));


  static size_t clock = 0;
  while (true) {
    if (cache[clock].valid_bit == true) {
      return &(cache[clock]);
    }

    if (cache[clock].reference_bit) {
      cache[clock].reference_bit = false;
    }
    else 
      break;

    clock ++;
    clock %= BUFFER_CACHE_SIZE;
  }

  struct buffer_cache_entry_t *slot = &cache[clock];
  if (slot->dirty_bit) {
    buffer_cache_flush (slot);
  }

  slot->valid_bit = true;
  return slot;
}

