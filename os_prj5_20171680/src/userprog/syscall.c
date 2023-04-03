#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "threads/palloc.h"
#include "string.h"

enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };
static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

struct lock rw_lock;
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&rw_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_user_vaddr(const void *vaddr){
  if(!is_user_vaddr(vaddr)){
    exit(-1);
  }
}
bool
put_user (uint8_t *udst, uint8_t byte) {
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT: /* Halt the operating system. */
      halt();
      break;                         
    case SYS_EXIT:
      check_user_vaddr(f->esp+4);
      exit(*(uint32_t *)(f->esp+4));
      break;                   /* Terminate this process. */
    case SYS_EXEC:
      check_user_vaddr(f->esp+4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp+4));
      break;                   /* Start another process. */
    case SYS_WAIT:                   /* Wait for a child process to die. */
      check_user_vaddr(f->esp+4);
      f->eax = wait((pid_t)*(uint32_t *)(f->esp+4));
      break;
    case SYS_CREATE:
      check_user_vaddr(f->esp+4);
      check_user_vaddr(f->esp+8);
      f->eax = create((const char *)*(uint32_t *)(f->esp+4),(unsigned)*(uint32_t *)(f->esp+8));
      break;                 /* Create a file. */
    case SYS_REMOVE:
      check_user_vaddr(f->esp+4);
      f->eax = remove((const char*)*(uint32_t *)(f->esp+4));
      break;                 /* Delete a file. */
    case SYS_OPEN:
      check_user_vaddr(f->esp+4);
      f->eax = open((const char*)*(uint32_t *)(f->esp+4));
      break;                   /* Open a file. */
    case SYS_FILESIZE:
      check_user_vaddr(f->esp+4);
      f->eax = filesize((int)*(uint32_t *)(f->esp+4));
      break;               /* Obtain a file's size. */
    case SYS_READ:
      check_user_vaddr(f->esp+20);
      check_user_vaddr(f->esp+24);
      check_user_vaddr(f->esp+28);
      f->eax = read((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;                   /* Read from a file. */
    case SYS_WRITE :
      check_user_vaddr(f->esp+20);
      check_user_vaddr(f->esp+24);
      check_user_vaddr(f->esp+28);
      f->eax = write((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
      break;                  /* Write to a file. */
    case SYS_SEEK :
      check_user_vaddr(f->esp+4);
      check_user_vaddr(f->esp+8);
      seek((int)*(uint32_t *)(f->esp+4),(unsigned)*(uint32_t *)(f->esp+8));
      break;                   /* Change position in a file. */
    case SYS_TELL:
      check_user_vaddr(f->esp+4);
      f->eax = tell((int)*(uint32_t *)(f->esp+4));
      break;                   /* Report current position in a file. */
    case SYS_CLOSE:
      check_user_vaddr(f->esp+4);
      close((int)*(uint32_t *)(f->esp+4));
      break;                  /* Close a file. */
    case SYS_FIB:
      check_user_vaddr(f->esp+4);
      //hex_dump(f->esp,f->esp,300,1);
      f->eax = fibonacci((int)*(uint32_t *)(f->esp+4));
      break;
    case SYS_MOFI:
      check_user_vaddr(f->esp+4);
      check_user_vaddr(f->esp+8);
      check_user_vaddr(f->esp+12);
      check_user_vaddr(f->esp+16);
      //hex_dump(f->esp,f->esp,300,1);
      f->eax = max_of_four_int( (int)*(uint32_t *)(f->esp+4),(int)*(uint32_t *)(f->esp+8),(int)*(uint32_t *)(f->esp+12),(int)*(uint32_t *)(f->esp+16)  );
      break;
    case SYS_CHDIR:
      check_user_vaddr(f->esp+4);
      f->eax = chdir((const char*)*(uint32_t *)(f->esp+4));
      break;                  
    case SYS_MKDIR:
      check_user_vaddr(f->esp + 4);
      f->eax = mkdir((const char*)*(uint32_t *)(f->esp+4));
      break;                  
    case SYS_READDIR:
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      f->eax = readdir((int)*(uint32_t *)(f->esp+4), (char*)*(uint32_t *)(f->esp+8));       
      break;               
    case SYS_ISDIR:
      check_user_vaddr(f->esp + 4);
      f->eax = isdir((int)*(uint32_t *)(f->esp+4));
      break;                 
    case SYS_INUMBER:
      check_user_vaddr(f->esp + 4);
      f->eax = inumber((int)*(uint32_t *)(f->esp+4));
      break;              
  }
}

void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  thread_current()-> exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit ();
}

pid_t exec (const char *cmd_line) {
    return process_execute(cmd_line); 
}

int wait (pid_t pid) {
  return process_wait(pid);
}

int fibonacci(int n){
 
  int a1=0,a2=1;
  int result;
  if(n == 0 || n == 1 ) return n;
  else if (n < 0) return -1;
  else{
    for(int i=1;i<=n;i++){
      result = a1 + a2;
      a2 = a1;
      a1 = result;
    }
  }
  return result;
}

int max_of_four_int(int a, int b, int c , int d){
   
  int tmp = a;
  if(b > tmp) tmp = b;
  if(c > tmp) tmp = c;
  if(d > tmp) tmp = d;
  return tmp; 
}

int read(int fd, void *buffer, unsigned size) {
  check_user_vaddr((const uint8_t*) buffer);
  check_user_vaddr((const uint8_t*) buffer + size - 1);

  lock_acquire (&rw_lock);
  int ret;

  if(fd == 0) { 
    unsigned i;
    for(i = 0; i < size; ++i) {
      if(! put_user(buffer + i, input_getc()) ) {
        lock_release (&rw_lock);
        exit(-1); 
      }
    }
    ret = size;
  }
  else {
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

    if(file_d && file_d->file) {
      ret = file_read(file_d->file, buffer, size);
    }
    else 
      ret = -1;
  }

  lock_release (&rw_lock);
  return ret;
}


int write(int fd, const void *buffer, unsigned size) {

  lock_acquire (&rw_lock);
  int ret;

  if(fd == 1) { 
    putbuf(buffer, size);
    ret = size;
  }
  else {
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else
      ret = -1;
  }
  lock_release (&rw_lock);
  return ret;
}

bool create(const char *file,unsigned initial_size){
  if(file == NULL){
    exit(-1);
  }
  bool ret;
  lock_acquire(&rw_lock);
  ret = filesys_create(file,initial_size,false);
  lock_release(&rw_lock); 
  return ret; 
}

bool remove(const char *file){
  if(file == NULL){
    exit(-1);
  }
  return filesys_remove(file);
  
}

int open(const char *file){
  struct file* fp;
  struct file_desc* fd = palloc_get_page(0);   
  int ret = -1;
  
  if(!fd)
    return -1;  
  lock_acquire(&rw_lock);
  fp = filesys_open(file);
  if(!fp){
    palloc_free_page (fd);
    ret = -1;
  }
  else {
    if(strcmp(thread_current()->name,file) == 0){
          file_deny_write(fp);
    }
    fd->file = fp; 

    // directory handling
    struct inode *inode = file_get_inode(fd->file);
    if(inode != NULL && inode_is_directory(inode)) {
     fd->dir = dir_open( inode_reopen(inode) );
    }
    else fd->dir = NULL;
    struct list* fd_list = &thread_current()->file_descriptors;
    if (list_empty(fd_list)) {
     fd->id = 3;
    }
    else {
     fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
    }
    list_push_back(fd_list, &(fd->elem));
    ret = fd->id;
  }
  lock_release(&rw_lock);
  return ret;
 
}

int filesize(int fd){
  struct file_desc* file_d;
  int ret;
  file_d = find_file_desc(thread_current(), fd, FD_FILE);
  if(file_d == NULL) {
    ret = -1;
  }
  else{
    ret = file_length(file_d->file);
  }
  return ret;
}

void seek(int fd, unsigned position){
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else{
    exit(-1); 
  }
}

unsigned tell (int fd){
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else{
    exit(-1);
  }
  return ret;
}

void close (int fd){
  lock_acquire (&rw_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    if(file_d->dir) dir_close(file_d->dir);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&rw_lock);
}


////////////proj 5////////////

static struct file_desc*
find_file_desc(struct thread *t, int fd, enum fd_search_filter flag)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        if (desc->dir != NULL && (flag & FD_DIRECTORY) )
          return desc;
        else if (desc->dir == NULL && (flag & FD_FILE) )
          return desc;
      }
    }
  }

  return NULL;
}


bool chdir(const char *filename)
{
  bool return_code;

  lock_acquire (&rw_lock);
  return_code = filesys_chdir(filename);
  lock_release (&rw_lock);

  return return_code;
}


bool mkdir(const char *filename)
{
  bool return_code;

  lock_acquire (&rw_lock);
  return_code = filesys_create(filename, 0, true);
  lock_release (&rw_lock);

  return return_code;
}

bool readdir(int fd, char *name)
{
  struct file_desc* file_d;
  bool ret = false;

  lock_acquire (&rw_lock);
  file_d = find_file_desc(thread_current(), fd, FD_DIRECTORY);
  if (file_d == NULL) goto done;

  struct inode *inode;
  inode = file_get_inode(file_d->file); // file descriptor -> inode
  if(inode == NULL) goto done;

  // check whether it is a valid directory
  if(! inode_is_directory(inode)) goto done;

  ASSERT (file_d->dir != NULL); // see sys_open()
  ret = dir_readdir (file_d->dir, name);

done:
  lock_release (&rw_lock);
  return ret;
}

bool isdir(int fd)
{
  lock_acquire (&rw_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  bool ret = inode_is_directory (file_get_inode(file_d->file));

  lock_release (&rw_lock);
  return ret;
}

int inumber(int fd)
{
  lock_acquire (&rw_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  int ret = (int) inode_get_inumber (file_get_inode(file_d->file));

  lock_release (&rw_lock);
  return ret;
}