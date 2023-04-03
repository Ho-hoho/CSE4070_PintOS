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
#include "string.h"

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
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call! : %d\n",*(uint32_t *)(f->esp));
  //hex_dump(f->esp,f->esp,100,1);
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
      //f->eax = exec((const char *)(f->esp+4));
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

    /* Project 3 and optionally project 4. */
    case SYS_MMAP :
      break;                   /* Map a file into memory. */
    case SYS_MUNMAP:                 /* Remove a memory mapping. */
      break;
    /* Project 4 only. */
    case SYS_CHDIR:
      break;                  /* Change the current directory. */
    case SYS_MKDIR:
      break;                  /* Create a directory. */
    case SYS_READDIR:
      break;                /* Reads a directory entry. */
    case SYS_ISDIR:
      break;                  /* Tests if a fd represents a directory. */
    case SYS_INUMBER:
      break;                 /* Returns the inode number for a fd. */
  }
  //thread_exit ();
}

void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  thread_current()-> exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  for(int i=3;i<128;i++){
    if(thread_current()->fd[i] != NULL){
      close(i);
    }
  }
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

int read (int fd, void* buffer, unsigned size) {
  int ret = -1;
  check_user_vaddr(buffer);
  lock_acquire(&rw_lock);
  if (fd == 0) {
    ret = input_getc();
  }
  else if( fd > 2){
    ret = file_read(thread_current()->fd[fd],buffer,size);
  }
  lock_release(&rw_lock);
  return ret;
}

int write (int fd, const void *buffer, unsigned size) {
  int ret= -1;
  check_user_vaddr(buffer);
  lock_acquire(&rw_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    ret = size;
  }
  else if(fd > 2){
    if (thread_current()->fd[fd] == NULL) {
      lock_release(&rw_lock);
      exit(-1);
    }
    ret= file_write(thread_current()->fd[fd],buffer,size);
  }
  lock_release(&rw_lock);  
  return ret;
}

bool create(const char *file,unsigned initial_size){
  if(file == NULL){
    exit(-1);
  }
  return filesys_create(file,initial_size);
}

bool remove(const char *file){
  if(file == NULL){
    exit(-1);
  }
  return filesys_remove(file);
}

int open(const char *file){
  int ret = -1;
  if(file == NULL){
    exit(-1);
  }
  check_user_vaddr(file);
  lock_acquire(&rw_lock);
  struct file* fp = filesys_open(file);  
  if(fp == NULL){
    ret = -1;
  }
  else {
    for(int i=3;i<128;i++){
      if(thread_current()->fd[i] == NULL){
        if(strcmp(thread_current()->name,file) == 0){
          file_deny_write(fp);
        }
        thread_current()->fd[i] = fp;
        ret= i;
        break;
     }
    }
  }
  lock_release(&rw_lock);
  return ret;
}

int filesize(int fd){
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}
void seek(int fd, unsigned position){
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  return file_seek(thread_current()->fd[fd],position);
}
unsigned tell (int fd){
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd){
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  struct file* fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
}