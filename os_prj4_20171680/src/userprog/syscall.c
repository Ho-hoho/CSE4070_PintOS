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
#include "vm/page.h"

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&rw_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
check_address(void *addr, void *esp UNUSED)
{	
	if(is_kernel_vaddr(addr))
	  exit(-1);
}
void
get_argument(void *esp, int *arg, int count)
{
	int i;
	void *stack_pointer=esp+4;
	if(count > 0)
	{
		for(i=0; i<count; i++){
			check_address(stack_pointer, esp);
			arg[i] = *(int *)stack_pointer;
			stack_pointer = stack_pointer + 4;
		}
	}
}
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write)
{
	struct vm_entry *vme;
	unsigned i;
	char *check_buffer = (char *)buffer;
	/* check buffer */
	for(i=0; i<size; i++){
		check_address((void *)check_buffer, esp);
		vme = find_vme((void *)check_buffer);
		if(vme != NULL){
			if(to_write == true){
				if(vme->writable == false)
					exit(-1);
			}
		}
		check_buffer++;
	}
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_num;
  int arg[5];
  void *esp = f->esp;
  check_address(esp, f->esp);
  syscall_num = *(int *)esp;
  switch(syscall_num)
  {
	  case SYS_HALT:
		  halt();
		  break;
	  case SYS_EXIT:
		  get_argument(esp,arg,1);
		  exit(arg[0]);
		  break;
	  case SYS_EXEC:
		  get_argument(esp,arg,1);
		  check_address((void *)arg[0], f->esp);
		  f->eax = exec((const char *)arg[0]);
		  break;
	  case SYS_WAIT:
		  get_argument(esp,arg,1);
		  f->eax = wait(arg[0]);
		  break;
	  case SYS_CREATE:
		  get_argument(esp,arg,2);
		  check_address((void *)arg[0], f->esp);
		  f->eax = create((const char *)arg[0],(unsigned)arg[1]);
		  break;
	  case SYS_REMOVE:
		  get_argument(esp,arg,1);
		  check_address((void *)arg[0], f->esp);
		  f->eax=remove((const char *)arg[0]);
		  break;
	  case SYS_OPEN:
		  get_argument(esp,arg,1);
		  check_address((void *)arg[0], f->esp);
      f->eax = open((const char *)arg[0]);
		  break;
	  case SYS_FILESIZE:
		  get_argument(esp,arg,1);
		  f->eax = filesize(arg[0]);
		  break;
	  case SYS_READ:
		  get_argument(esp,arg,3);
		  check_address((void *)arg[1],f->esp);
		  f->eax = read(arg[0],(void *)arg[1],(unsigned)arg[2]);
		  break;
	  case SYS_WRITE:
		  get_argument(esp,arg,3);
		  check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, false);
		  f->eax = write(arg[0],(void *)arg[1],(unsigned)arg[2]);
		  break;
	  case SYS_SEEK:
		  get_argument(esp,arg,2);
		  seek(arg[0],(unsigned)arg[1]);
		  break;
	  case SYS_TELL:
		  get_argument(esp,arg,1);
		  f->eax = tell(arg[0]);
		  break;
	  case SYS_CLOSE:
		  get_argument(esp,arg,1);
		  close(arg[0]);
		  break;
	  case SYS_MMAP:
		  break;
	  case SYS_MUNMAP:
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
 //check_user_vaddr(buffer);
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
  //check_user_vaddr(buffer);
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
  bool result;
  if(file == NULL){
    exit(-1);
  }

  lock_acquire(&rw_lock);
  result = filesys_create(file,initial_size);
  lock_release(&rw_lock);

  return result;
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
  //check_user_vaddr(file);
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

