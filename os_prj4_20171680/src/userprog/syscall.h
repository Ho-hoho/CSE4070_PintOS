#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h"

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_lime);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
//void check_user_vaddr(const void *);
void check_address(void *addr, void *esp UNUSED);
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
//void check_valid_string(const void *str, void *esp);
void get_argument(void *esp, int *arg, int count);
int fibonacci(int n);
int max_of_four_int(int a,int b,int c,int d);

bool create(const char *file,unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


struct lock rw_lock;
#endif /* userprog/syscall.h */
