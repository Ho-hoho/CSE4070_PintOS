#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h"
#include "threads/vaddr.h"
void syscall_init (void);
bool put_user (uint8_t *udst, uint8_t byte);
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
void check_user_vaddr(const void *);
int fibonacci(int n);
int max_of_four_int(int a,int b,int c,int d);
bool chdir(const char *filename);
bool mkdir(const char *filename);
bool readdir(int fd, char *filename);
bool isdir(int fd);
int inumber(int fd);


#endif /* userprog/syscall.h */
