#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define COLUMN_WIDTH 17 // Column width
#define COLUMN_NUM 8	// Number of columns
#define MAX_LINES 5		// Max number of lines per cell

// ANSI color codes
#define GREEN "\033[32m"
#define RESET "\033[0m"
#define CYAN "\033[0;36m"

// Sample data
char *x64[][8] = {
	{"SYSCALL NAME", "RAX", "RDI", "RSI", "RDX", "R10", "R8", "R9"},
	{"read", "0", "unsigned int fd", "char *buf", "size_t count", "-", "-", "-"},
	{"write", "1", "unsigned int fd", "const char *buf", "size_t count", "-", "-", "-"},
	{"open", "2", "const char *filename", "int flags", "umode_t mode", "-", "-", "-"},
	{"close", "3", "unsigned int fd", "-", "-", "-", "-", "-"},
	{"stat", "4", "const char *filename", "struct __old_kernel_stat *statbuf", "-", "-", "-", "-"},
	{"fstat", "5", "unsigned int fd", "struct __old_kernel_stat *statbuf", "-", "-", "-", "-"},
	{"lstat", "6", "const char *filename", "struct __old_kernel_stat *statbuf", "-", "-", "-", "-"},
	{"poll", "7", "struct pollfd *ufds", "unsigned int nfds", "int timeout", "-", "-", "-"},
	{"lseek", "8", "unsigned int fd", "off_t offset", "unsigned int whence", "-", "-", "-"},
	{"mmap", "9", "?", "?", "?", "?", "?", "?"},
	{"mprotect", "10", "unsigned long start", "size_t len", "unsigned long prot", "-", "-", "-"},
	{"munmap", "11", "unsigned long addr", "size_t len", "-", "-", "-", "-"},
	{"brk", "12", "unsigned long brk", "-", "-", "-", "-", "-"},
	{"rt_sigaction", "13", "int", "const struct sigaction *", "struct sigaction *", "size_t", "-", "-"},
	{"rt_sigprocmask", "14", "int how", "sigset_t *set", "sigset_t *oset", "size_t sigsetsize", "-", "-"},
	{"rt_sigreturn", "15", "?", "?", "?", "?", "?", "?"},
	{"ioctl", "16", "unsigned int fd", "unsigned int cmd", "unsigned long arg", "-", "-", "-"},
	{"pread64", "17", "unsigned int fd", "char *buf", "size_t count", "loff_t pos", "-", "-"},
	{"pwrite64", "18", "unsigned int fd", "const char *buf", "size_t count", "loff_t pos", "-", "-"},
	{"readv", "19", "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-", "-", "-"},
	{"writev", "20", "unsigned long fd", "const struct iovec *vec", "unsigned long vlen", "-", "-", "-"},
	{"access", "21", "const char *filename", "int mode", "-", "-", "-", "-"},
	{"pipe", "22", "int *fildes", "-", "-", "-", "-", "-"},
	{"select", "23", "int n", "fd_set *inp", "fd_set *outp", "fd_set *exp", "struct timeval *tvp", "-"},
	{"sched_yield", "24", "-", "-", "-", "-", "-", "-"},
	{"mremap", "25", "unsigned long addr", "unsigned long old_len", "unsigned long new_len", "unsigned long flags", "unsigned long new_addr", "-"},
	{"msync", "26", "unsigned long start", "size_t len", "int flags", "-", "-", "-"},
	{"mincore", "27", "unsigned long start", "size_t len", "unsigned char * vec", "-", "-", "-"},
	{"madvise", "28", "unsigned long start", "size_t len", "int behavior", "-", "-", "-"},
	{"shmget", "29", "key_t key", "size_t size", "int flag", "-", "-", "-"},
	{"shmat", "30", "int shmid", "char *shmaddr", "int shmflg", "-", "-", "-"},
	{"shmctl", "31", "int shmid", "int cmd", "struct shmid_ds *buf", "-", "-", "-"},
	{"dup", "32", "unsigned int fildes", "-", "-", "-", "-", "-"},
	{"dup2", "33", "unsigned int oldfd", "unsigned int newfd", "-", "-", "-", "-"},
	{"pause", "34", "-", "-", "-", "-", "-", "-"},
	{"nanosleep", "35", "struct __kernel_timespec *rqtp", "struct __kernel_timespec *rmtp", "-", "-", "-", "-"},
	{"getitimer", "36", "int which", "struct itimerval *value", "-", "-", "-", "-"},
	{"alarm", "37", "unsigned int seconds", "-", "-", "-", "-", "-"},
	{"setitimer", "38", "int which", "struct itimerval *value", "struct itimerval *ovalue", "-", "-", "-"},
	{"getpid", "39", "-", "-", "-", "-", "-", "-"},
	{"sendfile", "40", "int out_fd", "int in_fd", "off_t *offset", "size_t count", "-", "-"},
	{"socket", "41", "int", "int", "int", "-", "-", "-"},
	{"connect", "42", "int", "struct sockaddr *", "int", "-", "-", "-"},
	{"accept", "43", "int", "struct sockaddr *", "int *", "-", "-", "-"},
	{"sendto", "44", "int", "void *", "size_t", "unsigned", "struct sockaddr *", "int"},
	{"recvfrom", "45", "int", "void *", "size_t", "unsigned", "struct sockaddr *", "int *"},
	{"sendmsg", "46", "int fd", "struct user_msghdr *msg", "unsigned flags", "-", "-", "-"},
	{"recvmsg", "47", "int fd", "struct user_msghdr *msg", "unsigned flags", "-", "-", "-"},
	{"shutdown", "48", "int", "int", "-", "-", "-", "-"},
	{"bind", "49", "int", "struct sockaddr *", "int", "-", "-", "-"},
	{"listen", "50", "int", "int", "-", "-", "-", "-"},
	{"getsockname", "51", "int", "struct sockaddr *", "int *", "-", "-", "-"},
	{NULL}};
char *x86[][8] = {
	{"SYSCALL NAME", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"},
	{"restart_syscall", "0", "-", "-", "-", "-", "-", "-"},
	{"exit", "1", "int error_code", "-", "-", "-", "-", "-"},
	{"fork", "2", "-", "-", "-", "-", "-", "-"},
	{"read", "3", "unsigned int fd", "char * buf", "size_t count", "-", "-", "-"},
	{"write", "4", "unsigned int fd", "const char * buf", "size_t count", "-", "-", "-"},
	{"open", "5", "const char * filename", "int flags", "int mode", "-", "-", "-"},
	{"close", "6", "unsigned int fd", "-", "-", "-", "-", "-"},
	{"waitpid", "7", "pid_t pid", "int * wait_stat", "int options", "-", "-", "-"},
	{"creat", "8", "const char * pathname", "int mode", "-", "-", "-", "-"},
	{"link", "9", "const char * oldname", "const char * newname", "-", "-", "-", "-"},
	{"unlink", "10", "const char * pathname", "-", "-", "-", "-", "-"},
	{"execve", "11", "const char * filename", "char const argv []", "char const envp []", "-", "-", "-"},
	{"chdir", "12", "const char * filename", "-", "-", "-", "-", "-"},
	{"time", "13", "time_t * tloc", "-", "-", "-", "-", "-"},
	{"mknod", "14", "const char * filename", "int mode", "int dev", "-", "-", "-"},
	{"chmod", "15", "const char * filename", "mode_t mode", "-", "-", "-", "-"},
	{"lchown", "16", "const char * filename", "uid_t owner", "gid_t group", "-", "-", "-"},
	{"break", "17", "-", "-", "-", "-", "-", "-"},
	{"oldstat", "18", "const char * filename", "struct old_kernel_stat * statbuf", "-", "-", "-", "-"},
	{"lseek", "19", "unsigned int fd", "off_t offset", "unsigned int whence", "-", "-", "-"},
	{"getpid", "20", "-", "-", "-", "-", "-", "-"},
	{"mount", "21", "char * dev_name", "char * dir_name", "char * type", "unsigned long flags", "void * data", "-"},
	{"umount", "22", "char * name", "int flags", "-", "-", "-", "-"},
	{"setuid", "23", "uid_t uid", "-", "-", "-", "-", "-"},
	{"getuid", "24", "-", "-", "-", "-", "-", "-"},
	{"stime", "25", "time_t * tptr", "-", "-", "-", "-", "-"},
	{"ptrace", "26", "long request", "long pid", "long addr", "long data", "-", "-"},
	{"alarm", "27", "unsigned int seconds", "-", "-", "-", "-", "-"},
	{"oldfstat", "28", "int fd", "struct old_kernel_stat * statbuf", "-", "-", "-", "-"},
	{"pause", "29", "-", "-", "-", "-", "-", "-"},
	{"utime", "30", "char * filename", "struct utimbuf * times", "-", "-", "-", "-"},
	{"stty", "31", "-", "-", "-", "-", "-", "-"},
	{"gtty", "32", "-", "-", "-", "-", "-", "-"},
	{"access", "33", "const char * filename", "int mode", "-", "-", "-", "-"},
	{"nice", "34", "int priority", "-", "-", "-", "-", "-"},
	{"ftime", "35", "-", "-", "-", "-", "-", "-"},
	{"sync", "36", "-", "-", "-", "-", "-", "-"},
	{"kill", "37", "pid_t pid", "int sig", "-", "-", "-", "-"},
	{"rename", "38", "const char * oldname", "const char * newname", "-", "-", "-", "-"},
	{"mkdir", "39", "const char * pathname", "int mode", "-", "-", "-", "-"},
	{"rmdir", "40", "const char * pathname", "-", "-", "-", "-", "-"},
	{"dup", "41", "unsigned int fildes", "-", "-", "-", "-", "-"},
	{"pipe", "42", "int * fildes", "-", "-", "-", "-", "-"},
	{"times", "43", "struct tms * buf", "-", "-", "-", "-", "-"},
	{"prof", "44", "-", "-", "-", "-", "-", "-"},
	{"brk", "45", "void * brk", "-", "-", "-", "-", "-"},
	{"setgid", "46", "gid_t gid", "-", "-", "-", "-", "-"},
	{"getgid", "47", "-", "-", "-", "-", "-", "-"},
	{"signal", "48", "int sig", "void * handler", "-", "-", "-", "-"},
	{"geteuid", "49", "-", "-", "-", "-", "-", "-"},
	{"getegid", "50", "-", "-", "-", "-", "-", "-"},
	{"acct", "51", "const char * name", "-", "-", "-", "-", "-"},
	{NULL}};

void help(const char *argv)
{
	printf("\n");
	printf("\e[1mSysCall 1.0.0SVN ( https://github.com/omari4ms/linux-syscall-table.git )\e[m\n");
	printf("Usage: %s [arch] [syscall] \n", argv);
	printf("\n");
	printf("This tool provides quick access to Linux syscall tables.\n");
	printf("Available architectures: --x32, --x64, --arm32, --x86\n");
	printf("Use a syscall name after the architecture to filter specific syscall entries.\n");
	printf("\n");
	printf("\033[0;32mEXAMPLES:\033[0m\n");
	printf("  %s --x64                Show all x64 syscalls\n", argv);
	printf("  %s --x64 --write        Show details for the 'write' syscall on x64\n", argv);
	printf("  %s --arm32 --read       Show details for the 'read' syscall on arm32\n", argv);
	printf("  %s --x86 --read         Show details for the 'read' syscall on x86\n", argv);
	printf("\n");
}

// Function to print a line separator with cyan
void print_line()
{
	printf(CYAN);
	for (int i = 0; i < COLUMN_NUM; i++)
	{
		printf("+-----------------");
	}
	printf("+\n" RESET);
}

// Function to wrap text at word boundaries
int wrap_text(const char *text, char output[MAX_LINES][COLUMN_WIDTH + 1])
{
	int len = strlen(text);
	int row = 0, col = 0, last_space = -1;

	memset(output, 0, sizeof(char) * MAX_LINES * (COLUMN_WIDTH + 1));
	for (int i = 0; i < len; i++)
	{
		if (col >= COLUMN_WIDTH)
		{
			if (last_space != -1)
			{
				output[row][last_space] = '\0';
				i -= (col - last_space - 1);
			}
			else
			{
				output[row][col] = '\0';
			}
			row++;
			col = 0;
			last_space = -1;
			if (row >= MAX_LINES)
				break;
		}
		output[row][col] = text[i];
		if (text[i] == ' ')
			last_space = col;
		col++;
	}
	output[row][col] = '\0';
	return row + 1; // Number of lines used
}

// Function to print a centered cell
void print_centered(const char *text, int is_header)
{
	int len = strlen(text);
	int padding = (COLUMN_WIDTH - len) / 2;
	if (is_header)
	{
		printf(GREEN);
	}
	printf("|%*s%s%*s", padding, "", text, padding + (COLUMN_WIDTH - len) % 2, "");
	printf(RESET);
}

// Function to print a table row
void print_row(char *row[], int is_header)
{
	char wrapped[COLUMN_NUM][MAX_LINES][COLUMN_WIDTH + 1];
	int max_lines = 1;

	for (int i = 0; i < COLUMN_NUM; i++)
	{
		int lines = wrap_text(row[i], wrapped[i]);
		if (lines > max_lines)
			max_lines = lines;
	}

	for (int line = 0; line < max_lines; line++)
	{
		for (int i = 0; i < COLUMN_NUM; i++)
		{
			if (wrapped[i][line][0] == '\0')
			{
				printf("|%*s", COLUMN_WIDTH, " ");
			}
			else
			{
				print_centered(wrapped[i][line], is_header);
			}
		}
		printf("|\n");
	}
}

void print_table(char *table[][8])
{
	print_line();
	print_row(table[0], 1); // Print header with green color
	print_line();

	for (int i = 1; table[i][0] != NULL; i++)
	{
		print_row(table[i], 0);
		print_line();
	}
}

void search_and_print(char *table[][8], const char *name)
{
	print_line();
	print_row(table[0], 1);
	print_line();
	for (int i = 1; table[i][0] != NULL; i++)
	{
		if (strcmp(table[i][0], name) == 0)
		{
			print_row(table[i], 0);
			print_line();
			return;
		}
	}
	printf("No syscall named '%s' found.\n", name);
}

int main(int argc, char *argv[])
{
	switch (argc)
	{
	case 1:
		help(argv[0]);
		break;
	case 2:
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
		{
			help(argv[0]);
			break;
		}
		if (strcmp(argv[1], "--x64") == 0)
		{
			print_table(x64);
		}
		if (strcmp(argv[1], "--x86") == 0 || strcmp(argv[1], "--x32") == 0 )
		{
			print_table(x86);
		}

		break;
	case 3:
		if (strcmp(argv[1], "--x64") == 0)
		{
			search_and_print(x64, argv[2]);
		}
		if (strcmp(argv[1], "--x86") == 0 || strcmp(argv[1], "--x32") == 0)
		{
			search_and_print(x86, argv[2]);
		}
		break;
	default:
		help(argv[0]);
		break;
	}
	return 0;
}
