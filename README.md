# 🛠️ Linux Syscall Table 

A simple ANSI-colored command-line utility to display Linux syscall tables in a readable table format.

## 📋 Features

- Supports ANSI-colored, word-wrapped syscall argument display.
- Easy filtering by architecture and syscall name.
- Terminal-friendly, readable and pretty formatting.
- Architecture support: `--x64` (more coming soon: `--x86`, `--arm32`, etc.)

## 🖥️ Usage

```bash
./syscall [ARCH] [SYSCALL_NAME]
```

## 📦 Building

Simply compile using GCC:

```bash
Use `gcc` to compile:
gcc -o syscall syscall.c
```

---

## 🔧 Examples

Make sure your terminal supports ANSI escape codes.
```bash
./syscall --x64
./syscall --x64 write
./syscall --help
```
---

## 🧾 Output Preview

```pgsql
+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+
|   SYSCALL NAME  |       RAX       |       RDI       |       RSI       |       RDX       |       R10       |        R8       |        R9       |
+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+
|      write      |        1        | unsigned int fd | const char *buf |  size_t count   |        -        |        -        |        -        |
+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+-----------------+
```
---

## 📚 Help Output

```bash
SysCall 1.0.0SVN ( https://github.com/omari4ms/linux-syscall-table.git )
Usage: ./syscall_viewer [arch] [syscall]

This tool provides quick access to Linux syscall tables.
Available architectures: --x32, --x64, --arm32, --x86

EXAMPLES:
  ./syscall_viewer --x64                Show all x64 syscalls
  ./syscall_viewer --x64  write        Show details for the 'write' syscall on x64
  ./syscall_viewer --arm32  read       Show details for the 'read' syscall on arm32
  ./syscall_viewer --x86  read         Show details for the 'read' syscall on x86
```
---

---

## 📚 Makefile

```bash

Build & Run (Default):
make

Only Compile:
make build

Install System-Wide (requires sudo if /bin/ is protected):
make install

Clean Up (Remove Binary):
make clean

```
---

## 💡 Future Plans

Auto-detect terminal width.

Export to file option (e.g., --write-to=file.txt).

---

## 📄 License

MIT 

---

Made with 💻 by @omari4ms



---

```yaml
Let me know if you'd like to auto-detect terminal width, support `--arm32`, or add search by syscall name!
```



