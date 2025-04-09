CC = gcc
file = syscall.c
bin_file =  syscall

all: build run 
build:
	@$(CC) $(file) -o $(bin_file)
run:
	@./$(bin_file) --help
install:
	@mv $(bin_file) /bin/
clean:
	@if [ -e $(bin_file) ]; then rm $(bin_file); else echo "Error: '$(bin_file)'  file not found."; fi
	clear

