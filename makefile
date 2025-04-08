CC = gcc
appname = syscall.c
appout =  syscall

all: build run 
build:
	@$(CC) $(appname) -o $(appout)
run:
	@./$(appout) --help
install:
	@mv $(appout) /bin/
clean:
	@if [ -e $(appout) ]; then rm $(appout); else echo "Error: '$(appout)' binary file not found."; fi
	clear

