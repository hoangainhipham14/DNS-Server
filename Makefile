CC = gcc
CFLAGS = -Wall
EXE = dns_svr
OBJ = dns_svr.o phase1.o client.o error_handling.o
SRC = dns_svr.c phase1.c client.c error_handling.c

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) -lm

clean:
	rm -f $(OBJ) $(EXE)

usage: $(EXE)
	./$(EXE)

