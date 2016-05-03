# @file: Makefile
# @brief:
# @author: YoungJoo.Kim <vozltx@gmail.com>
# @version:
# @date: 20060924

GCC = gcc
TARGET = ipmac
SRC = ipmac.c
OBJ = $(SRC:%.c=%.o)
CFLAGS = -Wall
LIB = -lpcap
INC =
#DEF = -DDEBUG

.SUFFIXES: .c
%.o: %.c
	$(GCC) $(CFLAGS) $(DEF) $(INC) -c $< -o $@

all: $(TARGET)
$(TARGET): $(OBJ)
	$(GCC) -o $@ $(OBJ) $(LIB)

clean:
	rm -f *.o $(TARGET)
