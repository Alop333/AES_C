
CC = gcc           
CFLAGS = -Wall -O3 
TARGET = aes       
SRC = aes.c        


$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)


clean:
	rm -f $(TARGET)


debug: CFLAGS += -g
debug: $(TARGET)

.PHONY: clean debug
