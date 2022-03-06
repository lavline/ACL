
TARGET = aclContest

$(TARGET): *.c
	@echo Create $@ ...
	@g++ -O2 -o $@ $^ -L. -lxbench-mingw32

.PHONY : clean

clean:
	@echo Cleaning $(TARGET) ...
	@rm -f $(TARGET)
	
