OS:=$(shell uname)
CXX:=g++
CXX_STANDARD:=-std=c++17
LINKER:=-shared
DFLAGS:=-D USE_INTEL_AESNI -maes
CXX_FLAGS=-O3 -Wall -Wextra
PYTHON_INCLUDE=/usr/include/python3.9/

default:
	$(CXX) $(CXX_STANDARD) $(LINKER) -Wl,-soname,aeslib.so -o aeslib.so aeslib.cpp $(DFLAGS) $(CXX_FLAGS) -fPIC -I $(PYTHON_INCLUDE)

clean:
	@rm aeslib.so
