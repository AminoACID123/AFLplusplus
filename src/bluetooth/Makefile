CXXFLAGS = -I$(shell llvm-config --includedir)			\
		   -I$(shell llvm-config --obj-root)/include 	\
		   -L$(shell llvm-config --libdir)/include		\
		   $(shell llvm-config --link-shared --libs)	\
		   -O0 -g


libbluetooth.so: hci.cpp
	clang++ --shared  $(CXXFLAGS) -fPIC $< -o $@