obj-m := nfilt.o
KDIR = linux
MAKE = make

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules 

clean:
	$(MAKE) -C linux M=$(PWD) clean
