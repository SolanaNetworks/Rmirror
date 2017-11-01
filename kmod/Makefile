obj-m += xt_rmirror.o

all:
	make -C /lib/modules/${KERNELVERSION}/build M=$(PWD) modules

clean:
	make -C /lib/modules/${KERNELVERSION}/build M=$(PWD) clean
