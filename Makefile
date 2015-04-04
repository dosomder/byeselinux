KERNEL_BUILD := /root/kernel/kernel
KERNEL_CROSS_COMPILE := arm-linux-androideabi-

obj-m += byeselinux.o

all:
	make -C $(KERNEL_BUILD) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE) M=$(PWD) modules

clean:
	make -C $(KERNEL_BUILD) M=$(PWD) clean 2> /dev/null
	rm -f modules.order *~
