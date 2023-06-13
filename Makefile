ifeq ($(origin KERNEL_PATH), undefined)
  $(error "KERNEL_PATH not set")
endif

ifeq ($(origin LLVM_PATH), undefined)
  $(error "LLVM_PATH not set")
endif

ifeq ($(origin CROSS_COMPILE_TRIPLET), undefined)
  $(error "CROSS_COMPILE_TRIPLET not set")
endif

export PATH := $(LLVM_PATH):$(PATH)

obj-m += tracer.o

client:
	$(LLVM_PATH)/$(CROSS_COMPILE_TRIPLET)clang tracer_client.c -o tracer_client

module:
	make -C $(KERNEL_PATH) LLVM=1 ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE_TRIPLET) M=$(PWD) modules

all: client module


clean:
	rm -f tracer_client
	make -C $(KERNEL_PATH) M=$(PWD) clean

push: all
	adb push tracer.ko tracer_client /data/local/tmp/

