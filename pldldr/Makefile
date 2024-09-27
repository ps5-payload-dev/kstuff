all: payload.bin

clean:
	rm -f payload.elf payload.bin

../lib/lib.a:
	cd ../lib; make

payload.elf: ../lib/lib.a main.c
	gcc -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a main.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -Wl,-z,max-page-size=16384 -Wl,-zcommon-page-size=16384

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata --set-section-flags .bss=content,alloc,data -O binary payload.bin
	python3 ../lib/frankenelf.py $@
