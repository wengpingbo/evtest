evtest: evdev_test.c
	$(CROSS_COMPILE)gcc -static -s -o $@ $<
clean:
	rm -f evtest
