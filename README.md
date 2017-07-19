# bluetooth-mesh
Bluetooth mesh stack POC for Linux

build meshd:
$ make

In development state, only basic function via signal can be tested:

1. run meshd on device 1
	$ sudo ./meshd

2. run meshd on device 2
	$ sudo ./meshd

3. Provision device 2 from device 1
	$ sudo killall -SIGUSR1 meshd

4. Wait for provisioning complete

5. Send a mesh message from device 2 to 1
	$ sudo killall -SIGUSR2 meshd
