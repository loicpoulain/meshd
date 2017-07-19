# meshd
Bluetooth mesh stack POC for Linux
In development...

dependencies:
- glib
- Request (for now) crypto kernel UAPI with following config:
CRYPTO_USER_API_SKCIPHER, CRYPTO_ECB
CRYPTO_USER_API_HASH, CRYPTO_CMAC
CRYPTO_USER_API_AEAD, CRYPTO_CCM


build meshd:
- make


Only User control via SIGUSR1/2:

1. run meshd on device 1
- sudo ./meshd

2. run meshd on device 2
- sudo ./meshd

3. Self provisioning & provisioning of device 2
- sudo killall -SIGUSR1 meshd

4. Wait for provisioning complete

5. Send a mesh message from device 2 to 1
- sudo killall -SIGUSR2 meshd
