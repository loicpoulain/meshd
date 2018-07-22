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

Basic interactive interface for now

1. run meshd on device 1
sudo ./meshd -i

2. run meshd on device 2
sudo ./meshd -i

3. Create network on device 1
net-create

4. Scan unprovisioned nodes on device 1
scan on

5. Provision discovered node with address 0x1245
scan off
provision 00000000-0000-0000-0000-000000000000 0x1245

6. Wait for provisioning complete
