git clone https://github.com/vSlipenchuk/vos.git
git clone https://github.com/vSlipenchuk/ota_coder.git

cd ota_coder

gcc -o ota_coder main.c ota_coder.c common.c -lcrypto