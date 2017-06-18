#ifndef OTA_CODER_H
#define OTA_CODER_H

/*
   Good start: https://adywicaksono.wordpress.com/2008/05/21/understanding-gsm-0348/

   Linking: need crypto (openssl)

*/

enum {
   spi1_no_rc = 0,
   spi1_rc = 1,  // RC - 4 bytes?
   spi1_cc = 2,  // CRC
   spi1_ds = 3, //  DS can be 4 or 8 bytes long
   };

enum { // b4b3b2b1 bits of KIC & KID
     DES_CBC = 1,
   DES3_2k = 5,  // OK SUPPORTED, use IT !
     DES3_3k = 8+1, // unsupported by cards
  };


typedef struct { // 03.48 header
    // OTA setting, set by ota_coder_init
    unsigned char spi[2],kic[24],kid[24],cntr[5],tar[3],cc_length;

    unsigned char UDHL[3];  // SMS USER DATA HEADER REQUIRED CONSTANT (LEN=2, IEI=0x70,EIDL=00)
    // command packet 23.048
    unsigned char CPL[2],CHL,SPI[2],KIC,KID,TAR[3],CNTR[5],PCNTR,RC[8],other[256]; // real RC vary form 0 to 8 bytes
  } __attribute__((packed))  ota_coder;



void ota_coder_setkeys(ota_coder *c,char *sz_kic, char *sz_kid);
int  ota_code_packet(ota_coder *c,unsigned char spi1, unsigned char spi2, unsigned char kic, unsigned char kid,
                      unsigned char tar[3], unsigned char cntr[5], unsigned char *data, int len);


// deprecated
void ota_coder_begin(ota_coder *c); // clear all data and prepare for encoing...
int ota_encode(ota_coder *c,unsigned char *data, int len); // copy , sign & encrypt data, >0 on success


#endif // OTA_CODER_H
