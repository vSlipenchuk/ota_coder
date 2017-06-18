#include "ota_coder.h"
#include <openssl/des.h>
#include <inttypes.h>
#include <string.h>
#include "../vos/coders.h"




/*
int hex(unsigned char src) { // Converts char hex representation to a value...
if (src>='0' && src<='9') return src-'0';
if (src>='a' && src<='f') return 10+src-'a';
if (src>='A' && src<='F') return 10+src-'A';
return -1; }
*/


int hexstr2bin_(unsigned char *out,int out_sz,unsigned char *in, int len) {
int r=0;
if (len<0) len = strlen((char*)in);
while(len>0 && out_sz>0) {
    int h = hex(*in),h2;
    len--; in++;
    if (h<0) continue; // skip
    if (len>0) { // try next
        h2 = hex(*in); if (h2>=0) { h=h*16+h2; }
        len--; in++;
        }
    if (out) { *out=h; out++;}
    out_sz--; r++;
    }
//if (out) {*out=0;} // terminate
return r;
}


int cbc3_encode(char *dst,char *src, int len, unsigned char *key) {
DES_key_schedule ks1,ks2,ks3;
DES_cblock cb1,cb2,cb3;
memcpy(&cb1,key,8); memcpy(&cb2,key+8,8); memcpy(&cb3,key+16,8);

DES_cblock cblock; //' = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  if (DES_set_key(&cb1, &ks1) ||
        DES_set_key(&cb2, &ks2) ||
         DES_set_key(&cb3, &ks3)) {
      printf("Key error!!!, exiting ....\n");
      return -1;
   }

memset(cblock,0,sizeof(DES_cblock));
//DES_set_odd_parity(&cblock);
DES_ede3_cbc_encrypt((const unsigned char*)src, // outer triple cbc des
                         (unsigned char*)dst,
                          len, &ks1, &ks2, &ks3,
                                     &cblock,DES_ENCRYPT);

return len;
}

int cbc3_decode(char *dst,char *src, int len, unsigned char *key) {
DES_key_schedule ks1,ks2,ks3;
DES_cblock cb1,cb2,cb3;
memcpy(&cb1,key,8); memcpy(&cb2,key+8,8); memcpy(&cb3,key+16,8);

DES_cblock cblock; //' = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  if (DES_set_key(&cb1, &ks1) ||
        DES_set_key(&cb2, &ks2) ||
         DES_set_key(&cb3, &ks3)) {
      printf("Key error!!!, exiting ....\n");
      return -1;
   }

memset(cblock,0,sizeof(DES_cblock));

//DES_set_odd_parity(&cblock);

DES_ede3_cbc_encrypt((const unsigned char*)src, // outer triple cbc des
                         (unsigned char*)dst,
                          len, &ks1, &ks2, &ks3,
                                     &cblock,DES_DECRYPT);

return len;
}

uint32_t ota_CRC32(unsigned char *buf, int len) {
    uint32_t crc_table[256],crc; int i, j;
    for (i = 0; i < 256; i++)   {
        crc = i;
        for (j = 0; j < 8; j++)
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;

        crc_table[i] = crc;
    };
    crc = 0xFFFFFFFFUL;
    while (len--)
        crc = crc_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFUL;
}



void ota_coder_setkeys(ota_coder *c,char *sz_kic, char *sz_kid) {
int l;
memset(c,0,sizeof(*c));
  l = hexstr2bin_(c->kic,sizeof(c->kic),sz_kic,-1); if (l==16) memcpy(c->kic+16,c->kic,8); // 3DES: copy first key to position 3
}

int cbc1_sign(char *keys,char *src,int len,char *kid);

int ota_code_packet(ota_coder *c,unsigned char spi1, unsigned char spi2, unsigned char kic, unsigned char kid,
            unsigned char tar[3], unsigned char cntr[5], unsigned char *data, int len) {

int cc_type = spi1 & 3, cc_length = 0; // first - define cc_length - depends of RC/CC/DS length which depends from spi1

switch (cc_type) {
  //case spi1_no_rc:  cc_length = 0; break;  // no field
  case spi1_rc   :   cc_length = 4; break; // crc32
  case spi1_cc   :   cc_length = 8; break; // kid ?
  case spi1_ds   :   cc_length = 8; break; // ZU - it can be 4 either (on decoding)
  }

int crypt_need = spi1 & 4;
int crypt_length =  5+1+cc_length+len; // cntr[5]+padding[1]+rc+data [+may be padding]

c->PCNTR=0; // no padding
if (crypt_need) { // may be we need padding bits
   int rest = crypt_length%8;
   if (rest) { c->PCNTR=(8-rest); crypt_length+=c->PCNTR; } // adding a padding
   }

c->SPI[0]=spi1; c->SPI[1]=spi2; c->KIC=kic; c->KID=kid;
memcpy(c->TAR,tar,3); memcpy(c->CNTR,cntr,5);
c->CHL = 13+cc_length;
int full_length = c->CHL+c->PCNTR+len +1  ; // full length data
c->CPL[0]=full_length>>8; c->CPL[1]=full_length&0xFF; // full length

//printf("CHL=0x%x CPL=0x%x cc_length=%d len=%d + p = %d\n",c->CHL,full_length,cc_length,len,c->PCNTR); // expect

if (cc_type) { // need sign, prepare signing buffer
  int cc_size = 2+1+ // !!! (!) CPL and CHL MAY be signed or not - is is option (!!!) -- see 23.048 table2
     2+1+1+3+5+1 + len + c->PCNTR;  // SPI(2),KIC,KID,TAR,CNTR+PCNTR+ALL_DATA  -- RC/CC/DS not signed
  unsigned char *cc_data = &c->CPL[0]; // !! must be corrected if we need more to sign
  memcpy(c->RC,data,len); // copy data
  memset(c->RC+len,0,c->PCNTR); // padding must be zero
  uint32_t crc;

  switch ( cc_type) {
   case  spi1_rc: // RC, same as CRC ?
     crc = ota_CRC32(cc_data,cc_size);
     //hexdump("cc_data  2 sign:",cc_data,cc_size);
     //printf("CRC32=%x\n",crc);
     c->RC[0]= (crc>>24)&0xFF; c->RC[1]=(crc>>16)&0xFF; c->RC[2]=(crc>>8)&0xFF; c->RC[3]=crc&0xFF;
     break;
   case  spi1_cc: // CRC
       { //int cbc1_sign(char *keys,char *src,int len,char *kid) {
          char keys[8]; memset(keys,0,sizeof(keys));
          cbc1_sign(keys,cc_data,cc_size,c->kid);
          //printf("EXPECT e9 a8 7d 53 71 94 a6 c0\n");
          //hexdump("keys",keys,8);
          memcpy(c->RC,keys,8); // copy IT
       }

     break;
   default:
       printf("ota_code_packet -> unsupported singer code %d\n",cc_type);
       return -1;
  }
// now - copy data
memcpy(c->RC+cc_length,data,len); memset(c->RC+cc_length+len,0,c->PCNTR); // ready to sign
 unsigned char *crypt_data = c->CNTR; // data crypted from here
//hexdump("DataForRaw",data,len);
//hexdump("RawData",crypt_data,crypt_length);

if (crypt_need) {
   int crypt_type = kic&0xF;

   unsigned char buf[ crypt_length ]; // big enougth
   switch(crypt_type) {
     case DES3_2k:
         cbc3_encode(buf,crypt_data,crypt_length,c->kic); // cipher back
         //hexdump("CodedData",buf,crypt_length);
         memcpy(crypt_data,buf,crypt_length); // back to packet
         break;
     default:
       printf("ota_packet -> unsupported cypt_type %d\n",crypt_type);
       return -2;
     }

   }
}
return full_length+2; // + sizeof(CPL[2])
}



// deprecated

void ota_coder_begin(ota_coder *c) {
memset(c,0,sizeof(*c));
}


void ota_coder_init(ota_coder *c,char *sz_spi,char *sz_kic, char *sz_kid,char *sz_tar,char *sz_cntr,unsigned char cc_length) {
int l;
  hexstr2bin_(c->spi,sizeof(c->spi),sz_spi,-1);
  l = hexstr2bin_(c->kic,sizeof(c->kic),sz_kic,-1); if (l==16) memcpy(c->kic+16,c->kic,8); // 3DES: copy first key to position 3
  l = hexstr2bin_(c->kid,sizeof(c->kid),sz_kid,-1); if (l==16) memcpy(c->kid+16,c->kid,8); // 3DES: copy first key to position 3
  hexstr2bin_(c->cntr,sizeof(c->cntr),sz_cntr,-1 );
  hexstr2bin_(c->tar,sizeof(c->tar),sz_tar,-1 );
  c->cc_length = cc_length;
}

