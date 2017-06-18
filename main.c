#include <stdio.h>
#include <stdlib.h>

#include "ota_coder.h"
#include "../vos/coders.h"

typedef unsigned char uchar;
#include "../vos/hexdump.c"

#include <openssl/des.h>

ota_coder C,*c=&C;



void test1( ) { // from example: https://adywicaksono.wordpress.com/2008/05/21/understanding-gsm-0348/
char data[256],out[256];
// ! data starts after 14 bytes (cntr[5]+pcntr[1]+crc[8])
int  dl = hexstr2bin_(data,sizeof(data),"010E0A8A0E1BD80CABB2C3F3903D80EF579BAEECBE6941A6DC0D437D553FE120026765CF497DEE5D",-1);
ota_coder_init(c,"0021","30423042304430443045304530463046","0123456789ABCDEF100276FEDCBA0123","000000","0101010103",8);
hexdump("IN-data",data,dl);
cbc3_decode(out,data,dl,c->kic);
// ok - now decode it?
hexdump("outdata",out,dl);
hexdump("dataHERE",out+14,dl-14); // no header
 // 80 e6 02 00 12 07 a0 00 00 00 18 50 60 00 00 06 ef 04 c6 02 01 d8 00 00 00 00
printf("CodeBack\n");

char tar[3]={0,0,0},cntr[5]={0,0,0,0,2};
int res = ota_code_packet(c, 0x0E,0x19,   0x25,0x25, tar, cntr, out+14,dl-14);

printf("Coded res=%d\n",res);

if (res>0) hexdump("Data",c->CPL,res);

}

void test2( ) { // check RFM from https://adywicaksono.wordpress.com/2008/06/21/remote-file-management-rfm-on-simcard/
char data[256],out[256];
ota_coder_init(c,"0021","00112233445566778899AABBCCDDEEFF","00112233445566778899AABBCCDDEEFF","B0 00 10","000000",4);
// ok - now decode it?
int  dl = hexstr2bin_(data,sizeof(data),"25 4E 56 31 DF  D0 4D 77 DC 9C 64 90 30 E6E8 97 DF 57 49 4B FC 45 11 71 56 2B 5E D3 FF C0 11 AA"
                      "62 CA 46 B6 4A 51 B0 A8 52 B3 CC 9F D0 6B 0D 95C0 E8 DB E7 BF 44 25 39 67 90 B6 E2 22 BE C3 3FEF 5B 35 2D 9D F7 97 22 15 08 67 F4 AA 29 A5 73",-1);
                      ;
hexdump("test2:indata",data,dl);
cbc3_decode(out,data,dl,c->kic); //,s->kic+8,s->kic+16); // encode m
hexdump("test2:oudata",out,dl); // secure data from counter+pcounter+dc(4)
hexdump("sec_data",out+14,dl-14); // secure data from counter+pcounter+dc(4)

}




int cbc1_sign__(char *keys,char *src,int len,char *kid) {
    char dst[256];
    hex_dump("DATA4SIGN",src,len);
    cbc3_encode(dst,src,len,kid);
    hex_dump("DST_SIGN",dst,len);
    return 1;
}

int cbc1_sign(char *keys,char *src,int len,char *kid) {
DES_cblock cb1,cblock;
DES_key_schedule k;


memcpy(&cb1,kid,8); DES_set_key(&cb1,&k);
memset(&cblock,0,sizeof(DES_cblock));
//DES_set_odd_parity(&cblock);
//void DES_cbc_encrypt(const unsigned char *input,unsigned char *output,
		  //   long length,DES_key_schedule *schedule,DES_cblock *ivec,
		  //   int enc);
char dst[512];
/*
DES_cbc_encrypt((const unsigned char*)src, // outer triple cbc des
                         (unsigned char*)dst,
                          len, &k, &cblock,DES_DECRYPT);
hexdump("sec_decrypt",dst,len);
*/
memcpy(&cb1,kid,8); DES_set_key(&cb1,&k);
memset(&cblock,0,sizeof(DES_cblock));
//DES_set_odd_parity(&cblock); // Что это? Я не знаю...

DES_cbc_encrypt((const unsigned char*)src, // outer triple cbc des
                         (unsigned char*)dst,
                          len, &k, &cblock,DES_ENCRYPT);
 //hexdump("sec_encrypt",dst,len);

memcpy(&cb1,kid,8); DES_set_key(&cb1,&k);
memset(&cblock,0,sizeof(DES_cblock));
//DES_set_odd_parity(&cblock);

int code =  DES_cbc_cksum(src, (void*)keys, len, &k, &cblock ); // -> last DES_ENCRYPT

    printf("SIGN = %x \n",code);
  return 1;
}


int ota_encode(ota_coder *c,unsigned char *data, int dl) {
// first - need to setup headers
if (dl>sizeof(c->other)) { printf("ota_encode size tooo big %d max is %d\n",dl,sizeof(c->other)); return 0;}
c->SPI[0]=0x15; c->SPI[1]=0x21; c->KIC=0x15; c->KID=0x15;
memcpy(c->TAR,c->tar,3); memcpy(c->CNTR,c->cntr,5); // copy tar and counter
int cc_length=4; // mac_sign length -> to be extracted from  spi

c->CHL = 0x11;
c->CPL[0]=0; c->CPL[1]=0x40; // full length


int cipher_length= 2+1+ // !!! (!) CPL and CHL MAY be signed or not - is is option (!!!) -- see 23.048 table2
     2+1+1+3+5+1 + dl;  // SPI(2),KIC,KID,TAR,CNTR+PCNTR+ALL_DATA  -- RC/CC/DS not signed
unsigned char *cipher_data = &c->CPL[0]; // see prev comment - ciphering CPL is an option (!!!)

int crypto_length = 5+1+cc_length+dl;

printf("OTA_ENCODE_BEGIN %d bytes\n",dl);
  hexdump("OTA_ENCODE_DATA",data,dl);


hexdump("Digest_data",cipher_data,cipher_length);

//int code_CPL = 0; if (!code_CPL) {  cipher_data=&c->SPI[0]; cipher_length=2+1+1+3+5+1 + dl;}


//{  cipher_data=&c->SPI[0]; cipher_length=2+1+1+3+5+1 + dl;}


int last_oct = crypto_length%8; if (last_oct) { c->PCNTR=8-last_oct; crypto_length+=c->PCNTR; cipher_length+=c->PCNTR;}
printf("DataLength=%d Digest_length=%d crypto_len=%d padding=%d expect=3\n",dl,cipher_length,crypto_length,c->PCNTR);



//c->PCNTR=0x02; // we know it

memset(c->other,0,sizeof(c->other));
memcpy(c->RC,data,dl); // copy all data here

hexdump("digest_data",cipher_data,cipher_length);

char keys[8]; memset(keys,0,sizeof(keys));
cbc1_sign(keys,cipher_data,cipher_length,c->kid);
hexdump("EXPECT: 66 fc a6 b2  ",keys,8);

//char out[256];
//cbc3_decode(out,cipher_data,cipher_length,c->kid);
//hexdump("CB3_CODE:",out,cipher_length);


//printf("CRC32=%x\n", Crc32(cipher_data,cipher_length));

//printf("CRC32=%x\n", crc32(0xFFFFFFFF,cipher_data,cipher_length));
//printf("CRC32[0]=%x\n", crc32(0,cipher_data,cipher_length-dl));

//printf("CRC_XXX=%x\n", crc8PushBlock(0,cipher_data,cipher_length));
hexdump("HEADER_CPL",&c->CPL,32);


return 1;
}

void test0() {
char data[256],out[256];
ota_coder_init(c,"0021","8EBCB3ACE49FF15F5D39E3AD21C559DA","BCAB2A7C6E44B89E11441E1B6DEF0591",
                "B00000","00 00 00 0101",4);
int  dl = hexstr2bin_(data,sizeof(data),
  "0B 27 AD E8 C7 37  5F  E2 EB 8A 3F EE 1E 19 FE 30 9C EB 06 0C A6 78 F9 AF D5 21 CD 89 9D 51 82 D8 B7 12 D9 A7 90 D3 E5 DA 51 DB CA 5F 0B 03 21 7B B3 D5 47 0D 50 D5 49 43",-1);
printf("DL=%d bytes\n",dl);
hexdump("InData",data,dl);

cbc3_decode(out,data,dl,c->kic); //,s->kic+8,s->kic+16); // encode m
hexdump("OutData",out,dl);

char data2[256];
cbc3_encode(data2,out,dl,c->kic); // cipher back
   hexdump("INdata",data2,dl);

hexdump("Data",out+10,dl-10); // 4 bytes

// 01 01 01 00 00    -- 02    -- 67 fd a6 b2
printf("Encode back\n");
  //ota_encode(c,out+10,dl-10-3); // no zero, ok - padding = 3!

unsigned char tar[3]={ 0xb0,0,0}, cntr[5]={0,0,0,0x1,0x1};
int res = ota_code_packet(c, 0x15, 0x21,   0x15,0x15, tar, cntr,
                           out+10,dl-10-3);

printf("res code=%d\n",res);
return 1;
}


void test00() {
char data[200];
ota_coder_setkeys(c,"8EBCB3ACE49FF15F5D39E3AD21C559DA","BCAB2A7C6E44B89E11441E1B6DEF0591");
int dl = hexstr2bin_(data,sizeof(data),"A0A40000023F00A0A40000027F20A0A40000026F46A0D60000110054657374FFFFFFFFFFFFFFFFFFFFFFFF",-1);
unsigned char tar[3]={ 0xb0,0,0}, cntr[5]={0,0,0,0x1,0x1};
int res = ota_code_packet(c, 0x15, 0x21,   0x15,0x15, tar, cntr,data,dl);
printf("Result=%d coding=%d bytes\n",res,dl);
if (res>0) hexdump("Packet:",c->CPL,res);
// expects::
// Result=66 coding=43 bytes
// Packet::00 40 11 15 21 15 15 b0 00 00 0b 27 ad e8 c7 37 5f e2 eb 8a 3f ee 1e 19 fe 30 9c eb 06 0c a6 78 f9 af d5 21 cd 89 9d 51 82 d8 b7 12 d9 a7 90 d3 e5 da 51 db ca 5f 0b 03 21 7b b3 d5 47 0d 50 d5 49 43
}


uchar mySPI1,mySPI2,myKIC,myKID,myTAR[3]={0xb0,0,0},myData[512],myCntr[5];
int myDataLen;


int my_compain() { // simple compain
char buf[400],*cmd,bCntr[5];
int cnt  = 0;
fprintf(stderr,"OTA_START: <spi1=0x%02X,spi2=0x%02X,kic=0x%02X,kid=0x%02X,tar=%02X%02X%02x>\n",
            mySPI1,mySPI2,myKIC,myKID,myTAR[0],myTAR[1],myTAR[2]);
while(1) {
  gets(buf);
  // expect_in: ID(MSISDN,ICCID) KIC KID CNTR,  produce out: ID CODEDMSG
  cmd = buf;
  char *id = get_word(&cmd);
  if (!*id) break;
  char *kic = get_word(&cmd);
  char *kid = get_word(&cmd);
  char *cntr = get_word(&cmd);
  char *data = get_word(&cmd);
  if (!cntr || !*cntr) break; // any amty string -> break
    ota_coder_setkeys(c,kic,kid); // prepare coding
     int l =hexstr2bin_(myCntr,sizeof(myCntr),cntr,-1);
     if (l!=5) {
         fprintf(stderr,"cntr: expect 5 bytes found %d in '%s'\n",l,cntr);
         exit(2);
     }
  myDataLen = hexstr2bin_(myData,sizeof(myData),data,-1);
     if (myDataLen<=1) {
         fprintf(stderr,"ota_data: empty data");
         exit(3);
     }
     int res = ota_code_packet( c, mySPI1,mySPI2, myKIC, myKID, myTAR, myCntr, myData, myDataLen);
     if (res<0) {
        fprintf(stderr,"ota_code_packet returns error %d. Abort\n",res);
        exit(5);
     }
     printf("%s\t027000",id);
       unsigned char *out=&c->CPL[0];
       int i; for(i=0;i<res;i++) printf("%02X",out[i]);
     printf("\n");
     cnt++;
  }
fprintf(stderr,"OTA_END: coded %d records\n",cnt);
return 0; // OK
}

int getMyIntDef(char **pcmd,int def) {
 char *w = get_till(pcmd,",",1);
 if (!w || !*w) return def;
 if (lcmp(&w,"0x")) sscanf(w,"%x",&def); // try read hex
     else sscanf(w,"%d",&def); // try read int
 return def;
}

int cmd_ota(char *cmd) {
  mySPI1=getMyIntDef(&cmd,0x15);
  mySPI2=getMyIntDef(&cmd,0x21);
  myKIC=getMyIntDef(&cmd,0x15);
  myKID=getMyIntDef(&cmd,0x15);
     int l =  hexstr2bin_( myTAR,sizeof(myTAR), get_till(&cmd,",",1),-1);
     //printf("tar=%d\n",l);
  return my_compain();
}


int main(int npar,char **par) {
    if (npar==1) {
        printf("usage <ota=spi1[0x15],spi2[0x21],kic[0x15],kid[0x15],tar=[0xb0,0,0]>\n");
        return 1;
    }
    char *cmd = par[1];
    if (lcmp(&cmd,"ota=")) return cmd_ota(cmd);

    printf("command unknown run self test ^)\n");

    ota_coder_begin(c);
    //ota_coder_init(c,"0021","8EBCB3ACE49FF15F5D39E3AD21C559DA","BCAB2A7C6E44B89E11441E1B6DEF0591","0000000100","000000",4);

    //test00(); -- good
    test1();

    //test0();
    //test2();

    printf("Hello world sizeof(ota_coder)=%d!\n",sizeof(ota_coder));
    return 0;
}
