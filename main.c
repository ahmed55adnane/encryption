#include <stdio.h>
#include <stdlib.h>

/*int main()
{
    printf("enter the string : \n");
    scanf("%s", report);
    return 0;
}*/

#define CBC 1
#include "aes.h"

//Initialization Vector
uint8_t iv[]  = { 0x75, 0x52, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x21, 0x21 };

char* report = "my super secret thing that needs to remain that way!";
char* key = "thisIstheKey";



int dlen = strlen(report);          # the length of the report
int klen = strlen(key);             # the length of the key

int dlenu = dlen;
if (dlen % 16) {
    dlenu += 16 - (dlen % 16);      # make the length multiple of 16 bytes
}

int klenu = klen;
if (klen % 16) {
    klenu += 16 - (klen % 16);      # make the length multiple of 16 bytes
}



// Make the uint8_t arrays
uint8_t hexarray[dlenu];
uint8_t kexarray[klenu];

// Initialize them with zeros
memset( hexarray, 0, dlenu );
memset( kexarray, 0, klenu );


// Fill the uint8_t arrays
for (int i=0;i<dlen;i++) {
    hexarray[i] = (uint8_t)report[i];
}
for (int i=0;i<klen;i++) {
    kexarray[i] = (uint8_t)key[i];
}



int reportPad = pkcs7_padding_pad_buffer( hexarray, dlen, sizeof(hexarray), 16 );
int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );


//start the encryption
struct AES_ctx ctx;
AES_init_ctx_iv(&ctx, kexarray, iv);

// encrypt
AES_CBC_encrypt_buffer(&ctx, hexarray, dlenu);


// reset the iv !! important to work!
AES_ctx_set_iv(&ctx,iv);

// start decryption
AES_CBC_decrypt_buffer(&ctx, hexarray, dlenu);

size_t actualDataLength = pkcs7_padding_data_length( hexarray, dlenu, 16);

printf("the decrypted STRING = ");
for (i=0; i<actualDataLength;i++){
    printf("%02x",hexarray[i]);
}
printf("\n");



