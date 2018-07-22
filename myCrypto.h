/*----------------------------------------------------------------------------
PA-02: Messaage Digest using Pipes
Written By: 
     1- Dr. Mohamed Aboutabl
Submitted on: 
----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

void     handleErrors( char *msg) ;
int      encrypt_str( unsigned char *plaintext,  unsigned char *ciphertext, unsigned char *key, unsigned char *iv, int plaintext_len ) ;
int      decrypt_str( unsigned char *ciphertext, unsigned char *plaintext,  unsigned char *key, unsigned char *iv, int ciphertext_len ) ;
void     encrypt_file( int fd_in, int fd_out, unsigned char *key, unsigned char *iv ) ;
void     decrypt_file( int fd_in, int fd_out, unsigned char *key, unsigned char *iv ) ;
