/*
 Generate encryption key / IV and save to binary files
*/
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
void main()
{
	uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;

	unsigned key_len = EVP_MAX_KEY_LENGTH ;
	unsigned iv_len = EVP_MAX_IV_LENGTH ;
	int fd_key_amal, fd_iv_amal, fd_key_basim, fd_iv_basim ;

    // Open amal key and iv
	fd_key_amal = open("key_amal.bin", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR) ;

 	if( fd_key_amal == -1 )
 	{
 		fprintf(stderr, "Unable to open file for key_amal\n");
 		exit(-1) ;
 	}

 	fd_iv_amal = open("iv_amal.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;

 	if( fd_iv_amal == -1 )
 	{
 		fprintf(stderr, "Unable to open file for IV_amal\n");
 		exit(-1) ;
 	}

    // Open basim key and iv
    fd_key_basim = open("key_basim.bin", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR) ;

 	if( fd_key_basim == -1 )
 	{
 		fprintf(stderr, "Unable to open file for key_basim\n");
 		exit(-1) ;
 	}

 	fd_iv_basim = open("iv_basim.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;

 	if( fd_iv_basim == -1 )
 	{
 		fprintf(stderr, "Unable to open file for IV_basim\n");
 		exit(-1) ;
 	}

 	// Genrate the random key & IV for amal
 	RAND_bytes( key , key_len );
 	RAND_bytes( iv , iv_len );

 	write( fd_key_amal , key , key_len );
 	write( fd_iv_amal , iv , iv_len );

    // Genrate the random key & IV for basim
 	RAND_bytes( key , key_len );
 	RAND_bytes( iv , iv_len );

 	write( fd_key_basim , key , key_len );
 	write( fd_iv_basim , iv , iv_len );

    // Close files
 	close( fd_key_amal ) ;
	close( fd_iv_amal ) ;
    close( fd_key_basim ) ;
	close( fd_iv_basim ) ;
}
