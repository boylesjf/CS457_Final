/*-----------------------------------------------------------------------------
Final PA: 

FILE:   myCrypto.c

Written By: Joshua Boyles
     
Submitted on: 
-----------------------------------------------------------------------------*/

#include "myCrypto.h"
#include "wrappers.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------

int encrypt_str( unsigned char *plaintext, unsigned char *ciphertext, 
		unsigned char *key, unsigned char *iv, int plaintext_len )
{
    EVP_CIPHER_CTX *ctx;
    int len, out_len;

    // Create and initialize context
    if( !(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors("Error creating context in encrypt_str");

    // Initialize the encryption operation
    if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors("Error initializing encrypt_str");

    // Provide the message to be encrypted, and obtain the encrypted output
    if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) )
        handleErrors("Error with encrypt_str update");
    out_len = len;

    // Finalize the encryption
    if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) )
        handleErrors("Error with encrypt_str final");
    out_len += len;

    // Clean up
    EVP_CIPHER_CTX_cleanup(ctx);

    // Return
    return out_len;
}

//-----------------------------------------------------------------------------

int decrypt_str( unsigned char *ciphertext, unsigned char *plaintext, 
		unsigned char *key, unsigned char *iv, int ciphertext_len )
{
    EVP_CIPHER_CTX *ctx;
    int len, out_len;

    // Create and initialize context
    if( !(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Error creating context in decrypt_str");

    // Initialize the encryption operation
    if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors("Error initializing decrypt_str");

    // Provide the message to be encrypted, and obtain the encrypted output
    if( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) )
        handleErrors("Error with decrypt_str update");
    out_len = len;

    // Finalize the encryption
    if( 1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len) )
        handleErrors("Error with decrypt_str final");
    out_len += len;

    // Clean up
    EVP_CIPHER_CTX_cleanup(ctx);

    // Return
    return out_len;
}

//-----------------------------------------------------------------------------

void encrypt_file( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	EVP_CIPHER_CTX *ctx;
	char buffer_in[1008] , buffer_out[1024] ;
	int len, read_in = 0;

 	/* Create and initialise the context */
 	if( !(ctx = EVP_CIPHER_CTX_new()) )
 		handleErrors("Error creating context in encrypt_file");

 	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
 	* and IV size appropriate for your cipher
 	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
 	* IV size for *most* modes is the same as the block size. For AES this
 	* is 128 bits */
 	if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
 		handleErrors("Error initializing encrypt_file");

	while (1)
	{
		if ( ( read_in = read(fd_in, buffer_in, 1008) ) <= 0 )
			break;

		/* Provide the message to be encrypted, and obtain the encrypted output.
 		* EVP_EncryptUpdate can be called multiple times if necessary
 		*/
		if( 1 != EVP_EncryptUpdate(ctx, buffer_out, &len, buffer_in, read_in) )
 			handleErrors("Error with encrypt_file update");

		/* Write output to file */
		write( fd_out, buffer_out, len ) ;
	}

	/* Finalise the encryption. Further ciphertext bytes may be written at
 	* this stage.
 	*/
	if( 1 != EVP_EncryptFinal_ex(ctx, buffer_out, &len) )
 		handleErrors("Error with encrypt_file final");

	/* Write output to file */
	write( fd_out, buffer_out, len ) ;

	/* Clean up */
 	EVP_CIPHER_CTX_free(ctx);
}

//-----------------------------------------------------------------------------

void decrypt_file( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	EVP_CIPHER_CTX *ctx;
	char buffer_in[1024] , buffer_out[1024] ;
	int len, read_in = 0;

 	/* Create and initialise the context */
 	if( !(ctx = EVP_CIPHER_CTX_new()) )
 		handleErrors("Error creating context in decrypt_file");

 	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
 	* and IV size appropriate for your cipher
 	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
 	* IV size for *most* modes is the same as the block size. For AES this
 	* is 128 bits */
 	if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
 		handleErrors("Error initializing decrypt_file");

	while (1)
	{
		if ( ( read_in = read(fd_in, buffer_in, 1024) ) <= 0 )
			break;

		/* Provide the message to be encrypted, and obtain the encrypted output.
 		* EVP_EncryptUpdate can be called multiple times if necessary
 		*/
		if( 1 != EVP_DecryptUpdate(ctx, buffer_out, &len, buffer_in, read_in) )
 			handleErrors("Error with decrypt_file update");

		/* Write output to file */
		write( fd_out, buffer_out, len ) ;
	}

	/* Finalise the encryption. Further ciphertext bytes may be written at
 	* this stage.
 	*/
	if( 1 != EVP_DecryptFinal_ex(ctx, buffer_out, &len) )
 		handleErrors("Error with decrypt_file final");

	/* Write output to file */
	write( fd_out, buffer_out, len ) ;

	/* Clean up */
 	EVP_CIPHER_CTX_free(ctx);
}

