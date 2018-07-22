#include "../myCrypto.h"

int main( int argc , char *argv[] )
{
    char amal_id[5] = "Amal", basim_id[6] = "Basim", len_a_str[5], len_b_str[5],
			bytes_n_str[5], len_encr_str[5] ;
	char *amal_id_recv, *basim_id_recv, *nonce_recv ;
    unsigned char *recv_buffer, *package, *package_encr, *sub_pack, *sub_pack_encr ;
    int fd_AtoKDC_ctrl, fd_KDCtoA_ctrl, fd_key_a, fd_iv_a, fd_key_b, fd_iv_b ;
    int len_package, len_amal, len_basim, bytes_nonce, i, len_encr, count = 0 ;
    uint8_t key_a[EVP_MAX_KEY_LENGTH], iv_a[EVP_MAX_IV_LENGTH],
            key_b[EVP_MAX_KEY_LENGTH], iv_b[EVP_MAX_IV_LENGTH],
            key_s[EVP_MAX_KEY_LENGTH], iv_s[EVP_MAX_IV_LENGTH] ;
    unsigned key_len = 32 ;
    unsigned iv_len = 16 ;
    FILE *log ;

    /* BIO objects */
    BIO *bio_stdout;

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // Set up pipes from command line args
    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_AtoKDC_ctrl = atoi( argv[1] ) ;
    fd_KDCtoA_ctrl = atoi( argv[2] ) ;

    // Open the log file
    log = fopen("kdc/logKDC.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is The KDC. Could not create log file\n");
        exit(-1) ;
    }

    // Get Amal's master key
    fd_key_a = open("key_amal.bin" , O_RDONLY ) ;
    if( fd_key_a == -1 )
    { fprintf( log , "\nCould not open Amal's master key\n"); exit(-1) ;}

    read ( fd_key_a , key_a , key_len ) ;
    close( fd_key_a ) ;

    // Get Amal's master IV
    fd_iv_a = open("iv_amal.bin" , O_RDONLY ) ;
    if( fd_iv_a == -1 )
    { fprintf( log , "\nCould not open Amal's master IV\n"); exit(-1) ;}

    read ( fd_iv_a , iv_a , iv_len ) ;
    close( fd_iv_a ) ;

    // Get Basim's master key
    fd_key_b = open("key_basim.bin" , O_RDONLY ) ;
    if( fd_key_b == -1 )
    { fprintf( log , "\nCould not open Basim's master key\n"); exit(-1) ;}

    read ( fd_key_b , key_b , key_len ) ;
    close( fd_key_b ) ;

    // Get Basim's master IV
    fd_iv_b = open("iv_basim.bin" , O_RDONLY ) ;
    if( fd_iv_b == -1 )
    { fprintf( log , "\nCould not open Basim's master IV\n"); exit(-1) ;}

    read ( fd_iv_b , iv_b , iv_len ) ;
    close( fd_iv_b ) ;

    /* Initialize the BIO for BASE64 input/output */
    bio_stdout = BIO_new_fp( log , BIO_NOCLOSE );

    //----------------------------------------------------------------------------------------
    // MESSAGE 1

    // Receive length of message 1 from Amal
	recv_buffer = malloc(3);
    if ( read(fd_AtoKDC_ctrl, recv_buffer, 2 ) < 0 )
    { fprintf( log , "This is The KDC: error reading message 1 length\n" ); exit(-1) ;}

    len_package = atoi(recv_buffer);
	free(recv_buffer);

    // Receive message 1 from Amal
	recv_buffer = malloc(len_package);
    if ( read(fd_AtoKDC_ctrl, recv_buffer, len_package ) < 0 )
    { fprintf( log , "This is The KDC: error reading message 1\n" ); exit(-1) ;}

    // Get Amal's ID
    memcpy( len_a_str, recv_buffer, 1 ) ;
    count += 1;
	len_amal = atoi( len_a_str ) ;

	amal_id_recv = malloc( len_amal ) ;
	memcpy( amal_id_recv, recv_buffer + count, len_amal ) ;
    count += len_amal;
	amal_id_recv[len_amal] = '\0' ;

    // Get Basim's ID
    memcpy( len_b_str, recv_buffer + count, 1 ) ;
    count += 1;
	len_basim = atoi( len_b_str ) ;

	basim_id_recv = malloc( len_basim ) ;
	memcpy( basim_id_recv, recv_buffer + count, len_basim ) ;
    count += len_basim;
	basim_id_recv[len_basim] = '\0' ;

    // Get the nonce
    memcpy( bytes_n_str, recv_buffer + count, 2 ) ;
    count += 2;
	bytes_nonce = atoi( bytes_n_str ) ;

	nonce_recv = malloc( bytes_nonce ) ;
	memcpy( nonce_recv, recv_buffer + count, bytes_nonce ) ;
    count = 0;

    // Write to log
    fprintf( log , "This is The KDC: Recieved message 1: \nID_a || ID_b || N_a\n\n" ) ;
	fprintf( log , "ID_a: %s\n", amal_id_recv ) ;
	fprintf( log , "ID_b: %s\n", basim_id_recv ) ;
	fprintf( log , "N_a:\n" );
	BIO_dump( bio_stdout, (const char *) nonce_recv , bytes_nonce );

    // Check if the IDs are valid
    if ( strcmp(amal_id_recv, amal_id) != 0 || strcmp(basim_id_recv, basim_id) != 0 )
    { fprintf( log , "This is The KDC: The IDs do not match the expected values!\n" ); exit(-1) ;}

	free(recv_buffer);

    //----------------------------------------------------------------------------------------
    // MESSAGE 2

    // Generate symmetric key and IV
    RAND_bytes( key_s , key_len );
 	RAND_bytes( iv_s  , iv_len  );

    // Package the part of message 1 that will eventually be sent to Basim
    len_amal = strlen(amal_id_recv);

    // Malloc for the plaintext sub package
	len_package = key_len + iv_len + sizeof(int) + strlen(amal_id_recv) ;
    sub_pack = malloc( len_package );

    // Malloc for the ciphertext sub package, leaving room for padded bytes
    sub_pack_encr = malloc( len_package + 32 );

    // Build the plaintext sub string
    memcpy( sub_pack + count, key_s, key_len ) ;
    count += key_len;
    memcpy( sub_pack + count, iv_s, iv_len   ) ;
    count += iv_len;
    memcpy( sub_pack + count, &len_amal, sizeof(int) ) ;
    count += sizeof(int);
    memcpy( sub_pack + count, amal_id_recv, len_amal ) ;
    count = 0;

    // Encrypt the sub package with Basim's master key
    len_encr = encrypt_str( sub_pack, sub_pack_encr, key_b, iv_b, len_package );

    // Begin building entire plaintext message 2
    len_basim = strlen(basim_id_recv);

    // Malloc for the plaintext package
    len_package = key_len + iv_len + sizeof(int) + strlen(basim_id_recv) + sizeof(int) + 
                  strlen(nonce_recv) + sizeof(int) + len_encr ;
    package = malloc(len_package);

    // Malloc for the ciphertext package, leaving room for padded bytes
    package_encr = malloc(len_package + 32);

    // Build the package for message 2
    memcpy( package + count, key_s, key_len ) ;
    count += key_len;
    memcpy( package + count, iv_s, iv_len ) ;
    count += iv_len;
    memcpy( package + count, &len_basim, sizeof(int) ) ;
    count += sizeof(int);
    memcpy( package + count, basim_id_recv,	strlen(basim_id_recv) ) ;
    count += strlen(basim_id_recv);
    memcpy( package + count, &bytes_nonce, sizeof(int) ) ;
    count += sizeof(int);
    memcpy( package + count, nonce_recv, bytes_nonce ) ;
    count += bytes_nonce;
    memcpy( package + count, &len_encr, sizeof(int) ) ;
    count += sizeof(int);
    memcpy( package + count, sub_pack_encr, len_encr) ;
    count = 0;

    // Encrypt message 2 with Amal's master key
    len_encr = encrypt_str( package, package_encr, key_a, iv_a, len_package );

    // Write to log
    fprintf( log , "\n\nThis is The KDC: Sending message 2 to Amal:\n" ) ;
    fprintf( log , "E( K_a, K_s || IV_s || ID_b || N_a || E( K_b, K_s || IV_s || ID_a ) )\n\n" ) ;
	fprintf( log , "K_s:\n" );
    BIO_dump( bio_stdout, (const char *) key_s , key_len );
	fprintf( log , "IV_s:\n" );
    BIO_dump( bio_stdout, (const char *) iv_s , iv_len );
	fprintf( log , "ID_b: %s\n", basim_id_recv );
	fprintf( log , "N_a:\n" );
	BIO_dump( bio_stdout, (const char *) nonce_recv , bytes_nonce );
	fprintf( log , "ID_a: %s\n", amal_id ) ;

    // Send the length of message 2 to Amal
    if ( write(fd_KDCtoA_ctrl, &len_encr, sizeof(int) ) < 0 )
    { fprintf( log , "\nThis is The KDC: error writing length of message 2 to the pipe\n" ); exit(-1) ;}

    // Send message 2 to Amal
    if ( write(fd_KDCtoA_ctrl, package_encr, len_encr ) < 0 )
    { fprintf( log , "This is The KDC: error writing message 2 to the pipe\n" ); exit(-1) ;}

    //----------------------------------------------------------------------------------------
    // End of The KDC's duties

    // Free allocated memory
    free(sub_pack);
    free(sub_pack_encr);
    free(package);
    free(package_encr);

    // Close log file
    fclose( log );

    // Close pipes
    close(fd_AtoKDC_ctrl);
    close(fd_KDCtoA_ctrl);

    /* Clean up */
 	BIO_flush ( bio_stdout );
 	EVP_cleanup();
 	ERR_free_strings();
}
