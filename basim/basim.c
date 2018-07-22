#include "../myCrypto.h"

int main( int argc , char *argv[] )
{
    unsigned char *recv_buffer, *pack_encr, *package, *nonce_a2_str, *f_n_a2_str, *nonce_b_str ;
    char amal_id_recv[5];
    char amal_id[5] = "Amal", basim_id[6] = "Basim" ;
    int len_recv, len_package, len_encr, bytes_nonce, len_nonce, len_f_nonce, len_amal, count = 0 ;
    int fd_AtoB_ctrl, fd_BtoA_ctrl, fd_AtoB_data, fd_out ;
    uint8_t key_b[EVP_MAX_KEY_LENGTH] , iv_b[EVP_MAX_IV_LENGTH],
            key_s[EVP_MAX_KEY_LENGTH] , iv_s[EVP_MAX_IV_LENGTH] ;
    unsigned key_len = 32 ;
    unsigned iv_len = 16 ;
    unsigned char *pack_5_encr = malloc(64), *package_5 = malloc(64) ;  // Trying to malloc in the message 5
    FILE *log;                                                          // area causes crashes 100% of the time.
    BIGNUM *nonce_b = BN_new() ;                                        // Put the malloc up here so that it
    BIGNUM *nonce_a2 ;                                                  // works at least.
                                                                        // Malloc wouldn't even return so I
    /* Initialise the crypto library */                                 // wanted it to at least work.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* BIO objects */
    BIO *bio_stdout;

    if( argc < 4 )
    {
        printf("Missing command-line arguments: %s\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_AtoB_ctrl = atoi( argv[1] ) ;
    fd_BtoA_ctrl = atoi( argv[2] ) ;
    fd_AtoB_data = atoi( argv[3] ) ;

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }

    /* Initialize the BIO for BASE64 input/output */
    bio_stdout = BIO_new_fp( log , BIO_NOCLOSE );

    // Print key and iv material to the log file
    int fd_key , fd_iv ;

 	fd_key = open("key_basim.bin" , O_RDONLY ) ;
	if( fd_key == -1 )
 	{ fprintf( log , "\nCould not open key_basim.bin\n"); exit(-1) ;}

    fd_iv = open("iv_basim.bin" , O_RDONLY ) ;
	if( fd_key == -1 )
 	{ fprintf( log , "\nCould not open iv_basim.bin\n"); exit(-1) ;}

    read ( fd_key , key_b , 32 ) ;
    fprintf( log , "This is Basim: My master key material is:\n" );
    BIO_dump ( bio_stdout, (const char *) key_b, key_len );
 	close( fd_key ) ;

    read ( fd_iv , iv_b , 16 ) ;
    fprintf( log , "\nThis is Basim: My master iv material is:\n" );
    BIO_dump ( bio_stdout, (const char *) iv_b , iv_len );
 	close( fd_iv ) ;

    //----------------------------------------------------------------------------------------
    // MESSAGE 3

    // Get length of message 3 from Amal
    if (read( fd_AtoB_ctrl, &len_recv, sizeof(int) ) < 0 )
    { fprintf( log , "This is Basim: error reading length of message 3\n" ); exit(-1) ;}

    // Get message 3 from Amal
    recv_buffer = malloc( len_recv );

    if (read( fd_AtoB_ctrl, recv_buffer, len_recv ) < 0 )
    { fprintf( log , "This is Amal: error reading message 3\n" ); exit(-1) ;}

    // Get encrypted part of the package
    memcpy( &len_encr, recv_buffer, sizeof(int) ) ;
    count += sizeof(int);

    pack_encr = malloc( len_encr );
    memcpy( pack_encr, recv_buffer + count, len_encr ) ;
    count += len_encr;

    // Get the nonce_a2
    memcpy( &len_nonce, recv_buffer + count, sizeof(int) ) ;
    count += sizeof(int);

    nonce_a2_str = malloc( len_nonce );
    memcpy( nonce_a2_str, recv_buffer + count, len_nonce ) ;
    count = 0;

    // Decrypt the encrypted bytes of message 3
    package = malloc( len_encr );
    len_package = decrypt_str( pack_encr, package, key_b, iv_b, len_encr ) ;

    // Get session key
    memcpy( key_s, package, key_len );
    count += key_len;

    // Get session iv
    memcpy( iv_s, package + count, iv_len );
    count += iv_len;

    // Get Amal's ID
    memcpy( &len_amal, package + count, sizeof(int) );
    count += sizeof(int);

    memcpy( amal_id_recv, package + count, len_amal );
    amal_id_recv[len_amal] = '\0' ;
    count = 0;

    // Write to log
    fprintf( log , "\n\n\nThis is Basim: Received message 3:\n" );
    fprintf( log , "E( K_b, K_s || IV_s || ID_a ) || N_a2\n\n" );
    fprintf( log , "K_s:\n" );
    BIO_dump ( bio_stdout, (const char *) key_s , key_len );
    fprintf( log , "IV_s:\n" );
    BIO_dump ( bio_stdout, (const char *) iv_s , iv_len );
    fprintf( log , "ID_a: %s\n", amal_id_recv );
    fprintf( log , "N_a2:\n" );
    BIO_dump ( bio_stdout, (const char *) nonce_a2_str , len_nonce );

    // Check Amal's ID
    if ( strcmp(amal_id_recv, amal_id) != 0 )
    { fprintf( log , "Amal ID does not match the expected value!\n" ); exit(-1) ;}

    // Free memory
    free(recv_buffer);
    free(pack_encr);
    free(package);

    //----------------------------------------------------------------------------------------
    // MESSAGE 4

    // Create nonce_b
	if ( BN_rand( nonce_b, 256, -1, 1 ) < 1 )
	{ fprintf( log , "This is Amal: error generating nonce_b\n" ); exit(-1) ;}

    // Make a char* representation of the nonce
	len_nonce = BN_num_bytes(nonce_b);
	nonce_b_str = malloc(len_nonce);
	bytes_nonce = BN_bn2bin(nonce_b, nonce_b_str);

    // Get nonce_a2
    nonce_a2 = BN_bin2bn(nonce_a2_str, len_nonce, NULL);

    // Increment nonce_a2 by 1
    if ( BN_add_word( nonce_a2, (BN_ULONG)1 ) < 0 )
    { fprintf( log , "Error computing function of nonce_a2!\n" ); exit(-1) ;}

    // Make a char* representation of the function of nonce_a2
    f_n_a2_str = malloc( len_nonce );
    len_f_nonce = BN_bn2bin(nonce_a2, f_n_a2_str);

    // Package plaintext message 4
    len_package = sizeof(int) + len_nonce + sizeof(int) + bytes_nonce ;
    package = malloc( len_package );

    memcpy( package, &len_nonce, sizeof(int) ) ;
    count = sizeof(int);

    memcpy( package + count, f_n_a2_str, len_nonce ) ;
    count += len_nonce;

    memcpy( package + count, &bytes_nonce, sizeof(int) ) ;
    count += sizeof(int);

    memcpy( package + count, nonce_b_str, bytes_nonce ) ;
    count = 0;

    // Encrypt message 4 using the session key
    pack_encr = malloc( len_package + 32 );
    len_encr = encrypt_str( package, pack_encr, key_s, iv_s, len_package );

    // Write to log
    fprintf( log , "\n\nThis is Basim: Sending message 4 to Amal:\n" ) ;
    fprintf( log , "E( K_s, f(N_a2) || N_b )\n\n" ) ;
    fprintf( log , "f(N_a2):\n" );
    BIO_dump ( bio_stdout, (const char *) f_n_a2_str , len_f_nonce );
    fprintf( log , "N_b:\n" );
    BIO_dump ( bio_stdout, (const char *) nonce_b_str , bytes_nonce );

    // Send the length of message 4
    if (write( fd_BtoA_ctrl, &len_encr, sizeof(int) ) < 0 )
    { fprintf( log , "This is Basim: error sending message 4 length\n" ); exit(-1) ;}

    // Send message 4
    if (write( fd_BtoA_ctrl, pack_encr, len_encr ) < 0 )
    { fprintf( log , "This is Basim: error sending message 4\n" ); exit(-1) ;}

    // Free memory
    free(f_n_a2_str);
    free(package);
    free(pack_encr);

    //----------------------------------------------------------------------------------------
    // MESSAGE 5

    // Get length of message 5
    if (read( fd_AtoB_ctrl, &len_encr, sizeof(int) ) < 0 )
    { fprintf( log , "Error reading length of message 5\n" ); exit(-1) ;}

    // Get message 5
    //pack_5_encr = malloc( len_encr );
    if (read( fd_AtoB_ctrl, pack_5_encr, len_encr ) < 0 )
    { fprintf( log , "Error reading message 5\n" ); exit(-1) ;}

    // Decrypt message 5
    //package = malloc( len_encr );
    len_package = decrypt_str( pack_5_encr, package_5, key_s, iv_s, len_encr );

    fprintf( log , "\n\nThis is Basim: Received message 5:\n" );
    fprintf( log , "E( key_s, f(N_b) )\n" );
    fprintf( log , "f(N_b):\n" );
    BIO_dump ( bio_stdout, (const char *) package_5 , len_package );

    free(nonce_b_str);
    free(pack_5_encr);
    free(package_5);

    //----------------------------------------------------------------------------------------
    // MESSAGE DATA

    fprintf( log , "\n\nThis is Basim: Receiving data from Amal\n" );

    fd_out = open("basim/bunny.mp4", O_WRONLY | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR) ;
    if( fd_out == -1)
        fprintf( log , "Could not open bunny.mp4: %s\n", strerror(errno) );

    decrypt_file( fd_AtoB_data, fd_out, key_s, iv_s );

    close(fd_out);

    //----------------------------------------------------------------------------------------
    // End of Basim's duties

    // Close log file
    fclose( log );

    // Close pipes
    close(fd_AtoB_ctrl);
    close(fd_BtoA_ctrl);
    close(fd_AtoB_data);

    /* Clean up */
 	BIO_flush ( bio_stdout );
 	EVP_cleanup();
 	ERR_free_strings();

    // Free big nums
    BN_free(nonce_b);
    BN_free(nonce_a2);
}
