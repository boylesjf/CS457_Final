#include "../myCrypto.h"

int main( int argc , char *argv[] )
{
    int fd_AtoKDC_ctrl, fd_KDCtoA_ctrl, fd_AtoB_ctrl, fd_BtoA_ctrl, fd_AtoB_data, fd_in;
    int len_package, len_package_encr, len_sub_pack, len_a, len_b, len_nonce,
			bytes_nonce, len_recv, len_n_a2, len_n_b, count = 0 ;
    uint8_t key_a[EVP_MAX_KEY_LENGTH] , iv_a[EVP_MAX_IV_LENGTH],
            key_s[EVP_MAX_KEY_LENGTH] , iv_s[EVP_MAX_IV_LENGTH] ;
    char amal_id[5] = "Amal", basim_id[6] = "Basim" ;
    char len_package_str[5], len_a_str[5], len_b_str[5], len_nonce_str[5] ;
    char *bytes_n_str, *package, *len_sub_str, *recv_buffer, *b_id_recv, *nonce_recv, *package_encr ;
	unsigned char *nonce_a_str, *nonce_a2_str, *nonce_b_str ;
    unsigned key_len = 32 ;
    unsigned iv_len = 16 ;
    char *f_nonce_b_str = malloc(32) ;                                  // Trying to malloc these char arrays
    unsigned char *package_3 = malloc(104), *package_5 = malloc(64) ;   // would cause the process to crash.
    FILE *log ;                                                         // So, I put the malloc calls up here
	BIGNUM *nonce_a  = BN_new() ;                                       // so the program would at least run.
	BIGNUM *n_a_recv = BN_new() ;
	BIGNUM *nonce_a2 = BN_new() ;

    /* BIO objects */
    BIO *bio_stdout;

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 6 )
    {
        printf("Missing command-line arguments: %s\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_AtoKDC_ctrl = atoi( argv[1] ) ;
    fd_KDCtoA_ctrl = atoi( argv[2] ) ;
    fd_AtoB_ctrl   = atoi( argv[3] ) ;
    fd_BtoA_ctrl   = atoi( argv[4] ) ;
    fd_AtoB_data   = atoi( argv[5] ) ;

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }

    /* Initialize the BIO for BASE64 input/output */
    bio_stdout = BIO_new_fp( log , BIO_NOCLOSE );

    // Get key and iv material from file
    int fd_key , fd_iv ;

 	fd_key = open("key_amal.bin" , O_RDONLY ) ;
	if( fd_key == -1 )
 	{ fprintf( log , "\nCould not open key_amal.bin\n"); exit(-1) ;}

    fd_iv = open("iv_amal.bin" , O_RDONLY ) ;
	if( fd_key == -1 )
 	{ fprintf( log , "\nCould not open iv_amal.bin\n"); exit(-1) ;}

    // Print key and iv material to the log file
    read ( fd_key , key_a , 32 ) ;
    fprintf( log , "This is Amal: My master key material is:\n" );
    BIO_dump ( bio_stdout, (const char *) key_a, key_len );
 	close( fd_key ) ;

    read ( fd_iv , iv_a , 16 ) ;
    fprintf( log , "\nThis is Amal: My master iv material is:\n" );
    BIO_dump ( bio_stdout, (const char *) iv_a , iv_len );
 	close( fd_iv ) ;

    //----------------------------------------------------------------------------------------
    // MESSAGE 1

	// Create nonce_a
	if ( BN_rand( nonce_a, 256, -1, 1 ) < 1 )
	{ fprintf( log , "This is Amal: error generating nonce_a\n" ); exit(-1) ;}

	// Make a char* representation of the nonce
	len_nonce = BN_num_bytes(nonce_a);
	nonce_a_str = malloc(len_nonce);
	bytes_nonce = BN_bn2bin(nonce_a, nonce_a_str);

    // Package message 1
    sprintf( len_a_str, "%ld", strlen(amal_id)  ) ;
    sprintf( len_b_str, "%ld", strlen(basim_id) ) ;
	sprintf( bytes_n_str, "%d", bytes_nonce     ) ;

    // Build package for message 1
	len_package = strlen(len_a_str) + strlen(amal_id) + strlen(len_b_str) + 
			strlen(basim_id) + strlen(bytes_n_str) + bytes_nonce ;
    package = malloc( len_package ) ;
    if ( package == NULL )
    { fprintf( log , "This is Amal: error allocating package for message 1\n" ); exit(-1) ;}

    memcpy( package, len_a_str, strlen(len_a_str) ) ;
    count += strlen(len_a_str);
    memcpy( package + count, amal_id, strlen(amal_id) ) ;
    count += strlen(amal_id);
    memcpy( package + count, len_b_str, strlen(len_b_str) ) ;
    count += strlen(len_b_str);
    memcpy( package + count, basim_id, strlen(basim_id) ) ;
    count += strlen(basim_id);
    memcpy( package + count, bytes_n_str, strlen(bytes_n_str) ) ;
    count += strlen(bytes_n_str);
    memcpy( package + count, nonce_a_str, bytes_nonce ) ;
    count = 0;

    // Send message 1 to the KDC

    // Build the length of message 1
    sprintf( len_package_str, "%d", len_package ) ;

    // Send the length of message 1 to The KDC
    if ( write(fd_AtoKDC_ctrl, len_package_str, strlen(len_package_str) ) < 0 )
    { fprintf( log , "This is Amal: error writing length of message 1 to the pipe\n" ); exit(-1) ;}

	// Write to log
    fprintf( log , "\n\n\nThis is Amal: Sending message 1 to the KDC: \nID_a || ID_b || N_a\n\n" ) ;
	fprintf( log , "ID_a: %s\n", amal_id ) ;
	fprintf( log , "ID_b: %s\n", basim_id ) ;
	fprintf( log , "N_a:\n" );
	BIO_dump ( bio_stdout, (const char *) nonce_a_str, bytes_nonce );

    // Send message 1 to The KDC
    if ( write(fd_AtoKDC_ctrl, package, len_package) < 0 )
    { fprintf( log , "This is Amal: error writing message 1 to the pipe\n" ); exit(-1) ;}

	// Free memory
    free(package);

    //----------------------------------------------------------------------------------------
    // MESSAGE 2

    // Receive length of message 2 from The KDC
    if ( read(fd_KDCtoA_ctrl, &len_recv, sizeof(int) ) < 0 )
    { fprintf( log , "This is Amal: error reading message 2 length\n" ); exit(-1) ;}

    // Receive message 2 from Amal
	recv_buffer = malloc(len_recv);
    if ( read(fd_KDCtoA_ctrl, recv_buffer, len_recv ) < 0 )
    { fprintf( log , "This is Amal: error reading message 2\n" ); exit(-1) ;}

    // Decrypt message 2
    package = malloc(len_recv);
    len_package = decrypt_str( recv_buffer, package, key_a, iv_a, len_recv );

    // Disassemble message 2

    // Get the session key
    memcpy( key_s, package, key_len ) ;
    count += key_len;

    // Get the session iv
    memcpy( iv_s, package + count, iv_len ) ;
    count += iv_len;

    // Get received Basim ID
    memcpy( &len_b, package + count, sizeof(int) ) ;
    count += sizeof(int);

    b_id_recv = malloc(len_b);
    memcpy( b_id_recv, package + count, len_b ) ;
    b_id_recv[len_b] = '\0' ;
    count += len_b;

    // Get received nonce
    memcpy( &bytes_nonce, package + count, sizeof(int) ) ;
    count += sizeof(int);

    nonce_recv = malloc(bytes_nonce);
    memcpy( nonce_recv, package + count, bytes_nonce ) ;
    count += bytes_nonce;

	// Write to log
    fprintf( log , "\n\nThis is Amal: Received message 2 from The KDC:\n" );
    fprintf( log , "E( K_a, K_s || IV_s || ID_b || N_a || E( K_b, K_s || IV_s || ID_a ) )\n\n" );

    fprintf( log , "K_s:\n" );
    BIO_dump ( bio_stdout, (const char *) key_s, key_len );
    fprintf( log , "IV_s:\n" );
    BIO_dump ( bio_stdout, (const char *) iv_s, iv_len );
	fprintf( log , "ID_b: %s\n", b_id_recv );
	fprintf( log , "N_a:\n" );
	BIO_dump ( bio_stdout, (const char *) nonce_recv, bytes_nonce );
	fprintf( log , "ID_a: %s\n", amal_id ) ;

    // Check Basim's ID
    if ( strcmp(b_id_recv, basim_id) != 0 )
    { fprintf( log , "Basim ID does not match the expected value!\n" ); exit(-1) ;}

    // Check nonce_a
    if ( memcmp(nonce_a_str, nonce_recv, bytes_nonce) != 0 )
    { fprintf( log , "Nonce_a does not match the expected value!\n" ); exit(-1) ;}

	// Free memory
	free(recv_buffer);
    free(b_id_recv);
    free(nonce_recv);
	free(nonce_a_str);

    //----------------------------------------------------------------------------------------
    // MESSAGE 3

	// Create nonce_a2
	if ( BN_rand( nonce_a2, 256, -1, 1 ) < 1 )
	{ fprintf( log , "This is Amal: error generating nonce_a2\n" ); exit(-1) ;}

	// Make a char* representation of the nonce
	len_nonce = BN_num_bytes(nonce_a2);
	nonce_a_str = malloc(len_nonce);
	bytes_nonce = BN_bn2bin(nonce_a2, nonce_a_str);

	// Get length of encrypted part of message 3
    memcpy( &len_sub_pack, package + count, sizeof(int) ) ;
    count += sizeof(int);

	// Allocate memory for message 3
	len_package = sizeof(int) + len_sub_pack + sizeof(int) + bytes_nonce ;
	//package_3 = malloc( len_package ) ;

	// Start building message 3
	memcpy( package_3, &len_sub_pack, sizeof(int) ) ;

	// Move encrypted bytes from message 2 to message 3
	memcpy( package_3 + sizeof(int), package + count, len_sub_pack ) ;
    count = sizeof(int) + len_sub_pack;

	// Move nonce length and nonce to message 3
	memcpy( package_3 + count, &bytes_nonce, sizeof(int) ) ;
    count += sizeof(int);
	memcpy( package_3 + count, nonce_a_str, bytes_nonce ) ;
    count = 0;

	// Write to log
	fprintf( log , "\n\nThis is Amal: Sending message 3 to Basim:\n" );
	fprintf( log , "E( K_b, K_s || IV_s || ID_a ) || N_a2\n\n" ) ;

	fprintf( log , "K_s:\n" );
    BIO_dump ( bio_stdout, (const char *) key_s, key_len );
	fprintf( log , "IV_s:\n" );
    BIO_dump ( bio_stdout, (const char *) iv_s, iv_len );
	fprintf( log , "ID_a: %s\n", amal_id );
	fprintf( log , "N_a2:\n" );
	BIO_dump ( bio_stdout, (const char *) nonce_a_str, bytes_nonce );

    // Send message 3 length to Basim
    if (write( fd_AtoB_ctrl, &len_package, sizeof(int) ) < 0 )
    { fprintf( log , "This is Amal: error sending message 3 length\n" ); exit(-1) ;}

    // Send message 3 to Basim
    if (write( fd_AtoB_ctrl, package_3, len_package ) < 0 )
    { fprintf( log , "This is Amal: error sending message 3\n" ); exit(-1) ;}

	// Free memory
	free(package_3);

    //----------------------------------------------------------------------------------------
    // MESSAGE 4

    // Get length of message 4
    if (read( fd_BtoA_ctrl, &len_recv, sizeof(int) ) < 0 )
    { fprintf( log , "This is Amal: error reading length of message 4\n" ); exit(-1) ;}

    // Get message 4
    recv_buffer = malloc( len_recv );
    if (read( fd_BtoA_ctrl, recv_buffer, len_recv ) < 0 )
    { fprintf( log , "This is Amal: error reading message 4\n" ); exit(-1) ;}

    // Decrypt message 4
    package = malloc( len_recv );
    len_package = decrypt_str( recv_buffer, package, key_s, iv_s, len_recv );

    // Get received function of nonce_a2
    memcpy( &len_n_a2, package, sizeof(int) );
    count = sizeof(int);

    nonce_a2_str = malloc( len_n_a2 );
    memcpy( nonce_a2_str, package + count, len_n_a2 );
    count += len_n_a2;

    // Get received nonce_b
    memcpy( &len_n_b, package + count, sizeof(int) );
    count += sizeof(int);

    nonce_b_str = malloc( len_n_b );
    memcpy( nonce_b_str, package + count, len_n_b );
    count = 0;

    // Write to log
    fprintf( log , "\n\nThis is Amal: Received message 4 from Basim:\n" );
    fprintf( log , "E( K_s, f(N_a2) || N_b )\n\n" );
    fprintf( log , "f(N_a2):\n" );
    BIO_dump ( bio_stdout, (const char *) nonce_a2_str, len_n_a2 );
    fprintf( log , "N_b:\n" );
    BIO_dump ( bio_stdout, (const char *) nonce_b_str, len_n_b );

    // Check f(N_a2)
    if ( BN_add_word( nonce_a2, (BN_ULONG)1 ) < 0 )
    { fprintf( log , "Error computing function of nonce_a2!\n" ); exit(-1) ;}

    len_nonce = BN_bn2bin(nonce_a2, nonce_a_str);

    if ( memcmp( nonce_a2_str, nonce_a_str, len_nonce ) != 0 )
    { fprintf( log , "Function of nonce_a2 is not the expected value!\n" ); exit(-1) ;}

    // Free memory
    free(recv_buffer);
    free(package);
    free(nonce_a2_str);
    free(nonce_a_str);

    //----------------------------------------------------------------------------------------
    // MESSAGE 5

    // Get nonce b
    nonce_a = BN_bin2bn(nonce_b_str, len_n_b, NULL);

    // Increment nonce_b by 1
    if ( BN_add_word( nonce_a, (BN_ULONG)1 ) < 0 )
    { fprintf( log , "Error computing function of nonce_b!\n" ); exit(-1) ;}

    //f_nonce_b_str = malloc( len_n_b );
    len_n_b = BN_bn2bin(nonce_a, f_nonce_b_str);

    // Encrypt the function of the nonce
    //package_5 = malloc( len_n_b + 32 );
    len_package_encr = encrypt_str( f_nonce_b_str, package_5, key_s, iv_s, len_n_b );

    // Write to log
    fprintf( log , "\n\nThis is Amal: Sending message 5 to Basim:\n" );
    fprintf( log , "E( K_s, f(N_b) )\n\n" );
    fprintf( log , "f(N_b):\n" );
    BIO_dump ( bio_stdout, (const char *) f_nonce_b_str, len_n_b );

    // Send length of the encrypted package
    if (write( fd_AtoB_ctrl, &len_package_encr, sizeof(int) ) < 0 )
    { fprintf( log , "Error sending length of message 5\n" ); exit(-1) ;}

    // Send message 5
    if (write( fd_AtoB_ctrl, package_5, len_package_encr ) < 0 )
    { fprintf( log , "Error sending message 5\n" ); exit(-1) ;}

    // Free memory
    free(nonce_b_str);
    free(f_nonce_b_str);
    free(package_5);

    //----------------------------------------------------------------------------------------
    // MESSAGE DATA

    fprintf( log , "\n\nThis is Amal: Sending data to Basim\n" );

    fd_in = open("amal/bunny.mp4" , O_RDONLY) ;
    if( fd_in == -1 )
        fprintf( log , "Could not open bunny.mp4: %s\n", strerror(errno) );

    encrypt_file( fd_in, fd_AtoB_data, key_s, iv_s );

    close(fd_in);

    //----------------------------------------------------------------------------------------
    // End of Amal's duties

    // Close log file
    fclose( log );

    // Close pipes
    close(fd_AtoKDC_ctrl);
    close(fd_KDCtoA_ctrl);
    close(fd_AtoB_ctrl);
    close(fd_BtoA_ctrl);
    close(fd_AtoB_data);

    /* Clean up */
 	BIO_flush ( bio_stdout );
 	EVP_cleanup();
 	ERR_free_strings();

	// Free big num stuff
	BN_free(nonce_a);
	BN_free(nonce_a2);
	BN_free(n_a_recv);
}





