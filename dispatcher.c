/*-------------------------------------------------------------------------------
pa-final: Two-way authentication using Pipes

FILE:   dispatcher.c

Written By: 
     1- Joshua Boyles
Submitted on: 
-------------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "wrappers.h"

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1
//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    pid_t amalPID, basimPID, kdcPID;
    int   AtoKDC_ctrl[2], KDCtoA_ctrl[2], AtoB_ctrl[2], BtoA_ctrl[2], AtoB_data[2];
    char  arg1[20], arg2[20], arg3[20], arg4[20], arg5[20];

    // Create pipes
    Pipe( AtoKDC_ctrl ) ;
    Pipe( KDCtoA_ctrl ) ;
    Pipe( AtoB_ctrl   ) ;
    Pipe( BtoA_ctrl   ) ;
    Pipe( AtoB_data   ) ;

    printf("\nDispather started and created all pipes\n") ;
    printf("Amal-to-KDC   control pipe: read=%d  write-%d\n", AtoKDC_ctrl[READ_END] , AtoKDC_ctrl[WRITE_END] ) ;
    printf("KDC-to-Amal   control pipe: read=%d  write-%d\n", KDCtoA_ctrl[READ_END] , KDCtoA_ctrl[WRITE_END] ) ;
    printf("Amal-to-Basim control pipe: read=%d  write-%d\n", AtoB_ctrl[READ_END]   , AtoB_ctrl[WRITE_END]   ) ;
    printf("Basim-to-Amal control pipe: read=%d  write-%d\n", BtoA_ctrl[READ_END]   , BtoA_ctrl[WRITE_END]   ) ;
    printf("Amal-to-Basim data    pipe: read=%d  write-%d\n", AtoB_data[READ_END]   , AtoB_data[WRITE_END]   ) ;

    // Create Amal processes
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {
        // This is the Amal process

        // Decrement the ends of the pipes not needed by Amal
        close( AtoKDC_ctrl[READ_END]  ) ;
        close( KDCtoA_ctrl[WRITE_END] ) ;
        close( AtoB_ctrl[READ_END]    ) ;
        close( BtoA_ctrl[WRITE_END]   ) ;
        close( AtoB_data[READ_END]    ) ;

        // Prepare the file descriptors as args to Amal
        snprintf( arg1, 20, "%d", AtoKDC_ctrl[WRITE_END] ) ;
        snprintf( arg2, 20, "%d", KDCtoA_ctrl[READ_END]  ) ;
        snprintf( arg3, 20, "%d", AtoB_ctrl[WRITE_END]   ) ;
        snprintf( arg4, 20, "%d", BtoA_ctrl[READ_END]    ) ;
        snprintf( arg5, 20, "%d", AtoB_data[WRITE_END]   ) ;

        // Start Amal
        char * cmnd = "./amal/amal" ;
        execlp( cmnd , "Amal" , arg1 , arg2 , arg3 , arg4 , arg5 , NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;
    }
    else
    {
        // Create Basim process
        basimPID = Fork() ;
        if ( basimPID == 0 )
        {
            // This is the Basim process

            // Decrement the ends of the pipes not needed by Basim
            close( AtoKDC_ctrl[READ_END]  ) ;
            close( AtoKDC_ctrl[WRITE_END] ) ;
            close( KDCtoA_ctrl[READ_END]  ) ;
            close( KDCtoA_ctrl[WRITE_END] ) ;
            close( AtoB_ctrl[WRITE_END]   ) ;
            close( BtoA_ctrl[READ_END]    ) ;
            close( AtoB_data[WRITE_END]   ) ;

            // Prepare the file descriptors as args to Basim
            snprintf( arg1, 20, "%d", AtoB_ctrl[READ_END]  ) ;
            snprintf( arg2, 20, "%d", BtoA_ctrl[WRITE_END] ) ;
            snprintf( arg3, 20, "%d", AtoB_data[READ_END]  ) ;

            // Start Basin
            char * cmnd = "./basim/basim" ;
            execlp( cmnd , "Basim" , arg1 , arg2 , arg3 , NULL );

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Basim" ) ;
            exit(-1) ;
        }
        else
        {
            // Create KDC process
            kdcPID = Fork() ;
            if ( kdcPID == 0 )
            {
                // This is the KDC process

                // Decrement the ends of the pipes not needed by the KDC
                close( AtoB_ctrl[READ_END]    ) ;
                close( AtoB_ctrl[WRITE_END]   ) ;
                close( BtoA_ctrl[READ_END]    ) ;
                close( BtoA_ctrl[WRITE_END]   ) ;
                close( AtoB_data[READ_END]    ) ;
                close( AtoB_data[WRITE_END]   ) ;
                close( AtoKDC_ctrl[WRITE_END] ) ;
                close( KDCtoA_ctrl[READ_END]  ) ;

                // Prepare the file descriptors as args to the KDC
                snprintf( arg1 , 20 , "%d" , AtoKDC_ctrl[READ_END]  ) ;
                snprintf( arg2 , 20 , "%d" , KDCtoA_ctrl[WRITE_END] ) ;

                // Start the KDC
                char * cmnd = "./kdc/kdc" ;
                execlp( cmnd , "KDC" , arg1 , arg2 , NULL );

                // the above execlp() only returns if an error occurs
                perror("ERROR starting the KDC" ) ;
                exit(-1) ;
            }
            else
            {
                // This is the parent Dispatcher process

                // Close all ends of the pipes so that their count is decremented
                close( AtoKDC_ctrl[READ_END]  ) ;
                close( AtoKDC_ctrl[WRITE_END] ) ;
                close( KDCtoA_ctrl[READ_END]  ) ;
                close( KDCtoA_ctrl[WRITE_END] ) ;
                close( AtoB_ctrl[READ_END]    ) ;
                close( AtoB_ctrl[WRITE_END]   ) ;
                close( BtoA_ctrl[READ_END]    ) ;
                close( BtoA_ctrl[WRITE_END]   ) ;
                close( AtoB_data[READ_END]    ) ;
                close( AtoB_data[WRITE_END]   ) ;

                printf("\nDispatcher is now waiting for Amal to terminate\n") ;
                waitpid( amalPID , NULL , 0 ) ;

                printf("\nDispatcher is now waiting for Basim to terminate\n") ;
                waitpid( basimPID , NULL , 0 ) ;

                printf("\nDispatcher is now waiting for the KDC to terminate\n") ;
                waitpid( kdcPID , NULL , 0 ) ;

                printf("\nThe Dispatcher process has terminated\n") ;
            }
        }
    }
}
