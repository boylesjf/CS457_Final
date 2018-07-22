/*-------------------------------------------------------------------------------
Written By: 
     1- Dr. Mohamed Aboutabl
Submitted on: 
-------------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

pid_t    Fork(void) ;
int      Pipe( int fdArr[2] ) ;
ssize_t  Read( int fd, void *buf, size_t count) ;
ssize_t	 Write( int fd, const void *buf , size_t count ) ;

