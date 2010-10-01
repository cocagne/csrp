#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


#include "srp.h"


#define NITER 100


unsigned long long get_usec()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (((unsigned long long)t.tv_sec) * 1000000) + t.tv_usec;
}


int main( int argc, char * argv[] )
{
    struct SRPVerifier * ver;
    struct SRPUser     * usr;
    
    const unsigned char * bytes_s = 0;
    const unsigned char * bytes_v = 0;
    const unsigned char * bytes_A = 0;
    const unsigned char * bytes_B = 0;
    
    const unsigned char * bytes_M    = 0;
    const unsigned char * bytes_HAMK = 0;
    
    int len_s   = 0;
    int len_v   = 0;
    int len_A   = 0;
    int len_B   = 0;
    int i;
    
    unsigned long long start;
    unsigned long long duration;
    
    const char * username = "testuser";
    const char * password = "password";
    
    const char * auth_username = 0;

    srp_init(NULL,0);
    
    srp_gen_sv( username, password, strlen(password), 
                &bytes_s, &len_s, &bytes_v, &len_v );
    

    
    start = get_usec();
    
    for( i = 0; i < NITER; i++ )
    {
        usr =  srp_user_new( username, password, strlen(password) );

        srp_user_start_authentication( usr, &auth_username, &bytes_A, &len_A );

        /* User -> Host: (username, bytes_A) */
        ver =  srp_verifier_new( username, bytes_s, len_s, bytes_v, len_v, 
                                 bytes_A, len_A, & bytes_B, &len_B );
        
        if ( !bytes_B )
        {
            printf("Verifier SRP-6a safety check violated!\n");
            goto cleanup;
        }
        
        /* Host -> User: (bytes_s, bytes_B) */
        srp_user_process_challenge( usr, bytes_s, len_s, bytes_B, len_B, &bytes_M );
        
        if ( !bytes_M )
        {
            printf("User SRP-6a safety check violation!\n");
            goto cleanup;
        }
        
        /* User -> Host: (bytes_M) */
        srp_verifier_verify_session( ver, bytes_M, &bytes_HAMK );
        
        if ( !bytes_HAMK )
        {
            printf("User authentication failed!\n");
            goto cleanup;
        }
        
        /* Host -> User: (HAMK) */
        srp_user_verify_session( usr, bytes_HAMK );
        
        if ( !srp_user_is_authenticated(usr) )
        {
            printf("Server authentication failed!\n");
        }
        
cleanup:
        srp_verifier_delete( ver );
        srp_user_delete( usr );
    }
    
    duration = get_usec() - start;
    
    printf("Usec per call: %d\n", (int)(duration / NITER));
    
    
    free( (char *)bytes_s );
    free( (char *)bytes_v );
    
    srp_fini();
        
    return 0;
}