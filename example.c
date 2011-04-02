#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "srp.h"


int main( int argc, char * argv[] )
{
    int auth_failed = 1;
    
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
    int len_M   = 0;
    
    const char * username = "testuser";
    const char * password = "password";
    
    const char * auth_username = 0;
    
    SRP_HashAlgorithm alg     = SRP_SHA1;
    SRP_NGType        ng_type = SRP_NG_2048;

    /* Create a salt+verification key for the user's password. The salt and
     * key need to be computed at the time the user's password is set and
     * must be stored by the server-side application for use during the
     * authentication process.
     */
    srp_create_salted_verification_key( alg, ng_type, username, 
                                        (const unsigned char *)password, 
                                        strlen(password), 
                                        &bytes_s, &len_s,
                                        &bytes_v, &len_v,
                                        NULL, NULL );
    
    /* Begin authentication process */
    usr =  srp_user_new( alg, ng_type, username, 
                         (const unsigned char *)password, 
                         strlen(password), NULL, NULL );

    srp_user_start_authentication( usr, &auth_username, &bytes_A, &len_A );

    /* User -> Host: (username, bytes_A) */
    ver =  srp_verifier_new( alg, ng_type, username, bytes_s, len_s, bytes_v, len_v, 
                             bytes_A, len_A, & bytes_B, &len_B, NULL, NULL );
        
    if ( !bytes_B ) {
       printf("Verifier SRP-6a safety check violated!\n");
       goto auth_failed;
    }
        
    /* Host -> User: (bytes_s, bytes_B) */
    srp_user_process_challenge( usr, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M );
        
    if ( !bytes_M ) {
       printf("User SRP-6a safety check violation!\n");
       goto auth_failed;
    }
        
    /* User -> Host: (bytes_M) */
    srp_verifier_verify_session( ver, bytes_M, &bytes_HAMK );
        
    if ( !bytes_HAMK ) {
       printf("User authentication failed!\n");
       goto auth_failed;
    }
        
    /* Host -> User: (HAMK) */
    srp_user_verify_session( usr, bytes_HAMK );
        
    if ( !srp_user_is_authenticated(usr) ) {
       printf("Server authentication failed!\n");
       goto auth_failed;
    }

    auth_failed = 0; /* auth success! */
        
auth_failed:
    srp_verifier_delete( ver );
    srp_user_delete( usr );
    
    free( (char *)bytes_s );
    free( (char *)bytes_v );
        
    return auth_failed;
}
