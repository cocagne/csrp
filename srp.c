/*
 * Secure Remote Password 6a implementation
 * Copyright (c) 2010 Tom Cocagne. All rights reserved.
 * http://csrp.googlecode.com/p/csrp/
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Google Code nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL TOM COCAGNE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#ifdef WIN32
    #include <Wincrypt.h>
#else
    #include <sys/time.h>
#endif

#include <alloca.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>


#include "srp.h"

/* 2048-bit prime & generator pair from RFC 5054 */
#define N_HEX "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
#define G_HEX "2"


static const BIGNUM * N = 0;
static const BIGNUM * g = 0;
static const BIGNUM * k = 0;
static int            g_initialized = 0;

struct SRPVerifier
{
    const char          * username;
    const unsigned char * bytes_B;
    int                   authenticated;
    
    unsigned char M           [SRP_SHA256_DIGEST_LENGTH];
    unsigned char H_AMK       [SRP_SHA256_DIGEST_LENGTH];
    unsigned char session_key [SRP_SHA256_DIGEST_LENGTH];
};


struct SRPUser
{
    BIGNUM *a;
    BIGNUM *A;
    BIGNUM *S;

    const unsigned char * bytes_A;
    int                   authenticated;
    
    const char *          username;
    const unsigned char * password;
    int                   password_len;
    
    unsigned char M           [SRP_SHA256_DIGEST_LENGTH];
    unsigned char H_AMK       [SRP_SHA256_DIGEST_LENGTH];
    unsigned char session_key [SRP_SHA256_DIGEST_LENGTH];
};



static BIGNUM * H_nn( const BIGNUM * n1, const BIGNUM * n2 )
{
    unsigned char   buff[ SHA256_DIGEST_LENGTH ];
    int             len_n1 = BN_num_bytes(n1);
    int             len_n2 = BN_num_bytes(n2);
    int             nbytes = len_n1 + len_n2;
    unsigned char * bin    = (unsigned char *) alloca( nbytes );
    BN_bn2bin(n1, bin);
    BN_bn2bin(n2, bin + len_n1);
    SHA256( bin, nbytes, buff );
    return BN_bin2bn(buff, SHA256_DIGEST_LENGTH, NULL);
}

static BIGNUM * H_ns( const BIGNUM * n, const unsigned char * bytes, int len_bytes )
{
    unsigned char   buff[ SHA256_DIGEST_LENGTH ];
    int             len_n  = BN_num_bytes(n);
    int             nbytes = len_n + len_bytes;
    unsigned char * bin    = (unsigned char *) alloca( nbytes );
    BN_bn2bin(n, bin);
    memcpy( bin + len_n, bytes, len_bytes );
    SHA256( bin, nbytes, buff );
    return BN_bin2bn(buff, SHA256_DIGEST_LENGTH, NULL);
}
    
static BIGNUM * calculate_x( const BIGNUM * salt, const char * username, const unsigned char * password, int password_len )
{
    unsigned char ucp_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX    ctx;
        
    SHA256_Init( &ctx );
    
    SHA256_Update( &ctx, username, strlen(username) );
    SHA256_Update( &ctx, ":", 1 );
    SHA256_Update( &ctx, password, password_len );
    
    SHA256_Final( ucp_hash, &ctx );
        
    return H_ns( salt, ucp_hash, sizeof(ucp_hash) );
}

static void update_hash( SHA256_CTX *ctx, const BIGNUM * n )
{
    unsigned long len = BN_num_bytes(n);
    unsigned char * n_bytes = (unsigned char *) alloca( len );
    BN_bn2bin(n, n_bytes);
    SHA256_Update(ctx, n_bytes, len);
}

static void hash_num( const BIGNUM * n, unsigned char * dest )
{
    int             nbytes = BN_num_bytes(n);
    unsigned char * bin    = (unsigned char *) alloca( nbytes );
    BN_bn2bin(n, bin);
    SHA256( bin, nbytes, dest );
}

static void calculate_M( unsigned char * dest, const char * I, const BIGNUM * s,
                         const BIGNUM * A, const BIGNUM * B, const unsigned char * K )
{
    unsigned char H_N[ SHA256_DIGEST_LENGTH ];
    unsigned char H_g[ SHA256_DIGEST_LENGTH ];
    unsigned char H_I[ SHA256_DIGEST_LENGTH ];
    unsigned char H_xor[ SHA256_DIGEST_LENGTH ];
    SHA256_CTX    ctx;
    int           i = 0;
        
    hash_num( N, H_N );
    hash_num( g, H_g );
    
    SHA256((const unsigned char *)I, strlen(I), H_I);
    
    for (i=0; i < SHA256_DIGEST_LENGTH; i++ )
        H_xor[i] = H_N[i] ^ H_g[i];
    
    SHA256_Init( &ctx );
    
    SHA256_Update( &ctx, H_xor, sizeof(H_xor) );
    SHA256_Update( &ctx, H_I,   sizeof(H_I)   );
    update_hash( &ctx, s );
    update_hash( &ctx, A );
    update_hash( &ctx, B );
    SHA256_Update( &ctx, K, SHA256_DIGEST_LENGTH );
    
    SHA256_Final( dest, &ctx );
}

static void calculate_H_AMK( unsigned char *dest, const BIGNUM * A, const unsigned char * M, const unsigned char * K )
{
    SHA256_CTX ctx;
    
    SHA256_Init( &ctx );
    
    update_hash( &ctx, A );
    SHA256_Update( &ctx, M, SHA256_DIGEST_LENGTH);
    SHA256_Update( &ctx, K, SHA256_DIGEST_LENGTH);
    
    SHA256_Final( dest, &ctx );
}


/***********************************************************************************************************
 *
 *  Exported Functions
 *
 ***********************************************************************************************************/

void srp_init()
{
#ifdef WIN32
    HCRYPTPROV wctx;
#else
    FILE   *fp   = 0;
#endif
    
    unsigned char buff[32];
    
    BIGNUM *tN   = BN_new();
    BIGNUM *tg   = BN_new();
    
    BN_hex2bn( &tN, N_HEX );
    BN_hex2bn( &tg, G_HEX );
    
    N = tN;
    g = tg;
    
    k = H_nn(N,g);
    
#ifdef WIN32

        CryptAcquireContext(&wctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        
        CryptGenRandom(wctx, sizeof(buff), (BYTE*) buff);
        
        CryptReleaseContext(wctx, 0);
        
#else
        fp = fopen("/dev/urandom", "r");
        
        if (fp)
        {
            fread(buff, sizeof(buff), 1, fp);
            fclose(fp);
            
        }
        else
        {
            /* Dirty... but better than nothing. */
            gettimeofday( (struct timeval *)buff, 0);
        }
#endif
    
    RAND_seed( buff, sizeof(buff) );
        
    g_initialized = 1;
}


void srp_fini()
{
    g_initialized = 0;
    
    BN_free((BIGNUM *)N);
    BN_free((BIGNUM *)g);
    BN_free((BIGNUM *)k);
    
    N = 0;
    g = 0;
}


int srp_is_initialized()
{
    return g_initialized;
}


void srp_gen_sv( const char * username,
                 const unsigned char * password, int len_password,
                 const unsigned char ** bytes_s, int * len_s, 
                 const unsigned char ** bytes_v, int * len_v )
{
    BIGNUM * s  = BN_new();
	BIGNUM * v  = BN_new();
	BIGNUM * x  = 0;
	BN_CTX *ctx = BN_CTX_new();
    	
	BN_rand(s, 32, -1, 0);
	
	x = calculate_x( s, username, password, len_password );

	BN_mod_exp(v, g, x, N, ctx);
        
    *len_s   = BN_num_bytes(s);
    *len_v   = BN_num_bytes(v);
    
    *bytes_s = (const unsigned char *) malloc( *len_s );
    *bytes_v = (const unsigned char *) malloc( *len_v );
    
    BN_bn2bin(s, (unsigned char *) *bytes_s);
    BN_bn2bin(v, (unsigned char *) *bytes_v);
        
    BN_free(s);
    BN_free(v);
    BN_free(x);
    BN_CTX_free(ctx);
}



/* Out: bytes_B, len_B.
 * 
 * On failure, bytes_B will be set to NULL and len_B will be set to 0
 */
struct SRPVerifier *  srp_verifier_new( const char * username,
                                        const unsigned char * bytes_s, int len_s, 
                                        const unsigned char * bytes_v, int len_v,
                                        const unsigned char * bytes_A, int len_A,
                                        const unsigned char ** bytes_B, int * len_B)
{
    BIGNUM *s    = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM *v    = BN_bin2bn(bytes_v, len_v, NULL);
    BIGNUM *A    = BN_bin2bn(bytes_A, len_A, NULL);
    BIGNUM *u    = 0;
    BIGNUM *B    = BN_new();
    BIGNUM *S    = BN_new();
    BIGNUM *b    = BN_new();
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BN_CTX *ctx  = BN_CTX_new();
    int     ulen = strlen(username) + 1;
    
    struct SRPVerifier * ver = (struct SRPVerifier *) malloc( sizeof(struct SRPVerifier) );
    
    ver->username = (char *) malloc( ulen );
    
    memcpy( (char*)ver->username, username, ulen );
    
    ver->authenticated = 0;
    	
    /* SRP-6a safety check */
    BN_mod(tmp1, A, N, ctx);
    if ( !BN_is_zero(tmp1) )
    {		
		BN_rand(b, 256, -1, 0);
		
		/* B = kv + g^b */
		BN_mul(tmp1, k, v, ctx);
		BN_mod_exp(tmp2, g, b, N, ctx);
		BN_add(B, tmp1, tmp2);
		
		u = H_nn(A,B);
		
		/* S = (A *(v^u)) ^ b */
		BN_mod_exp(tmp1, v, u, N, ctx);
		BN_mul(tmp2, A, tmp1, ctx);
		BN_mod_exp(S, tmp2, b, N, ctx);

		hash_num(S, ver->session_key);
		
		calculate_M( ver->M, username, s, A, B, ver->session_key );
		calculate_H_AMK( ver->H_AMK, A, ver->M, ver->session_key );
		
        *len_B   = BN_num_bytes(B);
        *bytes_B = malloc( *len_B );
        
        BN_bn2bin( B, (unsigned char *) *bytes_B );
        
        ver->bytes_B = *bytes_B;
	}
    else
    {
        *len_B   = 0;
        *bytes_B = NULL;
    }
    
    BN_free(s);
    BN_free(v);
    BN_free(A);
    if (u) BN_free(u);
    BN_free(B);
    BN_free(S);
    BN_free(b);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_CTX_free(ctx);
    
    return ver;
}

                                        


void srp_verifier_delete( struct SRPVerifier * ver )
{
    free( (char *) ver->username );
    free( (unsigned char *) ver->bytes_B );
    free( ver );
}



int srp_verifier_is_authenticated( struct SRPVerifier * ver )
{
    return ver->authenticated;
}


const char * srp_verifier_get_username( struct SRPVerifier * ver )
{
    return ver->username;
}

/* Key length is SRP_SHA256_DIGEST_LENGTH */
const unsigned char * srp_verifier_get_session_key( struct SRPVerifier * ver )
{
    return ver->session_key;
}



/* user_M must be exactly SRP_SHA256_DIGEST_LENGTH bytes in size */
void srp_verifier_verify_session( struct SRPVerifier * ver, const unsigned char * user_M, const unsigned char ** bytes_HAMK )
{
    if ( memcmp( ver->M, user_M, SRP_SHA256_DIGEST_LENGTH ) == 0 )
    {
        ver->authenticated = 1;
        *bytes_HAMK = ver->H_AMK;
    }
    else
        *bytes_HAMK = NULL;
}

/*******************************************************************************/

struct SRPUser * srp_user_new( const char * username, 
                               const unsigned char * bytes_password, int len_password )
{
    struct SRPUser  *usr  = (struct SRPUser *) malloc( sizeof(struct SRPUser) );
    int              ulen = strlen(username) + 1;
    
    usr->a = BN_new();
    usr->A = BN_new();
    usr->S = BN_new();
    
    usr->username     = (const char *) malloc(ulen);
    usr->password     = (const unsigned char *) malloc(len_password);
    usr->password_len = len_password;
    
    memcpy((char *)usr->username, username,       ulen);
    memcpy((char *)usr->password, bytes_password, len_password);
    
    usr->bytes_A = 0;
	
    return usr;
}



void srp_user_delete( struct SRPUser * usr )
{
    BN_free( usr->a );
    BN_free( usr->A );
    BN_free( usr->S );
    
    free((char *)usr->username);
    free((char *)usr->password);
    
    if (usr->bytes_A) 
        free( (char *)usr->bytes_A );
    
    free( usr );
}



int srp_user_is_authenticated( struct SRPUser * usr)
{
    return usr->authenticated;
}


const char * srp_user_get_username( struct SRPUser * usr )
{
    return usr->username;
}



/* Key length is SRP_SHA256_DIGEST_LENGTH */
const unsigned char * srp_user_get_session_key( struct SRPUser * usr )
{
    return usr->session_key;
}

/* Output: username, bytes_A, len_A */
void  srp_user_start_authentication( struct SRPUser * usr, const char ** username, 
                                     const unsigned char ** bytes_A, int * len_A )
{
    BN_CTX  *ctx  = BN_CTX_new();
    
    BN_rand(usr->a, 256, -1, 0);
		
    BN_mod_exp(usr->A, g, usr->a, N, ctx);
		
    BN_CTX_free(ctx);
    
    *len_A   = BN_num_bytes(usr->A);
    *bytes_A = malloc( *len_A );
        
    BN_bn2bin( usr->A, (unsigned char *) *bytes_A );
    
    usr->bytes_A = *bytes_A;
    *username = usr->username;
}


/* Output: bytes_M. Buffer length is SRP_SHA256_DIGEST_LENGTH */
void  srp_user_process_challenge( struct SRPUser * usr, 
                                  const unsigned char * bytes_s, int len_s, 
                                  const unsigned char * bytes_B, int len_B,
                                  const unsigned char ** bytes_M )
{
    BIGNUM *s    = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM *B    = BN_bin2bn(bytes_B, len_B, NULL);
    BIGNUM *u    = 0;
    BIGNUM *x    = 0;
    BIGNUM *v    = BN_new();
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *tmp3 = BN_new();
    BN_CTX *ctx  = BN_CTX_new();
    
    u = H_nn(usr->A,B);
    
    x = calculate_x( s, usr->username, usr->password, usr->password_len );
    
    /* SRP-6a safety check */
    if ( !BN_is_zero(B) && !BN_is_zero(u) )
    {
        BN_mod_exp(v, g, x, N, ctx);
        
        /* S = (B - k*(g^x)) ^ (a + ux) */
        BN_mul(tmp1, u, x, ctx);
        BN_add(tmp2, usr->a, tmp1);             /* tmp2 = (a + ux)      */
        BN_mod_exp(tmp1, g, x, N, ctx);
        BN_mul(tmp3, k, tmp1, ctx);             /* tmp3 = k*(g^x)       */
        BN_sub(tmp1, B, tmp3);                  /* tmp1 = (B - K*(g^x)) */
        BN_mod_exp(usr->S, tmp1, tmp2, N, ctx);

        hash_num(usr->S, usr->session_key);
        
        calculate_M( usr->M, usr->username, s, usr->A, B, usr->session_key );
        calculate_H_AMK( usr->H_AMK, usr->A, usr->M, usr->session_key );
        
        *bytes_M = usr->M;
    }
    else
    {
        *bytes_M = NULL;
    }
    
    BN_free(s);
    BN_free(B);
    BN_free(u);
    BN_free(x);
    BN_free(v);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);
    BN_CTX_free(ctx);
}
                                                  
/* bytes_HAMK must be exactly SRP_SHA256_DIGEST_LENGTH bytes in size */
void srp_user_verify_session( struct SRPUser * usr, const unsigned char * bytes_HAMK )
{
    if ( memcmp( usr->H_AMK, bytes_HAMK, SRP_SHA256_DIGEST_LENGTH ) == 0 )
        usr->authenticated = 1;
}
