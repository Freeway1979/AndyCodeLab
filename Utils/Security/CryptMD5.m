//
//  CryptMD5.m
//  CryptMD5
//
//  Created by andyliu on 2018/10/12.
//  Copyright © 2018 annkieliu@hotmail.com. All rights reserved.
//

#import "CryptMD5.h"

#import <CommonCrypto/CommonCrypto.h>

#define CC_MD5_DIGEST_LENGTH 16
#define ROUNDS 1000


static unsigned char itoa64[] =        /* 0 ... 63 => ascii - 64 */
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
        *s++ = itoa64[v & 0x3f];
        v >>= 6;
    }
}

/*
 */
char *md5Crypt(const char *password,const char *salt,const char *prefix)
{
    const unsigned int keyLen = (uint32_t)strlen(password);
    char *thePrefix = (char *)prefix;
    if (thePrefix == nil) {
        thePrefix = "$1$";
    }
    CC_MD5_CTX  md5Context;
    CC_MD5_Init(&md5Context);
    /*
     * The password first, since that is what is most unknown
     */
    CC_MD5_Update(&md5Context, password, keyLen);
    /*
     * Then our magic string
     */
    CC_MD5_Update(&md5Context, thePrefix, (uint32_t)strlen(thePrefix));
    /*
     * Then the raw salt
     */
    CC_MD5_Update(&md5Context, salt, (uint32_t)strlen(salt));
   
    CC_MD5_CTX  md5Context1;
    CC_MD5_Init(&md5Context1);
    /*
     * Then just as many characters of the MD5(pw,salt,pw)
     */
    CC_MD5_Update(&md5Context1, password, keyLen);
    CC_MD5_Update(&md5Context1, salt, (uint32_t)strlen(salt));
    CC_MD5_Update(&md5Context1, password, keyLen);
    
    unsigned char digist[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(digist, &md5Context1);
    int ii = keyLen;
    while (ii > 0) {
        CC_MD5_Update(&md5Context, digist, ii > 16 ? 16 : ii);
        ii -= 16;
    }
    memset(digist,0,sizeof(digist));
    
    /*
     * Then something really weird...
     */
    ii = keyLen;
    while (ii > 0) {
        if ((ii & 1) == 1) {
            CC_MD5_Update(&md5Context, digist, 1);
        } else {
            CC_MD5_Update(&md5Context, password, 1);
        }
        ii >>= 1;
    }

    /*
     * Now make the output string
     */
    static char passwd[120];
    memset((void*)passwd,0,120);
    /* Now make the output string */
    strcpy(passwd, thePrefix);
    strncat(passwd, salt,strlen(salt));
    strcat(passwd, "$");
    CC_MD5_Final(digist,&md5Context);
    
    /*
     * and now, just to make sure things don't run too fast On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for (int i = 0; i < ROUNDS; i++) {
        CC_MD5_Init(&md5Context1);
        if ((i & 1) != 0) {
            CC_MD5_Update(&md5Context1, password, keyLen);
        } else {
            CC_MD5_Update(&md5Context1, digist, CC_MD5_DIGEST_LENGTH);
        }
        
        if (i % 3 != 0) {
            CC_MD5_Update(&md5Context1, salt, (uint32_t)strlen(salt));
        }
        
        if (i % 7 != 0) {
            CC_MD5_Update(&md5Context1, password, keyLen);
        }
        
        if ((i & 1) != 0) {
            CC_MD5_Update(&md5Context1, digist, CC_MD5_DIGEST_LENGTH);
        } else {
            CC_MD5_Update(&md5Context1, password, keyLen);
        }
        CC_MD5_Final(digist,&md5Context1);
    }
    
    static char *p;
    
    p = passwd + strlen(passwd);
    
    unsigned long l;
    l = (digist[0] << 16) | (digist[6] << 8) | digist[12];
    to64(p, l, 4);
    p += 4;
    l = (digist[1] << 16) | (digist[7] << 8) | digist[13];
    to64(p, l, 4);
    p += 4;
    l = (digist[2] << 16) | (digist[8] << 8) | digist[14];
    to64(p, l, 4);
    p += 4;
    l = (digist[3] << 16) | (digist[9] << 8) | digist[15];
    to64(p, l, 4);
    p += 4;
    l = (digist[4] << 16) | (digist[10] << 8) | digist[5];
    to64(p, l, 4);
    p += 4;
    l = digist[11];
    to64(p, l, 2);
    p += 2;
    *p = '\0';
    
    /* Don't leave anything around in vm they could use. */
    memset(digist, 0, sizeof(digist) );
    
    return passwd;
    
}
