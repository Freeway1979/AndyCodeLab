//
//  SecurityUtils.m
//
//
//  Created by andyliu on 2018/7/27.
//  Copyright © 2018 annkieliu@hotmail.com. All rights reserved.
//

#import "SecurityUtils.h"

#import <CommonCrypto/CommonKeyDerivation.h>

#import "CryptMD5.h"

@implementation SecurityUtils

#pragma mark PBKDF2
const NSUInteger kAlgorithmKeySize = 40;
const NSUInteger kRounds = 4096;

+ (NSString *)hexStringWithData:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *)[data bytes];
    if (!dataBuffer) {
        return [NSString string];
    }
    
    NSUInteger          dataLength  = [data length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendFormat:@"%02x", (unsigned char)dataBuffer[i]];
    }
    return [NSString stringWithString:hexString];
}
+ (NSData *)encryptPBKDF2DataWithPassword:(NSString *)password
                                     ssid:(NSString *)ssid
{
    // Salt data getting from salt string.
    NSData *saltData = [ssid dataUsingEncoding:NSUTF8StringEncoding];
    
    // Data of String to generate Hash key(hexa decimal string).
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *derivedKey = [NSMutableData dataWithLength:kAlgorithmKeySize];
    
    // Key Derivation using PBKDF2 algorithm.
    int result = CCKeyDerivationPBKDF(kCCPBKDF2, passwordData.bytes, passwordData.length, saltData.bytes, saltData.length, kCCPRFHmacAlgSHA1, kRounds,  derivedKey.mutableBytes,derivedKey.length);
  
//    NSString *str = [self hexStringWithData:derivedKey];
//    NSLog(@"%@ %d",str,result);
//    
    return derivedKey;

    
}

#pragma mark Salt+MD5
+ (NSString *)md5Crypt:(NSString *)password
                  salt:(NSString *)salt
                prefix:(NSString *)prefix
{
    if (prefix.length==0) {
        prefix = @"$1$";
    }
    char *prefixBytes = (char *) ([prefix dataUsingEncoding:NSUTF8StringEncoding].bytes);
    char *passwordBytes = (char *) ([password dataUsingEncoding:NSUTF8StringEncoding].bytes);
    char *saltBytes = (char *) ([salt dataUsingEncoding:NSUTF8StringEncoding].bytes);
    char *result = md5Crypt(passwordBytes, saltBytes, prefixBytes);
    //printf("%s\n",result);
    return [NSString stringWithCString:result encoding:NSUTF8StringEncoding];
}
@end
