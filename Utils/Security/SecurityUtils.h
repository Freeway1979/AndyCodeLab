//
//  SecurityUtils.h
//  
//
//  Created by andyliu on 2018/7/27.
//  Copyright © 2018 annkieliu@hotmail.com. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SecurityUtils : NSObject

#pragma mark PBKDF2
/**
 Generate a derived key with password and ssid(salt)

 @param password <#password description#>
 @param ssid <#ssid description#>
 @return <#return value description#>
 */
+ (NSData *)encryptPBKDF2DataWithPassword:(NSString *)password
                                     ssid:(NSString *)ssid;

#pragma mark Salt+MD5
+ (NSString *)md5Crypt:(NSString * _Nonnull)password
                  salt:(NSString * _Nonnull)salt
                prefix:(NSString * _Nonnull)prefix;
@end
