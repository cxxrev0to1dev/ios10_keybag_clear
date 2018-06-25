/* 
 * Copyright (c) 2011, Neohapsis, Inc.
 * All rights reserved.
 *
 * Implementation by Patrick Toomey
 *
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met: 
 *
 *  - Redistributions of source code must retain the above copyright notice, this list 
 *   of conditions and the following disclaimer. 
 *  - Redistributions in binary form must reproduce the above copyright notice, this 
 *    list of conditions and the following disclaimer in the documentation and/or 
 *    other materials provided with the distribution. 
 *  - Neither the name of Neohapsis nor the names of its contributors may be used to 
 *    endorse or promote products derived from this software without specific prior 
 *    written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#include <err.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <objc/message.h>
#import "sqlite3.h"
//#import "app_clear_policy.m"
#import "app_clear_policy_test.m"

static char* BUNDLE_ID = NULL;

static int chown_names(const char *a1,
                       const char *a2, const char *a3){
  return chown(a1, getpwnam(a2)->pw_uid, getgrnam(a3)->gr_gid);
}
static void ClearITunesStored(){
  //system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/updates.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/play_activity.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored2.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored_private.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/*.sqlitedb-wal");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/*.sqlitedb-shm");
}
static void cccc(){
  system("/bin/rm -rf /var/mobile/Library/Accounts");
  mkdir("/var/mobile/Library/Accounts", 0x1C0u);
  chown_names("/var/mobile/Library/Accounts", "mobile", "mobile");
  
  system("/bin/rm -rf /var/mobile/Library/Caches");
  mkdir("/var/mobile/Library/Caches", 0x1FFu);
  chown_names("/var/mobile/Library/Caches", "mobile", "mobile");
  system("/usr/libexec/cydia/setnsfpn /var/mobile/Library/Caches");
  
  system("/bin/rm -rf /var/mobile/Library/Cookies");
  mkdir("/var/mobile/Library/Cookies", 0x1C0u);
  chown_names("/var/mobile/Library/Cookies", "mobile", "mobile");
  
  system("/bin/rm -rf /private/var/mobile/Library/com.apple.iTunesStore/");
  mkdir("/private/var/mobile/Library/com.apple.iTunesStore", 0x1C0u);
  chown_names("/private/var/mobile/Library/com.apple.iTunesStore", "mobile", "mobile");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/Wishlists/");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored2.sqlitedb-shm");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored_private.sqlitedb-wal");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/play_activity.sqlitedb-wal");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/play_activity.sqlitedb-shm");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored_private.sqlitedb-shm");
  //system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/updates.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/play_activity.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored2.sqlitedb-wal");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored2.sqlitedb");
  system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/itunesstored_private.sqlitedb");
  system("rm -rf /private/var/mobile/Library/Preferences/com.apple.itunesstored.plist");
  //system("su mobile -c uicache");
  /*
  system("/bin/rm -rf /private/var/mobile/Library/com.apple.itunesstored/");
  mkdir("/private/var/mobile/Library/com.apple.itunesstored", 0x1C0u);
  chown_names("/private/var/mobile/Library/com.apple.itunesstored", "mobile", "mobile");
  system("chmod 777 /private/var/mobile/Library/com.apple.itunesstored/");
  */
}

void printToStdOut(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *formattedString = [[NSString alloc] initWithFormat: format arguments: args];
    va_end(args);
    [[NSFileHandle fileHandleWithStandardOutput] writeData: [formattedString dataUsingEncoding: NSNEXTSTEPStringEncoding]];
	[formattedString release];
}

void printUsage() {
	printToStdOut(@"Usage: keychain_dumper [-e]|[-h]|[-agnick]\n");
	printToStdOut(@"<no flags>: Dump Password Keychain Items (Generic Password, Internet Passwords)\n");
	printToStdOut(@"-a: Dump All Keychain Items (Generic Passwords, Internet Passwords, Identities, Certificates, and Keys)\n");
	printToStdOut(@"-e: Dump Entitlements\n");
	printToStdOut(@"-g: Dump Generic Passwords\n");
	printToStdOut(@"-n: Dump Internet Passwords\n");
	printToStdOut(@"-i: Dump Identities\n");
	printToStdOut(@"-c: Dump Certificates\n");
	printToStdOut(@"-k: Dump Keys\n");
}

void dumpKeychainEntitlements() {
    NSString *databasePath = @"/var/Keychains/keychain-2.db";
    const char *dbpath = [databasePath UTF8String];
    sqlite3 *keychainDB;
    sqlite3_stmt *statement;
	NSMutableString *entitlementXML = [NSMutableString stringWithString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                       "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                                       "<plist version=\"1.0\">\n"
                                       "\t<dict>\n"
                                       "\t\t<key>keychain-access-groups</key>\n"
                                       "\t\t<array>\n"];
	
    if (sqlite3_open(dbpath, &keychainDB) == SQLITE_OK)
    {
        const char *query_stmt = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet";
		
        if (sqlite3_prepare_v2(keychainDB, query_stmt, -1, &statement, NULL) == SQLITE_OK)
        {
			while(sqlite3_step(statement) == SQLITE_ROW)
            {            
				NSString *group = [[NSString alloc] initWithUTF8String:(const char *) sqlite3_column_text(statement, 0)];
				
                [entitlementXML appendFormat:@"\t\t\t<string>%@</string>\n", group];
                [group release];
            }
            sqlite3_finalize(statement);
        }
        else
        {
            printToStdOut(@"Unknown error querying keychain database\n");
		}
		[entitlementXML appendString:@"\t\t</array>\n"
         "\t</dict>\n"
         "</plist>\n"];
		sqlite3_close(keychainDB);
		printToStdOut(@"%@", entitlementXML);
	}
	else
	{
		printToStdOut(@"Unknown error opening keychain database\n");
	}
}


NSMutableArray *getCommandLineOptions(int argc, char **argv) {
	NSMutableArray *arguments = [[NSMutableArray alloc] init];
	int argument;
	if (argc == 1) {
		[arguments addObject:(id)kSecClassGenericPassword];
		[arguments addObject:(id)kSecClassInternetPassword];
		return [arguments autorelease];
	}
	while ((argument = getopt (argc, argv, "aegnickh")) != -1) {
		switch (argument) {
			case 'a':
				[arguments addObject:(id)kSecClassGenericPassword];
				[arguments addObject:(id)kSecClassInternetPassword];
				[arguments addObject:(id)kSecClassIdentity];
				[arguments addObject:(id)kSecClassCertificate];
				[arguments addObject:(id)kSecClassKey];
				return [arguments autorelease];
			case 'e':
				// if they want to dump entitlements we will assume they don't want to dump anything else
				[arguments addObject:@"dumpEntitlements"];
				return [arguments autorelease];
			case 'g':
				[arguments addObject:(id)kSecClassGenericPassword];
				break;
			case 'n':
				[arguments addObject:(id)kSecClassInternetPassword];
				break;
			case 'i':
				[arguments addObject:(id)kSecClassIdentity];
				break;
			case 'c':
				[arguments addObject:(id)kSecClassCertificate];
				break;
			case 'k':
				[arguments addObject:(id)kSecClassKey];
				break;
			case 'h':
				printUsage();
				break;
			case '?':
			    printUsage();
			 	exit(EXIT_FAILURE);
			default:
				continue;
		}
	}

	return [arguments autorelease];

}

NSArray * getKeychainObjectsForSecClass(CFTypeRef kSecClassType) {
	NSMutableDictionary *genericQuery = [[NSMutableDictionary alloc] init];
	
	[genericQuery setObject:(id)kSecClassType forKey:(id)kSecClass];
	[genericQuery setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
	[genericQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
	
	NSArray *keychainItems = nil;
	if (SecItemCopyMatching((CFDictionaryRef)genericQuery, (CFTypeRef *)&keychainItems) != noErr)
	{
		keychainItems = nil;
	}
	[genericQuery release];
	return keychainItems;
}

NSString * getEmptyKeychainItemString(CFTypeRef kSecClassType) {
	if (kSecClassType == kSecClassGenericPassword) {
		return @"No Generic Password Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassInternetPassword) {
		return @"No Internet Password Keychain items found.\n";	
	} 
	else if (kSecClassType == kSecClassIdentity) {
		return @"No Identity Keychain items found.\n";
	}
	else if (kSecClassType == kSecClassCertificate) {
		return @"No Certificate Keychain items found.\n";	
	}
	else if (kSecClassType == kSecClassKey) {
		return @"No Key Keychain items found.\n";	
	}
	else {
		return @"Unknown Security Class\n";
	}
	
}

void printGenericPassword(NSDictionary *passwordItem) {
	printToStdOut(@"Generic Password\n");
	printToStdOut(@"----------------\n");
	printToStdOut(@"Service: %@\n", [passwordItem objectForKey:(id)kSecAttrService]);
	printToStdOut(@"Account: %@\n", [passwordItem objectForKey:(id)kSecAttrAccount]);
	printToStdOut(@"Entitlement Group: %@\n", [passwordItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [passwordItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Generic Field: %@\n", [[passwordItem objectForKey:(id)kSecAttrGeneric] description]);
	NSData* passwordData = [passwordItem objectForKey:(id)kSecValueData];
	printToStdOut(@"Keychain Data: %@\n\n", [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding]);
}

void printInternetPassword(NSDictionary *passwordItem) {
	printToStdOut(@"Internet Password\n");
	printToStdOut(@"-----------------\n");
	printToStdOut(@"Server: %@\n", [passwordItem objectForKey:(id)kSecAttrServer]);
	printToStdOut(@"Account: %@\n", [passwordItem objectForKey:(id)kSecAttrAccount]);
	printToStdOut(@"Entitlement Group: %@\n", [passwordItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [passwordItem objectForKey:(id)kSecAttrLabel]);
	NSData* passwordData = [passwordItem objectForKey:(id)kSecValueData];
	printToStdOut(@"Keychain Data: %@\n\n", [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding]);
}


void printCertificate(NSDictionary *certificateItem) {
	SecCertificateRef certificate = (SecCertificateRef)[certificateItem objectForKey:(id)kSecValueRef];

	CFStringRef summary;
	summary = SecCertificateCopySubjectSummary(certificate);
	printToStdOut(@"Certificate\n");
	printToStdOut(@"-----------\n");
	printToStdOut(@"Summary: %@\n", (NSString *)summary);
	CFRelease(summary);
	printToStdOut(@"Entitlement Group: %@\n", [certificateItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [certificateItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Serial Number: %@\n", [certificateItem objectForKey:(id)kSecAttrSerialNumber]);
	printToStdOut(@"Subject Key ID: %@\n", [certificateItem objectForKey:(id)kSecAttrSubjectKeyID]);
	printToStdOut(@"Subject Key Hash: %@\n\n", [certificateItem objectForKey:(id)kSecAttrPublicKeyHash]);
	
}

void printKey(NSDictionary *keyItem) {
	NSString *keyClass = @"Unknown";
	CFTypeRef _keyClass = [keyItem objectForKey:(id)kSecAttrKeyClass];

	if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassPublic]) {
		keyClass = @"Public";
	}
	else if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassPrivate]) {
		keyClass = @"Private";
	}
	else if ([[(id)_keyClass description] isEqual:(id)kSecAttrKeyClassSymmetric]) {
		keyClass = @"Symmetric";
	}

	printToStdOut(@"Key\n");
	printToStdOut(@"---\n");
	printToStdOut(@"Entitlement Group: %@\n", [keyItem objectForKey:(id)kSecAttrAccessGroup]);
	printToStdOut(@"Label: %@\n", [keyItem objectForKey:(id)kSecAttrLabel]);
	printToStdOut(@"Application Label: %@\n", [keyItem objectForKey:(id)kSecAttrApplicationLabel]);
	printToStdOut(@"Key Class: %@\n", keyClass);
	printToStdOut(@"Permanent Key: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrIsPermanent]) == true ? @"True" : @"False");
	printToStdOut(@"Key Size: %@\n", [keyItem objectForKey:(id)kSecAttrKeySizeInBits]);
	printToStdOut(@"Effective Key Size: %@\n", [keyItem objectForKey:(id)kSecAttrEffectiveKeySize]);
	printToStdOut(@"For Encryption: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanEncrypt]) == true ? @"True" : @"False");
	printToStdOut(@"For Decryption: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanDecrypt]) == true ? @"True" : @"False");
	printToStdOut(@"For Key Derivation: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanDerive]) == true ? @"True" : @"False");
	printToStdOut(@"For Signatures: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanSign]) == true ? @"True" : @"False");
	printToStdOut(@"For Signature Verification: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanVerify]) == true ? @"True" : @"False");
	printToStdOut(@"For Key Wrapping: %@\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanWrap]) == true ? @"True" : @"False");
	printToStdOut(@"For Key Unwrapping: %@\n\n", CFBooleanGetValue((CFBooleanRef)[keyItem objectForKey:(id)kSecAttrCanUnwrap]) == true ? @"True" : @"False");

}

void printIdentity(NSDictionary *identityItem) {
	SecIdentityRef identity = (SecIdentityRef)[identityItem objectForKey:(id)kSecValueRef];
	SecCertificateRef certificate;

	SecIdentityCopyCertificate(identity, &certificate);
	NSMutableDictionary *identityItemWithCertificate = [identityItem mutableCopy];
	[identityItemWithCertificate setObject:(id)certificate forKey:(id)kSecValueRef];
	printToStdOut(@"Identity\n");
	printToStdOut(@"--------\n");
	printCertificate(identityItemWithCertificate);
	printKey(identityItemWithCertificate);
	[identityItemWithCertificate release];
}

void printResultsForSecClass(NSArray *keychainItems, CFTypeRef kSecClassType) {
	if (keychainItems == nil) {
		printToStdOut(getEmptyKeychainItemString(kSecClassType));
		return;
	}
  unsigned long long delete_count = 0;
	NSDictionary *keychainItem;
	for (keychainItem in keychainItems) {
    id tmp = [keychainItem objectForKey:(id)kSecAttrService];
    NSString* target = (NSString*)tmp;
    if (target == nil || [target length]==0) {
      continue;
    }
    if (BUNDLE_ID&&[target isEqual:@(BUNDLE_ID)]) {
      SecItemDelete((CFDictionaryRef)keychainItem);
    }
		if (kSecClassType == kSecClassGenericPassword) {
      //NSLog(@"sssssssssssssss:%s",object_getClassName(tmp));
      /*if ([tmp isKindOfClass:[NSString class]]) {
        NSError *error = NULL;
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"-" options:NSRegularExpressionCaseInsensitive error:&error];
        NSUInteger numberOfMatches = [regex numberOfMatchesInString:target options:0 range:NSMakeRange(0, [target length])];
        if (numberOfMatches == 4) {
          SecItemDelete((CFDictionaryRef)keychainItem);
          system("rm -rf /private/var/preferences/com.apple.networkextension.plist");
          system("killall networkd_privileged&killall networkd");
          continue;
        }
      }*/
      bool gs_0 = false;
      gs_0 = [target isEqual: @"com.apple.gs.news.auth.com.apple.account.AppleIDAuthentication.token"];
      bool gs_a = false;
      gs_a = [target isEqual: @"com.apple.gs.pb.auth.com.apple.account.AppleIDAuthentication.token-expiry-date"];
      bool gs_b = false;
      gs_b = [target isEqual: @"com.apple.gs.icloud.auth.com.apple.account.AppleIDAuthentication.token-expiry-date"];
      bool gs_c = false;
      gs_c = [target isEqual: @"com.apple.account.AppleIDAuthentication.token-expiry-date"];
      if (gs_0||gs_a||gs_b||gs_c) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      gs_0 = [target isEqual: @"com.apple.account.AppleAccount.token"];
      gs_a = [target isEqual: @"com.apple.account.AppleAccount.maps-token"];
      gs_b = [target isEqual: @"com.apple.appleaccount.fmf.token"];
      gs_c = [target isEqual: @"com.apple.appleaccount.cloudkit.token"];
      if (gs_0||gs_a||gs_b||gs_c) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      if ([target isEqual: @"com.apple.itunesstored.token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"Apple ID Authentication"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.appleaccount.fmf.apptoken"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.idms.heartbeat-token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.CloudKit.token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.cloudd.deviceIdentifier.Production"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.DeviceLocator.token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.FindMyFriends.find-my-friends-app-token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.FindMyFriends.find-my-friends-token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.gs.idms.hb.com.apple.account.AppleIDAuthentication.token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.idms.token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.iTunesStore.password"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"com.apple.account.IdentityServices.token"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if ([target isEqual: @"BackupIDSAccountToken"]) {
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else if([target isEqual:@"push.apple.com,PerAppToken.v0"]){
        SecItemDelete((CFDictionaryRef)keychainItem);
        delete_count++;
      }
      else{
        NSData* passwordData = [keychainItem objectForKey:(id)kSecValueData];
        if ([passwordData length] >= 200) {
          SecItemDelete((CFDictionaryRef)keychainItem);
          delete_count++;
        }
        else{
          printGenericPassword(keychainItem);
        }
      }
		}
		else if (kSecClassType == kSecClassInternetPassword) {
			printInternetPassword(keychainItem);
		}
		else if (kSecClassType == kSecClassIdentity) {
			printIdentity(keychainItem);
		}
		else if (kSecClassType == kSecClassCertificate) {
			printCertificate(keychainItem);
		}
		else if (kSecClassType == kSecClassKey) {
			printKey(keychainItem);
		}
	}
  NSLog(@"delete count:%llu",delete_count);
	return;
}

static BOOL UpdateKvsList(NSData* plist){
  sqlite3* kvs_db;
  NSString* path =
    @"/private/var/mobile/Library/com.apple.itunesstored/kvs.sqlitedb";
  if(sqlite3_open([path UTF8String],&kvs_db)!=SQLITE_OK){
    sqlite3_close(kvs_db);
    return NO;
  }
  sqlite3_stmt *statement;
  char *sql = "UPDATE kvs_value SET value=? WHERE key='TempStorefront' or key='Storefront'";
  int success = sqlite3_prepare_v2(kvs_db,sql,-1,&statement,NULL);
  if(success!=SQLITE_OK){
    sqlite3_close(kvs_db);
    return NO;
  }
  sqlite3_bind_blob(statement,1,[plist bytes],[plist length],NULL);
  sqlite3_bind_blob(statement,2,[plist bytes],[plist length],NULL);
  success = sqlite3_step(statement);
  sqlite3_finalize(statement);
  sqlite3_close(kvs_db);
  if(success==SQLITE_ERROR){
    return NO;
  }
  else{
    return YES;
  }
}
static void DelAll(){
  NSString *cacheDir = @"/private/var/mobile/Library/com.apple.itunesstored/";
  NSFileManager *fm = [NSFileManager defaultManager];
  NSArray *fileList = [fm contentsOfDirectoryAtPath: cacheDir error: nil];
  for(NSInteger i = 0; i < [fileList count]; ++i){
    NSString *fp =  [fileList objectAtIndex: i];
    NSString *remPath = [cacheDir stringByAppendingPathComponent: fp];
    if ([remPath rangeOfString:@"kvs.sqlitedb"].length>0) {
      continue;
    }
    [fm removeItemAtPath: remPath error: nil];
  }
}
static int GetCaptcha(sqlite3* db){
  NSString *sql = @"SELECT * FROM cfurl_cache_response";
  sqlite3_stmt *stmt = nil;
  int result = sqlite3_prepare_v2(db, [sql UTF8String], -1, &stmt, nil);
  unsigned char *url = nil;
  if (result == SQLITE_OK){
    while (sqlite3_step(stmt) == SQLITE_ROW){
      int entry_id = sqlite3_column_int(stmt, 0);
      url = (unsigned char*)sqlite3_column_text(stmt, 4);
      if (url!=nil&&strstr((const char*)url,"/captcha/?")!=NULL) {
        char* s1 = "DELETE FROM cfurl_cache_response WHERE entry_ID=?";
        if(sqlite3_prepare_v2(db,s1,-1,&stmt,NULL)==SQLITE_OK){
          sqlite3_bind_int(stmt, 1, entry_id);
          while(sqlite3_step(stmt) == SQLITE_ROW);
          sqlite3_finalize(stmt);
        }
      }
    }
    sqlite3_step(stmt);
    if (url!=nil&&strstr((const char*)url,"/captcha/?")!=NULL) {
      NSURL *url = [NSURL URLWithString:@"http://verify.25fz.com/imgToCode.php"];
      NSMutableURLRequest *request = [[NSMutableURLRequest alloc]initWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:10];
      [request setHTTPMethod:@"POST"];
      const char* str2 = (const char*)url;
      NSString *str = @"verify_code_url=";
      NSString *str5 = [str stringByAppendingString:@(str2)];
      NSData *data = [str5 dataUsingEncoding:NSUTF8StringEncoding];
      [request setHTTPBody:data];
      NSData *received = [NSURLConnection sendSynchronousRequest:request returningResponse:nil error:nil];
      NSString *str1 = [[NSString alloc]initWithData:received encoding:NSUTF8StringEncoding];
      NSLog(@"%@",str1);
      return 0;
    }
    else{
      return 1;
    }
  }
  sqlite3_finalize(stmt);
  return 2;
}
static int GetCaptchaURL(){
  NSString *identifier = @"com.apple.AppStore";
  LSApplicationProxy *app;
  app = [LSApplicationProxy applicationProxyForIdentifier:identifier];
  NSURL *dataContainer = app.dataContainerURL;
  NSURL *db;
  NSString* file = @"/Library/Caches/com.apple.AppStore/Cache.db";
  db = [dataContainer URLByAppendingPathComponent:file isDirectory:NO];
  sqlite3* kvs_db;
  NSMutableString* ss = [[NSMutableString alloc] initWithString:
                         [db absoluteString]];
  NSString* file_proto = @"file://";
  NSRange substr = [ss rangeOfString:file_proto];
  if (substr.location != NSNotFound) {
    [ss deleteCharactersInRange:substr];
  }
  if(sqlite3_open([ss UTF8String],&kvs_db)!=SQLITE_OK){
    sqlite3_close(kvs_db);
    return 2;
  }
  int status = GetCaptcha(kvs_db);
  sqlite3_close(kvs_db);
  return status;
}
int main(int argc,char** argv){
  setuid(0);
  setgid(0);
  bool is_clear_cache = false;
  bool is_reset_kvs = false;
  bool is_captcha = false;
  NSString* kvs_plist;
  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i],"-cache")) {
      is_clear_cache = true;
    }
    else if (!strcmp(argv[i],"-clear_id")) {
      BUNDLE_ID = argv[i+1];
    }
    else if (!strcmp(argv[i],"-kvs")) {
      is_reset_kvs = true;
      kvs_plist = @(argv[i+1]);
    }
    else if (!strcmp(argv[i],"-captcha")) {
      is_captcha = true;
    }
  }
  if (is_captcha) {
    return GetCaptchaURL();
  }
  if (is_clear_cache) {
    cccc();
    return 0;
  }
  if (BUNDLE_ID) {
    //Cleanup();
    //ClearTmpDirectory();
    ClearCacheTest(@(BUNDLE_ID));
    //ClearCache(@(BUNDLE_ID));
    return 0;
  }
  if (is_reset_kvs) {
    NSData *output = [NSData dataWithContentsOfFile:
                       [kvs_plist stringByExpandingTildeInPath]];
    UpdateKvsList(output);
    return 0;
  }
	id pool=[NSAutoreleasePool new];
	NSArray* arguments;
	arguments = getCommandLineOptions(argc, argv);
	if ([arguments indexOfObject:@"dumpEntitlements"] != NSNotFound) {
		dumpKeychainEntitlements();
		exit(EXIT_SUCCESS);
	}
	NSArray *keychainItems = nil;
	for (id kSecClassType in (NSArray *) arguments) {
		keychainItems = getKeychainObjectsForSecClass((CFTypeRef)kSecClassType);
		printResultsForSecClass(keychainItems, (CFTypeRef)kSecClassType);
		[keychainItems release];	
	}
	[pool drain];
  return 0;
}

