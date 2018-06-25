#import <AdSupport/ASIdentifierManager.h>
#import <AdSupport/AdSupport.h>
#import <Foundation/Foundation.h>
#import <Foundation/NSProcessInfo.h>
#import <sqlite3.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <stdio.h>
//#import <MobileCoreServices/LSApplicationProxy.h>
#import "app_clear_policy.h"

typedef enum {
    kCert = 0,
    kKeys = 1,
    kGenp = 2,
    kInet = 3
}KeychainTable;
static void ClearKeychain(KeychainTable type,NSString* bundle_id){
    char type_array[5][6] = {"cert","keys","genp","inet",""};
    sqlite3 *ppDb = nil;
    if(sqlite3_open("/private/var/Keychains/keychain-2.db",&ppDb)!=SQLITE_OK){
        return;
    }
    int type_int = (int)type;
    NSString* sql_format = nil;
    sql_format = [[NSString alloc] initWithFormat:
                  @"DELETE FROM %s WHERE agrp like '%%%@%%'",
                  type_array[type_int],bundle_id];
    const char* utf8 = [sql_format UTF8String];
    sqlite3_exec(ppDb, utf8, 0, 0, 0);
    sqlite3_close(ppDb);
}
static void Cleanup(){
    NSString *folderPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NSError *error = nil;
    for (NSString *file in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:folderPath error:&error]) {
        [[NSFileManager defaultManager] removeItemAtPath:[folderPath stringByAppendingPathComponent:file] error:&error];
    }
}
static void ClearTmpDirectory(){
    NSArray* tmpDirectory = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:NSTemporaryDirectory() error:NULL];
    for (NSString *file in tmpDirectory) {
        [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithFormat:@"%@%@", NSTemporaryDirectory(), file] error:NULL];
    }
}
static void ClearDirectoryURLContents(NSURL *url){
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:url includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsSubdirectoryDescendants errorHandler:nil];
    NSURL *child;
    while ((child = [enumerator nextObject])) {
        [fm removeItemAtURL:child error:NULL];
    }
}
static void ResetDiskContent(NSString* bundle_id){
    NSString *identifier = bundle_id;
    LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:identifier];
    NSString *title = app.localizedShortName;
    NSNumber *originalDynamicSize = [[app.dynamicDiskUsage retain] autorelease];
    NSURL *dataContainer = app.dataContainerURL;
    //SBSApplicationTerminationAssertionRef assertion = SBSApplicationTerminationAssertionCreateWithError(NULL, identifier, 1, NULL);
    ClearDirectoryURLContents([dataContainer URLByAppendingPathComponent:@"tmp" isDirectory:YES]);
    NSURL *libraryURL = [dataContainer URLByAppendingPathComponent:@"Library" isDirectory:YES];
    ClearDirectoryURLContents(libraryURL);
    [[NSFileManager defaultManager] createDirectoryAtURL:[libraryURL URLByAppendingPathComponent:@"Preferences" isDirectory:YES] withIntermediateDirectories:YES attributes:nil error:NULL];
    ClearDirectoryURLContents([dataContainer URLByAppendingPathComponent:@"Documents" isDirectory:YES]);
    //if (assertion) {
    //  SBSApplicationTerminationAssertionInvalidate(assertion);
    //}
    NSNumber *newDynamicSize = [LSApplicationProxy applicationProxyForIdentifier:identifier].dynamicDiskUsage;
    if ([newDynamicSize isEqualToNumber:originalDynamicSize]) {
        NSLog(@"%@ was already reset, no disk space was reclaimed.", title);
    } else {
        NSLog(@"%@ is now restored to a fresh state. Reclaimed %@ bytes!", title, [NSNumber numberWithDouble:[originalDynamicSize doubleValue] - [newDynamicSize doubleValue]]);
    }
}
static void ClearCache(NSString* bundle_id){
    void* handle_ptr = NULL;
    handle_ptr = dlopen("SpringBoardServices", RTLD_LAZY);
    void* func_ptr = NULL;
    func_ptr = dlsym(handle_ptr, "SBSApplicationTerminationAssertionCreateWithError");
    if (func_ptr!=NULL) {
        *(unsigned long*)(&SBSApplicationTerminationAssertionCreateWithError)
            = (unsigned long)func_ptr;
    }
    ResetDiskContent(bundle_id);
    NSString *identifier = bundle_id;
    LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:identifier];
    NSString *title = app.localizedShortName;
    NSNumber *originalDynamicSize = [[app.dynamicDiskUsage retain] autorelease];
    NSURL *dataContainer = app.dataContainerURL;
    //SBSApplicationTerminationAssertionRef assertion = SBSApplicationTerminationAssertionCreateWithError(NULL, identifier, 1, NULL);
    ClearDirectoryURLContents([dataContainer URLByAppendingPathComponent:@"tmp" isDirectory:YES]);
    ClearDirectoryURLContents([[dataContainer URLByAppendingPathComponent:@"Library" isDirectory:YES] URLByAppendingPathComponent:@"Caches" isDirectory:YES]);
    ClearDirectoryURLContents([[[dataContainer URLByAppendingPathComponent:@"Library" isDirectory:YES] URLByAppendingPathComponent:@"Application Support" isDirectory:YES] URLByAppendingPathComponent:@"Dropbox" isDirectory:YES]);
    //if (assertion) {
    //SBSApplicationTerminationAssertionInvalidate(assertion);
    //}
    NSNumber *newDynamicSize = [LSApplicationProxy applicationProxyForIdentifier:identifier].dynamicDiskUsage;
    if ([newDynamicSize isEqualToNumber:originalDynamicSize]) {
        NSLog(@"Cache for %@ was already empty, no disk space was reclaimed.", title);
    } else {
        NSLog(@"Reclaimed %@ bytes!\n%@ may use more data or run slower on next launch to repopulate the cache.", [NSNumber numberWithDouble:[originalDynamicSize doubleValue] - [newDynamicSize doubleValue]], title);
    }
}
static void ResetBundleIdAllKeychain(NSString* bundle_id){
    ClearKeychain(kCert,bundle_id);
    ClearKeychain(kKeys,bundle_id);
    ClearKeychain(kGenp,bundle_id);
    ClearKeychain(kInet,bundle_id);
}
static void ResetAPP(NSString* bundle_id){
    Cleanup();
    ClearTmpDirectory();
    ResetBundleIdAllKeychain(bundle_id);
  //ResetBundleIdAllKeychain(@"com.apple.itunesstored.token");
  //ResetBundleIdAllKeychain(@"com.apple.account.idms.heartbeat-token");
  //ResetBundleIdAllKeychain(@"com.apple.account.idms.token");
    ClearCache(bundle_id);
}
