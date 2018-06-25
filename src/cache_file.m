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

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)


int chown_names(const char *a1, const char *a2, const char *a3){
  return chown(a1, getpwnam(a2)->pw_uid, getgrnam(a3)->gr_gid);
}
bool PathExist(NSString* path){
  NSFileManager *fm;
  fm = [NSFileManager defaultManager];
  return ([fm fileExistsAtPath:path] == NO);
}
void KillAppStore(){
  system("killall -6 itunesstored");
  system("killall -6 akd");
  system("killall -6 online-auth-agent");
  system("killall -6 deleted");
  system("killall -6 itunescloudd");
  system("killall -6 storebookkeeperd");
  system("killall -6 AppStore");
  system("killall -6 locationd");
  system("killall -6 AppleIDAuthAgent");
  system("killall -6 CacheDeleteSystemFiles");
  system("killall -6 CacheDeleteAppContainerCaches");
  system("killall -6 CacheDeleteITunesStore");
}
int main(int argc,char** argv){
  @autoreleasepool {
    setgid(0);
    setuid(0);
    bool is_lock_screen = false;
    bool is_kill_spring_board = true;
    bool is_remove_itunesstored = false;
    bool is_kill_appstore = true;
    bool is_reset_keychain = true;
    bool is_reset_appdata = true;
    bool is_reset_library = true;
    bool is_remove_tmp = true;
    for (int i=0; i<argc; i++) {
      if (!strcmp(argv[i],"-LockScreen")) {
        is_lock_screen = true;
      }
      else if (!strcmp(argv[i],"-KillSpringBoard")) {
        is_kill_spring_board = true;
      }
      else if (!strcmp(argv[i],"-KillAppStore")) {
        is_kill_appstore = true;
      }
      else if (!strcmp(argv[i],"-ResetKeychain")) {
        is_reset_keychain = true;
      }
      else if (!strcmp(argv[i],"-ResetAppData")) {
        is_reset_appdata = true;
      }
      else if (!strcmp(argv[i],"-ResetLibrary")) {
        is_reset_library = true;
      }
      else if (!strcmp(argv[i],"-RemoveTMP")) {
        is_remove_tmp = true;
      }
      else if (!strcmp(argv[i],"-RemoveITunesStored")) {
        is_remove_itunesstored = true;
      }
    }
    if (is_kill_appstore) {
      KillAppStore();
    }
    if (is_reset_keychain) {
      char* argvs[] = {argv[0],NULL};
      ResetKeychain(argc,argvs);
    }
    if (is_reset_appdata) {
      system("rm -rf /var/mobile/Containers/Data");
      mkdir("/var/mobile/Containers/Data/", 0x1EDu);
      chown_names("/var/mobile/Containers/Data/", "mobile", "mobile");
    }

    if (is_reset_library) {
      /*system("rm -rf /var/mobile/Library2");
       rename("/var/mobile/Library", "/var/mobile/Library2");
       mkdir("/var/mobile/Library/", 0x1EDu);
       chown_names("/var/mobile/Library/", "mobile", "mobile");
       system("/usr/libexec/cydia/setnsfpn /var/mobile/Library/");*/
      system("rm -rf /var/mobile/Library/Accounts");
      mkdir("/var/mobile/Library/Accounts", 0x1C0u);
      chown_names("/var/mobile/Library/Accounts", "mobile", "mobile");
      
      system("rm -rf /var/mobile/Library/AddressBook");
      mkdir("/var/mobile/Library/AddressBook", 0x1C0u);
      chown_names("/var/mobile/Library/AddressBook", "mobile", "mobile");
      
      system("rm -rf /var/mobile/Library/Caches");
      mkdir("/var/mobile/Library/Caches", 0x1FFu);
      chown_names("/var/mobile/Library/Caches", "mobile", "mobile");
      system("/usr/libexec/cydia/setnsfpn /var/mobile/Library/Caches");
      
      system("rm -rf /var/mobile/Library/Cookies");
      mkdir("/var/mobile/Library/Cookies", 0x1C0u);
      chown_names("/var/mobile/Library/Cookies", "mobile", "mobile");
      
      system("rm -rf /var/mobile/Library/Inboxes");
      mkdir("/var/mobile/Library/Inboxes", 0x1EDu);
      chown_names("/var/mobile/Library/Inboxes", "mobile", "mobile");
      
      system("rm -rf /var/mobile/Library/Keyboard");
      mkdir("/var/mobile/Library/Keyboard", 0x1C0u);
      chown_names("/var/mobile/Library/Keyboard", "mobile", "mobile");
      
      system("rm -rf /private/var/mobile/Library/FrontBoard");
      mkdir("/private/var/mobile/Library/FrontBoard", 0x1C0u);
      chown_names("/private/var/mobile/Library/FrontBoard", "mobile", "mobile");
      
      system("rm -rf /private/var/mobile/Library/AggregateDictionary");
      mkdir("/private/var/mobile/Library/AggregateDictionary", 0x1C0u);
      chown_names("/private/var/mobile/Library/AggregateDictionary", "mobile", "mobile");
      
      system("rm -rf /private/var/mobile/Library/BulletinBoard");
      mkdir("/private/var/mobile/Library/BulletinBoard", 0x1C0u);
      chown_names("/private/var/mobile/Library/BulletinBoard", "mobile", "mobile");
      
      system("rm -rf /private/var/mobile/Library/Mail");
      mkdir("/private/var/mobile/Library/Mail", 0x1C0u);
      chown_names("/private/var/mobile/Library/Mail", "mobile", "mobile");
      
      NSMutableDictionary* mutableDict = [NSMutableDictionary dictionary];
      [mutableDict setValue:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
      NSString* sss = @"/private/var/mobile/Library/Preferences/com.apple.springboard.plist";
      [mutableDict writeToFile:sss atomically:YES];
      
      system("rm -rf /var/mobile/Library/Safari");
      mkdir("/var/mobile/Library/Safari", 0x1C0u);
      chown_names("/var/mobile/Library/Safari", "mobile", "mobile");
      
      system("rm -rf /private/var/mobile/Library/locationd");
      mkdir("/private/var/mobile/Library/locationd", 0x1C0u);
      chown_names("/private/var/mobile/Library/locationd", "root", "mobile");
      
      system("rm -rf /private/var/mobile/Library/SyncedPreferences/");
      mkdir("/private/var/mobile/Library/SyncedPreferences/", 0x1C0u);
      chown_names("/private/var/mobile/Library/SyncedPreferences/", "mobile", "mobile");
      
      system("rm -rf /private/var/mobile/Library/SpringBoard");
      mkdir("/private/var/mobile/Library/SpringBoard", 0x1C0u);
      chown_names("/private/var/mobile/Library/SpringBoard", "mobile", "mobile");
      
      system("rm -rf /var/mobile/Library/WebClips");
      mkdir("/var/mobile/Library/WebClips", 0x1C0u);
      chown_names("/var/mobile/Library/WebClips", "mobile", "mobile");
      
      if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"9.3")) {
        system("rm -rf /private/var/mobile/Library/UserConfigurationProfiles/");
        mkdir("/private/var/mobile/Library/UserConfigurationProfiles", 0x1C0u);
        chown_names("/private/var/mobile/Library/UserConfigurationProfiles", "root", "mobile");
        system("chmod 777 /private/var/mobile/Library/UserConfigurationProfiles/");
        
        system("rm -rf /private/var/mobile/Library/DataAccess");
        mkdir("/private/var/mobile/Library/DataAccess", 0x1C0u);
        chown_names("/private/var/mobile/Library/DataAccess", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/Teiron/");
        mkdir("/private/var/mobile/Library/Teiron", 0x1C0u);
        chown_names("/private/var/mobile/Library/Teiron", "root", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/Profile/");
        mkdir("/private/var/mobile/Library/Profile", 0x1C0u);
        chown_names("/private/var/mobile/Library/Profile", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/WatchConnectivity/");
        mkdir("/private/var/mobile/Library/WatchConnectivity", 0x1C0u);
        chown_names("/private/var/mobile/Library/WatchConnectivity", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/ExternalAccessory/");
        mkdir("/private/var/mobile/Library/ExternalAccessory", 0x1C0u);
        chown_names("/private/var/mobile/Library/ExternalAccessory", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/SoftwareUpdate/");
        mkdir("/private/var/mobile/Library/SoftwareUpdate", 0x1C0u);
        chown_names("/private/var/mobile/Library/SoftwareUpdate", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/BackBoard/");
        mkdir("/private/var/mobile/Library/BackBoard", 0x1C0u);
        chown_names("/private/var/mobile/Library/BackBoard", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/LASD/");
        mkdir("/private/var/mobile/Library/LASD", 0x1C0u);
        chown_names("/private/var/mobile/Library/LASD", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/com.apple.iTunesStore/");
        mkdir("/private/var/mobile/Library/com.apple.iTunesStore", 0x1C0u);
        chown_names("/private/var/mobile/Library/com.apple.iTunesStore", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/Operator Bundle.bundle/");
        mkdir("/private/var/mobile/Library/Operator Bundle.bundle", 0x1C0u);
        chown_names("/private/var/mobile/Library/Operator Bundle.bundle", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/CrashReporter/");
        mkdir("/private/var/mobile/Library/CrashReporter", 0x1C0u);
        chown_names("/private/var/mobile/Library/CrashReporter", "mobile", "mobile");
        
        system("/bin/rm -rf /private/var/mobile/Library/Application Support/");
        mkdir("/private/var/mobile/Library/Application Support", 0x1C0u);
        chown_names("/private/var/mobile/Library/Application Support", "mobile", "mobile");
        
        system("rm -rf /private/var/mobile/Library/Cydia/");
      }
      else{
        system("rm -rf /var/mobile/Library/Preferences");
        mkdir("/var/mobile/Library/Preferences", 0x1EDu);
        chown_names("/var/mobile/Library/Preferences", "mobile", "mobile");
        system("/usr/libexec/cydia/setnsfpn /var/mobile/Library/Preferences");
        
        system("rm -rf /private/var/mobile/Library/ConfigurationProfiles/");
        mkdir("/private/var/mobile/Library/ConfigurationProfiles", 0x1C0u);
        chown_names("/private/var/mobile/Library/ConfigurationProfiles", "root", "mobile");
        system("chmod 777 /private/var/mobile/Library/ConfigurationProfiles/");
        
        system("rm -rf /private/var/mobile/Library/Application Support/");
      }
      
      system("rm -rf /private/var/mobile/Library/MusicLibrary/");
      system("rm -rf /private/var/mobile/Library/Calendar/");
      system("rm -rf /private/var/mobile/Library/CallHistoryDB/");
      system("rm -rf /private/var/mobile/Library/CallHistoryTransactions/");
      system("rm -rf /private/var/mobile/Library/BatteryLife/");
      system("rm -rf /private/var/mobile/Library/adi/");
      system("rm -rf /private/var/mobile/Library/Carrier Bundle.bundle/");
      system("rm -rf /private/var/mobile/Library/Carrier Bundles/");
      system("rm -rf /private/var/mobile/Library/CarrierDefault.bundle/");
      system("rm -rf /private/var/mobile/Library/MobileBluetooth/");
      system("rm -rf /private/var/mobile/Library/FairPlay/");
      system("rm -rf /private/var/mobile/Library/MobileContainerManager/");
      system("rm -rf /private/var/mobile/Library/SMS/");
      system("rm -rf /private/var/mobile/Library/FileProvider/");
      system("rm -rf /private/var/mobile/Library/GeoServices/");
      system("rm -rf /private/var/mobile/Library/OTALogging/");
      system("rm -rf /private/var/mobile/Library/ApplePushService/");
      system("rm -rf /private/var/mobile/Library/Spotlight/");
      system("rm -rf /private/var/mobile/Library/Suggestions/");
      system("rm -rf /private/var/mobile/Library/MobileInstallation/");
      system("rm -rf /private/var/mobile/Library/Notes/");
      system("rm -rf /private/var/mobile/Library/MediaStream/");
      system("rm -rf /private/var/mobile/Library/Social/");
      system("rm -rf /private/var/mobile/Library/CoreFollowUp/");
      system("rm -rf /private/var/mobile/Library/com.apple.Music/");
      system("rm -rf /private/var/mobile/Library/fps/");
      system("rm -rf /private/var/mobile/Library/OnDemandResources/");
      system("rm -rf /private/var/mobile/Library/Voicemail/");
      system("rm -rf /private/var/mobile/Library/homed/");
      system("rm -rf /private/var/mobile/Library/ReplayKit/");
      system("rm -rf /private/var/mobile/Library/WelcomeMat/");
      system("rm -rf /private/var/mobile/Library/Assets/");
      system("rm -rf /private/var/mobile/Library/TCC/");
      system("rm -rf /private/var/mobile/Library/VoiceServices/");
      system("rm -rf /private/var/mobile/Library/Health/");
      system("rm -rf /private/var/mobile/Library/mad/");
      system("rm -rf /private/var/mobile/Library/CoreDuet/");
      system("rm -rf /private/var/mobile/Library/Passes/");
      system("rm -rf /private/var/mobile/Library/IdentityServices/");
      system("rm -rf /private/var/mobile/Library/Logs/");
      system("rm -rf /private/var/mobile/Library/com.apple.nsurlsessiond/");
      system("rm -rf /private/var/mobile/Library/cyaidami/");
      system("rm -rf /private/var/mobile/Library/DuetExpertCenter/");
    }
    if (is_remove_itunesstored) {
      system("rm -rf /private/var/mobile/Library/com.apple.itunesstored/");
      mkdir("/private/var/mobile/Library/com.apple.itunesstored", 0x1C0u);
      chown_names("/private/var/mobile/Library/com.apple.itunesstored", "mobile", "mobile");
      system("chmod 777 /private/var/mobile/Library/com.apple.itunesstored/");
    }
    if (is_remove_tmp) {
      system("rm -rf /private/var/tmp/");
      mkdir("/private/var/tmp", 0x1C0u);
      chown_names("/private/var/tmp", "root", "mobile");
      system("chmod 1777 /private/var/tmp/");
    }
    if (is_kill_appstore) {
      KillAppStore();
    }
    if (is_kill_spring_board) {
      system("killall backboardd");
      system("killall SpringBoard");
    }
    if (is_lock_screen) {
      while (true) {
        [[UIApplication sharedApplication] setIdleTimerDisabled: YES];
        [UIApplication sharedApplication].idleTimerDisabled = YES;
        [NSThread sleepForTimeInterval:2.0f];
      }
      return 0;
    }
    return 0;
  }
}
