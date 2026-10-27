// RelyVPN 自动抹数据  v51（防闪退版）

//

// 只做一件事：额度归零 → 抹掉用户数据 → 自拉起 App → 自动连回 VPN。

// 等价于你自己用 Apps Manager 点「抹掉用户数据」，区别是不用动手。

//

// v50 装上就闪退，原因是它一启动就判定「额度归零」（你现在账号本来就是归零态），

// 于是 1.5 秒后抹数据 + 自拉起 + exit(0) —— 看起来就是打开即闪退，

// 而且抹完起来又判定归零，循环闪。v51 针对这一点加了三道保险（见下）。

//

// ─── v51 相对 v50 改了什么 ────────────────────────────────────────────

//   1. 启动宽限 25 秒：刚起来的进程在这段时间内只记日志、不动手；

//   2. 快速循环熔断：15 分钟内连续抹 4 次还是归零 → 自动停用（不再闪），

//      日志里写明原因，手动扳机仍然可用；

//   3. 自拉起失败就不 exit —— 绝不让你「App 消失打不开」；

//   4. 砍掉面板（UIWindow）、protobuf 全树解码、兜底定时器、keychain 清理；

//   5. 扫描改成「先 memmem 过滤 + 200ms 节流 + 复用缓冲」，不再对每个包

//      逐 region 调 vm_region_64（v50 那个是真吃 CPU）。

//

// ─── 判据（任一命中即动手，都只在报文里找，不猜）──────────────────────

//   ① 报文里出现 signup_gift_placeholder（服务端「福利模式占位号」，

//      只在额度归零时下发，v37 真机确认）

//   ② 报文文本里 remaining <= 0，或 used >= quota * 0.97

//   ③ 手动扳机：Documents 里放一个空文件 rb_wipe（绕过所有保险，强制抹）

//

// ─── 抹什么 ──────────────────────────────────────────────────────────

//   Documents / Library 各子目录 / tmp / SystemData / App Group / NSUserDefaults

//   白名单：Library/rb_state.plist（计数与时间戳）、Documents/rb-shim.log

//   keychain 默认不动 —— 隧道配置里的密码引用指向 keychain，清了反而连不上。



#import <Foundation/Foundation.h>

#import <UIKit/UIKit.h>

#import <Security/Security.h>

#import <AVFoundation/AVFoundation.h>

#import <os/log.h>

#import <mach/mach.h>

#import <objc/runtime.h>

#import <objc/message.h>

#import <sys/socket.h>

#import <netinet/in.h>

#import <arpa/inet.h>

#import <netdb.h>

#import <unistd.h>

#import <sys/time.h>

#include <mach-o/dyld.h>

#include <dlfcn.h>          // dlopen / dlsym / dladdr

#include <malloc/malloc.h>  // malloc_size（free_buffer 靠它拿响应长度）

#include <ifaddrs.h>        // getifaddrs —— 直接读 utun 接口走了多少流量

#include <net/if.h>

#include <string.h>

#include <stdlib.h>

#include <ctype.h>

#include <unistd.h>

#include <fcntl.h>



#pragma mark - 配置区（要改就改这里，没有环境变量）



#define RB_ENABLED          1        // 总开关；0 = 只转发，什么也不做

#define RB_GRACE_SEC        15.0     // 启动宽限：进程起来这么多秒内不动手

#define RB_COOL_SEC         60.0     // 两次自动抹除的最小间隔

#define RB_DELAY_SEC        1.5      // 判定命中后延迟多久动手

#define RB_MAX_RAPID        4        // 15 分钟内连续抹这么多次仍归零 → 自动停用

#define RB_RAPID_WIN        900.0    // 「连续」的窗口（秒）

#define RB_MAX_BOOT_LOOP    6        // 12 秒内重启这么多次 → 判定为闪退循环，停用

#define RB_WIPE_THRESHOLD   0.97     // used >= quota * 这个值 就算归零



// v54「快速通道」：刚抹完重开的那个新进程，如果一上来又是归零，说明这次抹得

// 还不够（服务端换了个身份但额度还是旧的），那就别让用户等 60 秒冷却、也别等他

// 手动再进一次 App —— 直接把宽限和冷却压到几秒，让它自己接着抹第二次。

// 实测就是要连抹两次才刷新，之前这两次之间是靠你手动进 App + 等冷却才走完的。

#define RB_GRACE_FAST_SEC   4.0      // 快速通道下的启动宽限

#define RB_COOL_FAST_SEC    8.0      // 快速通道下的冷却

#define RB_FAST_LANE_SEC    120.0    // 重开后多久算「稳定了」，退出快速通道



// 流量判据（v52 新增，最靠谱的一条）：直接读 utun 接口走了多少字节，

// 累计到额度就抹。额度就是流量，这条不依赖任何报文格式。

#define RB_FLOW_ENABLED     1                      // 1=启用流量判据

#define RB_QUOTA_BYTES      (300LL * 1024 * 1024)  // 你的额度（300MB）

#define RB_FLOW_FACTOR      0.95                   // 用到额度的这个比例就抹

#define RB_FLOW_TICK_SEC    5.0                    // 采样间隔（秒）

#define RB_FLOW_MAX_STEP    (1024LL * 1024 * 1024)   // 一个采样周期最多可能跑这么多；

                                                   // v65：原来是 64MB，实测速率 11812 KB/s 时
                                                   // 一个 5 秒周期就跑 69MB，被当成「接口变化」
                                                   // 掉弃 → 累计不涨、流量时间戳不更新 →
                                                   // 看门狗反过来把**正在跑的隧道**判成假连接
                                                   // 停掉（v64 日志 98/120 行）。改成 1GB：
                                                   // 真接口变化是「读数倒退」，走下面那个分支。

// v61：限速判据。300MB 用完的硬特征是掉到福利速度（160Kbps ≈ 20KB/s），

// 而 App 上那个「剩 31.9 GB」是服务端给的展示值，跟真实流量对不上 ——

// 只靠字节数判据会漏（utun 一重建累计就被清零，永远攒不到 285MB），

// 速率才是抓「已经被限速」的那条。

#define RB_THROTTLE_DETECT   1        // 1=检测到被限速就抹

#define RB_THROTTLE_KBPS     40.0     // 速率持续低于这个值（KB/s）才算被限速

#define RB_THROTTLE_HOLD_SEC 90.0     // 要连续这么久（秒）才动手

#define RB_THROTTLE_MIN_MB   30.0     // 并且累计已跑掉这么多 MB（说明确实在用额度）

#define RB_THROTTLE_MIN_DELTA 8192    // 每个采样周期至少这么多字节在走。

                                      // 隧道 keepalive 一个周期才 1~2KB，达不到，

                                      // 所以「连着但空闲」不会误判；被限速时 5 秒有 ~100KB

// v62：节点快照。抹数据把 App 记的「当前节点」一起抹了，新进程自动重连时

// providerConfiguration 里的节点是空的 → 卡「正在连接」转圈，用户必须手动

// 进 App 重选一次。现在抹前把节点配置快照进 rb_state.plist（白名单文件，

// 抹除不删），重连前写回去 —— 节点选择和设备身份无关，恢复它不影响刷新额度。

#define RB_NODE_SNAP_KEY   @"nodeSnap"

#define RB_NODE_RECHECK    30.0       // 两次恢复校验的最小间隔（秒）

// v64：真正的「当前节点」不在 providerConfiguration（那里面只有 1 个键），
// 而是在 Flutter 的 NSUserDefaults 里 —— 抹数据时被 removePersistentDomain 一起清掉，
// 所以抹完 App 是「从没选过节点」的新状态，自动重连拉起隧道也连不上任何节点，
// 只能手动点。这里抹前把「节点类」键挑出来快照，抹完写回去。

#define RB_PREFS_SNAP_KEY  @"prefsSnap"

#define RB_PREFS_FILE      @"rb-prefs.txt"

// v65：**「当前节点」根本不在 NSUserDefaults，也不在 providerConfiguration
// （那里面只有 1 个键）。它在
//   Library/Application Support/RelyVPN/currentNodeWithReason.bin
// （315 字节明文：IP + 城市 + 节点名 + 国家 + 节点 UUID + 认证串 + 域名）。
// 抹数据时整个 Application Support 被 rb_clean_deep 扫掉 → 新进程不认识任何节点
// → 自动重连拉起空壳隧道 → 卡「正在连接」转圈 → 只能手动点节点。
// 这个文件里只有节点凭据、没有设备身份，保住它不影响额度刷新。

#define RB_NODEFILES_KEY   @"nodeFiles"

// ---- v67：抹除后用新节点 ----
// currentNodeWithReason.bin 里除了 IP/城市/名字，还带着一串服务端签发的「节点认证串」，
// 那串是绑账号/设备的。抹完数据换来新身份，却把旧认证串写回去连同一个节点 ——
// 服务端按旧账号记账，直接压成福利限速（v66 日志：抹后 82 秒只跑 0.7MB、10.8 KB/s，
// 正常是 8000+ KB/s）。所以抹完之后要「查一遍速率」，被限速就把旧节点丢掉，
// 让 App 用新身份重新申请节点。
#define RB_NODE_ROTATE_ON    0          // v72：关掉。rb-shim(12)(13)(14) 三份日志实证它
                                       // 每次都把刚连好的隧道拆掉，收益从未被证实。
                                       // 要试就改回 1（面板 b8 手动按钮不受这个开关影响）
#define RB_NODE_SELF_SEC     180.0      // 抹除后这么久内算「刚抹完」→ 不写回旧节点，让 App 自己选
#define RB_NODE_LIMIT_KBPS   500.0      // 抹后持续低于这个速率（KB/s）判为节点被限速
#define RB_NODE_OBS_SEC      20.0       // 观测窗口：连着这么久都低速才动手
#define RB_NODE_OBS_ARM_SEC  8.0        // 抹完前这些秒不算（隧道在握手、本来就没速度）
#define RB_NODE_OK_MB        3.0        // 抹后跑出这么多 MB 就说明没限速，观测结束
#define RB_NODE_WAIT_SEC     180.0      // 抹除后这么久内才做这个检测
#define RB_NODE_ROTATE_MAX   3          // 一次抹除周期最多丢几次节点
#define RB_NODE_WATCH_SEC    4.0        // 丢了之后每隔多久看一眼 App 有没有选出新节点
#define RB_NODE_WATCH_MAX    40         // 最多看这么多次（40 x 4 秒 = 160 秒）
#define RB_POST_WIPE_FALLBACK_SEC 25.0  // v73：抹后先等 App 自己重写节点文件；
                                       // 等这么久它还没动静，才退回正常自动重连



// 时间兜底：RB_FALLBACK_ON=1 时，距上次抹除超过 RB_WIPE_MAX_HOURS 小时就抹一次。

// （浮点常量不能进 #if，所以开关与数值分开写）

#define RB_FALLBACK_ON      0

#define RB_WIPE_MAX_HOURS   4.0      // 兜底间隔（小时），仅 RB_FALLBACK_ON=1 时生效

// v53：keychain 默认清。Apps Manager 抹数据是连 keychain 一起清的，

// 而 v52 只删了沙箱里 4 个文件、keychain 没动 → 设备身份还在 → 额度不刷新。

// 这里是逐项精确删除，只跳过 service == bundle id 的项（NE VPN 配置的

// passwordReference 指向它，清了 VPN 就连不上了）。

#define RB_WIPE_KEYCHAIN    1

#define RB_KEEP_VPN_KC      1        // 1=保留 VPN 配置引用的 keychain 项

#define RB_RELAUNCH         1        // 抹完自拉起 App

#define RB_AUTO_RECONNECT   1        // 新进程自动连回 VPN

#define RB_RECONNECT_TRIES  6        // 自动重连最多试这么多次（每次间隔 2.5 秒）

// v59：拉起之后的稳定期 / 卡死线。刚连上的隧道零流量是正常的，

// 不给稳定期就会「拉起→判假连接→停→再拉」无限循环（v58 的卡死现场）。

#define RB_START_SETTLE_SEC  30.0    // 拉起后这么多秒内不判假连接

#define RB_START_STUCK_SEC   45.0    // 一直停在「连接中」超过这么久才算卡死（v66：45 秒就 bounce）

#define RB_REFRESH_MB        5       // 抹除后跑掉这么多 MB 就认为额度已刷新（补刀复核用）

// v60：假连接处理的封顶与节奏。

#define RB_STOP_SETTLE_SEC   2.5     // 停完隧道等这么久再拉（stop 是异步的，立刻 start 会被拒）

#define RB_FAKE_FIX_MAX      3       // 连续判定「假连接」最多处理这么多次

#define RB_FAKE_FIX_COOL     300.0   // 到上限后歇这么久（秒）—— 不再无限循环

#define RB_STOP_BEFORE_WIPE 1        // 抹数据前先把隧道停掉（防止扩展把旧身份写回来）

#define RB_TRIGGER_FILE     1        // 手动扳机 Documents/rb_wipe

#define RB_PANEL            1        // App 右上角小面板（含「立即抹数据」按钮）

#define RB_LOG_FILE         1        // 写 Documents/rb-shim.log

#define RB_STATUS_LOG_SEC   60.0     // 每这么久打一条状态行（排障用）



// ─── v56：自动连接 / 保活 / 速率监测 ────────────────────────────────────

// 面板上那个「自动连接」开关：开 = 常连（断了就拉起来，抹完自动接回去），

// 关 = 立刻断开并且再也不自动连。不用再去点 App 里那个连接按钮。

#define RB_AUTO_CONNECT      1        // 开关的默认值（改过之后会记住）

#define RB_KEEPALIVE         1        // 开关打开时盯场：状态不对就重新拉起

#define RB_KEEPALIVE_SEC     12.0     // 盯场间隔（秒）
#define RB_POST_WIPE_QUIET   25.0     // v74：抹后多少秒内不抢先拉隧道

#define RB_RECONNECT_GAP     20.0     // 两次真实 start 之间的最小间隔，防止打太密

#define RB_ONDEMAND_CONNECT  1        // 开「自动连接」时给配置装上 on-demand 常连规则

                                      // （这是 iOS 系统级常连，App 被挂起也照样重连）

#define RB_ASSERTION_KEEP    1        // RunningBoard / BoardServices 断言保活

#define RB_BGTASK_KEEP       1        // 后台任务续期（多撑一分钟是一分钟）

#define RB_AUDIO_KEEP        1        // 兜底：静音音频保活（上面两条都失败时才开）

#define RB_RATEMON           1        // 速率监测（从 utun 真实字节数算，不猜）

#define RB_NE_PROBE          1        // start 全失败时把 NE 类可用方法打进日志

#define RB_SLOW_KBPS         20.0     // 已连接但低于这个速率 → 面板标「慢」

#define RB_SLOW_RECONNECT    0        // 1=持续慢就重连换路（默认关：不下载时速率

                                      // 本来就是 0，会误判，需要你确认后再开）



#define RB_STATE_FILE @"rb_state.plist"

#define RB_LOG_NAME_C "rb-shim.log"

#define RB_LOG_NAME   @RB_LOG_NAME_C

#define RB_TRIGGER_C  "rb_wipe"

#define RB_TRIGGER    @RB_TRIGGER_C

#define RB_GROUP_ID   @"group.com.quietleafapp.vpn"

#define RB_MIN_QUOTA  (100LL * 1024 * 1024)   // 小于 100MB 的 quota 不当额度看
#define RB_MAX_QUOTA  (4LL * 1024 * 1024 * 1024)  // v63：大于 4GB 的「额度」是巧合
#define RB_MIN_PB_LEN 64                      // v63：短包不跑 pb 判据（len=40 曾误命中）

#define RB_PB_MAX_LEN 8192                    // 超过这么大的包不跑 pb 判据（防大包误判）



#pragma mark - 日志



#define RB_LOG_MAXBYTES (1LL << 20)




// v74：把所有诊断产物合并成一个 txt，用户只转发这一个文件。
// 内部 60 秒节流，不会拖慢日志路径。绝不调 rb_log（避免递归）。
static double gReportTs = 0.0;

static void rb_report_merge(void) {

    double now = [[NSDate date] timeIntervalSince1970];

    if (now - gReportTs < 60.0) return;

    gReportTs = now;

    @autoreleasepool {

        NSString *h = NSHomeDirectory();

        if (!h) return;

        NSString *doc = [h stringByAppendingPathComponent:@"Documents"];

        NSArray *names = [NSArray arrayWithObjects:@"rb-shim.log", @"rb-nodes.txt",

                          @"rb-kc.txt", @"rb-node-hex.txt", @"rb-auth-sample.txt",

                          @"rb-necfg.txt", nil];

        NSMutableString *out = [NSMutableString stringWithCapacity:(1u << 19)];

        [out appendFormat:@"# RelyVPN shim 合并报告（只需转发这一个文件）\n# %@\n",

            [NSDate date]];

        for (NSString *nm in names) {

            NSString *p = [doc stringByAppendingPathComponent:nm];

            NSString *s = [NSString stringWithContentsOfFile:p

                                                    encoding:NSUTF8StringEncoding

                                                       error:NULL];

            if (!s) continue;

            [out appendFormat:@"\n\n===== %@（%lu 字符）=====\n", nm, (unsigned long)[s length]];

            if ([s length] > 400000) s = [s substringFromIndex:[s length] - 400000];

            [out appendString:s];

        }

        [out writeToFile:[doc stringByAppendingPathComponent:@"rb-report.txt"]

              atomically:YES

                encoding:NSUTF8StringEncoding

                   error:NULL];

    }

}

static void rb_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));



static void rb_log(const char *fmt, ...) {

    char buf[1024];

    va_list ap;

    va_start(ap, fmt);

    vsnprintf(buf, sizeof(buf), fmt, ap);

    va_end(ap);



    fprintf(stderr, "[rb-shim] %s\n", buf);

    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "[rb-shim] %{public}s", buf);



#if RB_LOG_FILE

    static int fd = -2;

    static char path[1024];

    static long long written = 0;

    if (fd == -2) {

        fd = -1;

        NSString *h = NSHomeDirectory();

        if (h) {

            snprintf(path, sizeof(path), "%s/Documents/%s",

                     [h fileSystemRepresentation], RB_LOG_NAME_C);

            fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);

            if (fd >= 0) {

                off_t e = lseek(fd, 0, SEEK_END);

                if (e > 0) written = (long long)e;

            }

        }

    }

    if (fd >= 0) {

        char line[1152];

        int n = snprintf(line, sizeof(line), "[rb-shim] %s\n", buf);

        if (n > 0) {

            (void)!write(fd, line, (size_t)n);

            written += n;

        }

        if (written > RB_LOG_MAXBYTES && path[0]) {

            close(fd);

            fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

            written = 0;

        }

    }

#endif

    // v74：顺手把全部诊断合并成一份，供用户转发

    rb_report_merge();

}



static double rb_now(void) {

    return [[NSDate date] timeIntervalSince1970];

}



// 只读地把 src 处 len 字节拷出来。地址不可读时内核直接返回失败，不会崩。

static size_t rb_read(const void *src, void *dst, size_t len) {

    if (!src || !dst || len == 0) return 0;

    vm_size_t got = 0;

    kern_return_t kr = vm_read_overwrite(mach_task_self(),

                                         (vm_address_t)src, (vm_size_t)len,

                                         (vm_address_t)dst, &got);

    if (kr != KERN_SUCCESS) return 0;

    return (size_t)got;

}



static int rb_is_exec(uint64_t a) {

    if (a < 0x1000) return 0;

    vm_address_t addr = (vm_address_t)a;

    vm_size_t size = 0;

    vm_region_basic_info_data_64_t bi;

    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;

    mach_port_t obj = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size,

                                    VM_REGION_BASIC_INFO_64,

                                    (vm_region_info_t)&bi, &cnt, &obj);

    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);

    if (kr != KERN_SUCCESS) return 0;

    return (bi.protection & VM_PROT_EXECUTE) ? 1 : 0;

}



#pragma mark - 状态（白名单文件，抹除时不删）



static NSString *rb_state_path(void) {

    return [NSHomeDirectory() stringByAppendingPathComponent:

            [@"Library/" stringByAppendingString:RB_STATE_FILE]];

}



static NSMutableDictionary *rb_state(void) {

    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:rb_state_path()];

    return d ? [NSMutableDictionary dictionaryWithDictionary:d]

             : [NSMutableDictionary dictionary];

}



static void rb_state_save(NSDictionary *d) {

    [[NSFileManager defaultManager]

        createDirectoryAtPath:[rb_state_path() stringByDeletingLastPathComponent]

      withIntermediateDirectories:YES attributes:nil error:NULL];

    [d writeToFile:rb_state_path() atomically:YES];

}



#pragma mark - 归零判定



static int rb_find(const uint8_t *h, size_t hn, const char *n, size_t nn) {

    if (!h || !n || nn == 0 || hn < nn) return 0;

    for (size_t i = 0; i + nn <= hn; i++)

        if (h[i] == (uint8_t)n[0] && memcmp(h + i, n, nn) == 0) return 1;

    return 0;

}



// 从 s 的 i 位置往后抓第一个整数

static NSString *rb_num_after(NSString *s, NSUInteger i) {

    NSUInteger n = [s length], k = i;

    while (k < n && ([s characterAtIndex:k] == ' ' || [s characterAtIndex:k] == ':' ||

                     [s characterAtIndex:k] == '"' || [s characterAtIndex:k] == ',')) k++;

    BOOL neg = NO;

    if (k < n && [s characterAtIndex:k] == '-') { neg = YES; k++; }

    NSUInteger st = k;

    while (k < n && [s characterAtIndex:k] >= '0' && [s characterAtIndex:k] <= '9') k++;

    if (k == st) return nil;

    NSString *t = [s substringWithRange:NSMakeRange(st, k - st)];

    return neg ? [@"-" stringByAppendingString:t] : t;

}



// 只有先命中关键词才建 NSString —— 正常报文一次 memmem 就退出，几乎不耗 CPU

static BOOL rb_text_dead(const uint8_t *b, size_t n) {

    NSString *s = [[[NSString alloc] initWithBytes:b length:n

                                          encoding:NSUTF8StringEncoding] autorelease];

    if (!s || [s length] < 8) return NO;



    NSRange rr = [s rangeOfString:@"remaining"];

    if (rr.location != NSNotFound) {

        NSString *v = rb_num_after(s, rr.location + rr.length);

        if (v && [v doubleValue] <= 0) return YES;

    }



    double quota = 0, used = 0;

    NSRange rq = [s rangeOfString:@"quota"];

    if (rq.location != NSNotFound) {

        NSString *v = rb_num_after(s, rq.location + rq.length);

        if (v) quota = [v doubleValue];

    }

    NSArray *uks = [NSArray arrayWithObjects:@"used_data_bytes", @"usedBytes",

                             @"\"used\"", @"\"used_bytes\"", nil];

    for (NSString *uk in uks) {

        NSRange ru = [s rangeOfString:uk];

        if (ru.location == NSNotFound) continue;

        NSString *v = rb_num_after(s, ru.location + ru.length);

        if (v && [v doubleValue] > used) used = [v doubleValue];

    }

    return (quota >= (double)RB_MIN_QUOTA && used >= quota * RB_WIPE_THRESHOLD);

}



// protobuf：同一个 message 里 f2=quota、f3=used，且 used 顶到 quota。

//

// v51 把它砍了 → 你反馈「额度用完没自动抹」。原因就在这：服务端的额度报文是

// protobuf 二进制，字段名不在线上（只有字段号），"quota"/"remaining" 这类

// ASCII 关键词根本搜不到，只剩的字符串判据又不一定每次都下发。

//

// 但 v50 原样拿它当判据会误判：时间戳 1.7e9 也满足 f2>=100MB，

// 两个相邻时间戳（1.7e9 / 1.73e9）比值≈1，直接命中 —— 那才是 v50 闪退的真凶。

// 所以这里加了「整 MB」特征：额度必然是 1024*1024 的整数倍（300MB），

// 时间戳几乎不可能整除 1MB。

static BOOL rb_pb_dead(const uint8_t *b, size_t n, int depth, size_t *budget);



// v65：服务端每次都会把额度报给我们（len=253 那种包里就是 total/used）。
// 记下来给面板显示用 —— 自己数 utun 字节是漏的：隧道每次重建 utun 从 0 起算，
// 重建前最后一段（最多 5 秒 × 11MB/s）全丢了，4 分钟就能少算 27MB。
// 截图里 App 已显示「体验套餐·已用尽」、面板还剩 27.2，就是漏算漏出来的。

static volatile uint64_t gSrvTotal = 0;   // 服务端报的总额度（字节）

static volatile uint64_t gSrvUsed  = 0;   // 服务端报的已用（字节）

static volatile double   gSrvTs    = 0;   // 上次收到额度报文的时刻

static volatile uint64_t gSrvAccAt = 0;   // 收到服务端读数那一刻的本地累计（v66）

static volatile uint64_t gFlowAcc = 0;   // 当前累计 VPN 流量（面板显示用；v66 上移供 rb_used_est 用）

static uint64_t rb_pb_prev_used = 0;      // 去重打日志用

// v66：面板显示的「已用」= 服务端基准 + 服务端读数之后本地又跑的部分。
// 只显示服务端会滞后（一分钟一报，App 那边早跑到 288 了面板还 240）；
// 只显示本地 utun 会在重建时漏算。两者相加：基准是权威账单，增量是实时的。
static uint64_t rb_used_est(void) {

    uint64_t base = gSrvUsed;

    if (base == 0) return gFlowAcc;

    uint64_t acc = gFlowAcc;

    uint64_t since = (acc > gSrvAccAt) ? (acc - gSrvAccAt) : 0;

    return base + since;

}



static BOOL rb_pb_dead(const uint8_t *b, size_t n, int depth, size_t *budget) {

    if (depth > 6 || n < 2) return NO;

    size_t i = 0;

    uint64_t f2 = 0, f3 = 0;

    int hasF2 = 0, hasF3 = 0;

    while (i < n) {

        if (*budget == 0) return NO;

        (*budget)--;

        uint64_t key = 0, sh = 0;

        size_t st = i;

        while (i < n) {

            uint8_t c = b[i++];

            key |= (uint64_t)(c & 0x7f) << sh;

            sh += 7;

            if (!(c & 0x80)) break;

            if (sh > 63) return NO;

        }

        if (i == st) return NO;

        uint64_t fn = key >> 3, wt = key & 7;

        if (fn == 0) return NO;

        if (wt == 0) {

            uint64_t v = 0; sh = 0;

            while (i < n) {

                uint8_t c = b[i++];

                v |= (uint64_t)(c & 0x7f) << sh;

                sh += 7;

                if (!(c & 0x80)) break;

                if (sh > 63) return NO;

            }

            if (fn == 2) { f2 = v; hasF2 = 1; }

            if (fn == 3) { f3 = v; hasF3 = 1; }

        } else if (wt == 2) {

            uint64_t ln = 0; sh = 0;

            while (i < n) {

                uint8_t c = b[i++];

                ln |= (uint64_t)(c & 0x7f) << sh;

                sh += 7;

                if (!(c & 0x80)) break;

                if (sh > 63) return NO;

            }

            if (ln > (uint64_t)(n - i)) return NO;

            if (rb_pb_dead(b + i, (size_t)ln, depth + 1, budget)) return YES;

            i += (size_t)ln;

        } else if (wt == 5) {

            i += 4;

        } else if (wt == 1) {

            i += 8;

        } else {

            return NO;      // wt 3/4（废弃组）或非法，整段放弃

        }

    }

    if (hasF2 && hasF3 &&

        f2 >= (uint64_t)RB_MIN_QUOTA &&

        (f2 % (1024 * 1024)) == 0 &&                       // 额度是整 MB，时间戳不是

        f2 <= (uint64_t)RB_MAX_QUOTA &&

        f3 <= f2 + f2 / 20) {                              // used 不会远超 quota

        // v65：只要像额度就记 —— 面板剩余量用它，不再自己数 utun 字节
        gSrvTotal = f2;

        gSrvUsed  = f3;

        gSrvTs    = rb_now();

        gSrvAccAt = gFlowAcc;

        if (f3 > rb_pb_prev_used + (1ULL << 20) ||
            f3 + (1ULL << 20) < rb_pb_prev_used ||
            rb_pb_prev_used == 0) {
            rb_pb_prev_used = f3;
            rb_log("服务端额度：共 %.1f MB，已用 %.1f MB，剩 %.1f MB",
                   (double)f2 / 1048576.0, (double)f3 / 1048576.0,
                   (double)(f2 - f3) / 1048576.0);
        }

        if (f3 >= (uint64_t)((double)f2 * RB_WIPE_THRESHOLD)) return YES;

    }

    return NO;

}



// v66：v30 时代读用量的老路 —— f1=35 心跳载荷（首字节 08 23）里，
// "DATA_" 锚点后面就是 f2=quota、f3=used。这种包服务端每次心跳都回，
// 更新非常勤（v29 实测 37.8->132->240->300 秒级跟进）。v65 只靠 len=253
// 那种包更新，一分钟才一两次，面板显示自然滞后几十 MB。
static void rb_scan_used35(const uint8_t *b, size_t n) {

    if (!b || n < 60 || b[0] != 0x08 || b[1] != 0x23) return;

    if (n > 8192) return;

    for (size_t i = 4; i + 24 <= n; i++) {

        if (memcmp(b + i, "DATA_", 5)) continue;

        if (b[i - 2] != 0x0a) continue;                  // 锚点前应是 f1 的 tag+len

        size_t L2 = b[i - 1];

        size_t p = i + L2;                               // token 结束

        if (p >= n || b[p] != 0x10) return;              // f2 = quota

        uint64_t quota = 0, used = 0;

        size_t sh = 0;

        p++;

        while (p < n && sh <= 56) { uint8_t c = b[p++];

            quota |= (uint64_t)(c & 0x7f) << sh; sh += 7;

            if (!(c & 0x80)) break; }

        if (quota < (uint64_t)RB_MIN_QUOTA || quota > (uint64_t)RB_MAX_QUOTA)

            return;

        if (p >= n || b[p] != 0x18) {

            used = 0;                                    // proto3 零值不落地 = 没用

        } else {

            p++; sh = 0;

            while (p < n && sh <= 56) { uint8_t c = b[p++];

                used |= (uint64_t)(c & 0x7f) << sh; sh += 7;

                if (!(c & 0x80)) break; }

            if (sh > 63) return;

        }

        if (used > quota + quota / 20) return;           // used 不会远超 quota

        gSrvTotal = quota;

        gSrvUsed  = used;

        gSrvTs    = rb_now();

        gSrvAccAt = gFlowAcc;

        static uint64_t prev35 = 0;

        if (used != prev35 && (used > prev35 + (1ULL<<20) ||
                               used + (1ULL<<20) < prev35)) {

            prev35 = used;

            rb_log("服务端额度（心跳）：共 %.1f MB，已用 %.1f MB，剩 %.1f MB",

                   (double)quota / 1048576.0, (double)used / 1048576.0,

                   (double)(quota - used) / 1048576.0);

        }

        return;

    }

}



static void rb_probe_auth(const uint8_t *b, size_t n) {

    if (!b || n < 48 || n > 8192) return;

    static int  done   = 0;

    static double lastT = 0;

    if (done >= 3) return;

    int upper = 0, lower = 0;

    for (size_t i = 0; i + 36 <= n; i++) {

        int up = 1, lo = 1, letters = 0;

        for (size_t k = 0; k < 36; k++) {

            char c = (char)b[i + k];

            if (k == 8 || k == 13 || k == 18 || k == 23) {

                if (c != '-') { up = lo = 0; break; }

                continue;

            }

            if (c >= 'A' && c <= 'F') { up = 0; letters++; continue; }

            if (c >= 'a' && c <= 'f') { lo = 0; letters++; continue; }

            if (c >= '0' && c <= '9') continue;

            up = lo = 0;

            break;

        }

        if (up && letters) upper++;

        if (lo && letters) lower++;

    }

    if (!upper || !lower) return;

    double now = rb_now();

    if (lastT > 0 && now - lastT < 30.0) return;

    lastT = now;

    done++;

    @try {

        NSMutableString *ms = [NSMutableString string];

        for (size_t i = 0; i < n && i < 1024; i++) [ms appendFormat:@"%02x", b[i]];

        NSString *p = [NSHomeDirectory()

                       stringByAppendingPathComponent:@"Documents/rb-auth-sample.txt"];

        NSString *txt = [NSString stringWithFormat:@"#%d len=%lu\n%@\n",

                         done, (unsigned long)n, ms];

        // v73：原来每份都覆盖同一个文件 —— rb-shim(15) 里 139 字节（高速时抓到的）
        // 和 253 字节（额度心跳）都被最后那份 210 字节冲掉了，只剩低速那一份，
        // 根本没法跟高速那份对比。改成追加：第一次写覆盖、之后追加。
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];

        if (done == 1 || !fh) {

            [txt writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];

        } else {

            [fh seekToEndOfFile];

            [fh writeData:[txt dataUsingEncoding:NSUTF8StringEncoding]];

            [fh closeFile];

        }

        rb_log("抓到疑似节点授权报文（第 %d 份，%lu 字节，含凭据+授权串）—— "
               "已存 Documents/rb-auth-sample.txt，下一版据此自动重放", done, (unsigned long)n);

    } @catch (NSException *e) { }

}



static BOOL rb_dead(const uint8_t *b, size_t n) {

    if (!b || n < 8) return NO;

    // ① 服务端下发的福利模式占位号

    if (rb_find(b, n, "signup_gift_placeholder", 23)) return YES;

    // ② 文本形态（JSON），先关键词过滤

    if (rb_find(b, n, "quota", 5) || rb_find(b, n, "remaining", 9)) {

        if (rb_text_dead(b, n)) return YES;

    }

    // v66：f1=35 心跳包里的 quota/used（高频），面板显示与触发判据都用它

    rb_scan_used35(b, n);

    // v71：抓取「节点授权」报文 —— 请求里带节点凭据（大写 36hex）、响应里回授权串
    // （小写 36hex），两者同时出现的包基本就是它。下一轮据此做「抹后自动重放拿授权」。
    rb_probe_auth(b, n);

    // ③ protobuf 二进制形态。

    // v53：只扫小包。日志里出现过 len=129808 的大响应被 pb 判据误命中

    // （一大段二进制里随便凑出 f2/f3 太容易了），真正的额度报文只有两百来字节。

    if (n > RB_PB_MAX_LEN || n < RB_MIN_PB_LEN) return NO;

    size_t budget = 2 * n + 65536;

    @try {

        if (rb_pb_dead(b, n, 0, &budget)) return YES;

    } @catch (NSException *e) { }

    return NO;

}



#pragma mark - 抹除



static volatile int      gWiping = 0;

static volatile int      gHits   = 0;

static volatile double   gBootAt = 0;

static volatile int      gStopped = 0;   // 熔断/闪退循环 → 1，之后只记日志

static volatile int      gFastLane = 0;  // 刚抹完重开 → 1，用更短的宽限/冷却

static NSString         *gLastWhy = nil;

// v56

static volatile double   gRateKBps = 0;  // 实测速率（KB/s）

static volatile double   gLastTrafficTs = 0; // 最近一次 utun 有流量的时刻（判假连接用）

// v58：这台机器上 NE 没有 start 接口（v57 日志已证实）→ 1 时不再反复重试刷日志

static volatile int      gNoStartApi = 0;

static volatile int      gNoStartLogged = 0;

// v59：v58 日志证实 start 在 connection 上（manager 上没有）→ 记住结论，别每次撞 4 次

static volatile int      gUseConnStart = 0;

static volatile int      gMgrStartLogged = 0;

// v59：抹除之后又收到过归零 → 1（说明那次抹除没换回额度，补刀复核要用）

static volatile int      gHitAfterWipe = 0;

static volatile double   gLastStartTs = 0;   // 上次**真的发出** start 的时刻（不是「尝试」的时刻）

// v60：假连接处理的计数器。之前入口就刷新 gLastStartTs，看门狗每 12 秒进来一次

// 把稳定期一直续上，结果「永远不会再判假连接、也永远不会再 start」——自动重连装死。

static volatile int      gFakeFixCount = 0;      // 连续判假连接并处理了几次

static volatile double   gFakeFixCoolUntil = 0;  // 封顶后的冷却截止时刻

static volatile int      gFakeFixCoolLog = 0;    // 冷却提示只打一次

static volatile double   gLastTryTs = 0;         // 上次「尝试拉起」的时刻（只用来限流打日志）

// v61：限速判据的计时。连续低速这么久 → 判定掉到福利速度 → 抹

static volatile double   gSlowSec     = 0;

static volatile int      gThrottleHit = 0;       // 本次已经因限速抹过（抹完清零）

// v61：utun 重建计数（排障用：日志里能看到累计被清零过几次）

static volatile int      gFlowRebuilds = 0;

// v62：上次节点快照校验的时刻（进程内节流，30 秒一次）

static volatile double   gNodeSnapTs = 0;

static volatile int      gAutoOn = 0;        // 「自动连接」开关当前值

static volatile int      gKeepAudio = 0;     // 静音音频保活是否已开

static id                gAssertion = nil;   // RBS/BKS 断言（拿到就一直握着）

static id                gPlayer    = nil;   // 静音保活播放器

// UIBackgroundTaskInvalid 在新 SDK 里是 extern 常量，不能拿来初始化静态变量，

// 所以自己用一个 BOOL 记着有没有握着后台任务

static UIBackgroundTaskIdentifier gBgTask = 0;

static BOOL gBgTaskHeld = NO;



// 下面几个函数在文件后半段才定义，这里先声明（rb_auto_set 要用）

static void rb_stop_vpn(void);

static void rb_set_ondemand(BOOL on);

// force=1 表示「用户点了按钮」，此时即使自动连接开关是关的也要拉一次

static int gQuietLogged = 0;      // v74：抹后静默期只报一次
static void rb_start_vpn_once(int force);

static void rb_node_rotate(void);

static void rb_node_watch_new(int left);

static void rb_ne_drop_configs(const char *why);
static void rb_ne_dump_cfg(NSArray *mans);          // v72 只读诊断

static void rb_ne_watch_config(int left);

static void rb_panel_refresh(void);

#if !RB_PANEL

static void rb_panel_refresh(void) { }   // 面板关掉时给个空实现，免得链接失败

#endif



// 「自动连接」开关：写进 rb_state.plist，重装/抹数据之外都记得住

static BOOL rb_auto_on(void) { return gAutoOn; }



static void rb_auto_set(BOOL on) {

    gAutoOn = on ? 1 : 0;

    NSMutableDictionary *st = rb_state();

    [st setObject:[NSNumber numberWithBool:on] forKey:@"autoConnect"];

    rb_state_save(st);

    rb_log("自动连接开关 → %s", on ? "开（会一直保持连接）" : "关（断开且不再自动连）");

    if (on) {

#if RB_ONDEMAND_CONNECT

        rb_set_ondemand(YES);

#endif

        rb_start_vpn_once(1);      // 用户刚打开开关：无论什么情况都拉一次

    } else {

#if RB_ONDEMAND_CONNECT

        rb_set_ondemand(NO);

#endif

        rb_stop_vpn();

    }

}



// 清空目录里的条目，保留目录本身与白名单。

// keepSubdirs=1 只删文件不删子目录：把 Caches 这类目录整个端掉会让 Flutter

// 引擎启动时找不到东西而崩，只清空内容最安全。

//

// v53 注意：对 Library/Caches、Library/Application Support 这类「内容全在子目录里」

// 的地方，keepSubdirs=1 等于什么都没删 —— v52 抹一次只删掉 4 个条目就是这么来的。

// 所以下面 rb_clean_deep 才是对这些目录该用的版本。

static int rb_clean(NSString *dir, NSArray *keep, int keepSubdirs) {

    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL isDir = NO;

    if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) return 0;

    NSArray *items = [fm contentsOfDirectoryAtPath:dir error:NULL];

    if (!items) return 0;

    int n = 0;

    for (NSString *it in items) {

        if (keep && [keep containsObject:it]) continue;

        NSString *p = [dir stringByAppendingPathComponent:it];

        if (keepSubdirs) {

            BOOL d = NO;

            if ([fm fileExistsAtPath:p isDirectory:&d] && d) continue;

        }

        if ([fm removeItemAtPath:p error:NULL]) n++;

    }

    return n;

}



// 连子目录一起删（v53）。

//

// v54 修正：删完目录要**原地重建空目录**。v53 抹完自拉起的新进程活不过 6 秒就死

// （日志里 pid 16142 打出「即将自动重连」后再无任何输出），根因就是 Flutter 启动时

// 发现 Caches / Application Support 下面的目录整个没了 —— 它只做 open 不做 mkdir，

// 直接崩。删除照旧，但删完立刻 mkdir 回来：目录还在、内容空，App 就能正常起。

static int rb_clean_deep(NSString *dir, NSArray *keep) {

    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL isDir = NO;

    if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) return 0;

    NSArray *items = [fm contentsOfDirectoryAtPath:dir error:NULL];

    if (!items) return 0;

    int n = 0;

    for (NSString *it in items) {

        if (keep && [keep containsObject:it]) continue;

        NSString *p = [dir stringByAppendingPathComponent:it];

        BOOL sub = NO;

        BOOL exists = [fm fileExistsAtPath:p isDirectory:&sub];

        if ([fm removeItemAtPath:p error:NULL]) {

            n++;

            // 删掉的是目录 → 原地重建一个空的，别让 App 启动时撞空

            if (exists && sub)

                [fm createDirectoryAtPath:p withIntermediateDirectories:YES

                               attributes:nil error:NULL];

        } else if (exists && sub) {

            // 删不掉（被占用 / 权限）：把它里面的东西逐个删掉，至少清内容

            NSArray *sub2 = [fm contentsOfDirectoryAtPath:p error:NULL];

            for (NSString *s in sub2)

                if ([fm removeItemAtPath:[p stringByAppendingPathComponent:s] error:NULL]) n++;

        }

    }

    return n;

}



// keychain 逐项精确删除。整类 SecItemDelete 会把 NE VPN 配置引用的那一项也端掉

// （passwordReference 指向它），清了之后 VPN 直接连不上，所以逐项判一遍。

static NSString *rb_bundle_id(void) {

    @try { return [[NSBundle mainBundle] bundleIdentifier]; }

    @catch (NSException *e) { return nil; }

}



// v55：VPN 凭据项的指纹集合，元素是 "service|account"。

// service == bundle id 这个判据太粗糙了 —— 实测 skip 一直是 0，也就是

// 「VPN 配置引用的那一项」根本没被认出来，照样被删。这里改成真凭实据：

// 从 NETunnelProviderManager.protocolConfiguration.passwordReference（persistent ref）

// 反查出那一项的 service/account，记下来，清 keychain 时精确跳过。

static NSMutableSet *gVpnKc = nil;



static NSString *rb_kc_key(NSString *svc, NSString *acct) {

    return [NSString stringWithFormat:@"%@|%@", svc ? svc : @"", acct ? acct : @""];

}



static void rb_collect_vpn_kc(void) {

    @try {

        if (!gVpnKc) gVpnKc = [[NSMutableSet alloc] init];

        Class C = objc_getClass("NETunnelProviderManager");

        if (!C) return;

        void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

            (void)err;

            for (id m in mans) {

                id proto = nil;

                if ([m respondsToSelector:@selector(protocolConfiguration)])

                    proto = [m valueForKey:@"protocolConfiguration"];

                if (!proto && [m respondsToSelector:@selector(protocol)])

                    proto = [m valueForKey:@"protocol"];

                if (!proto) continue;

                id ref = nil;

                if ([proto respondsToSelector:@selector(passwordReference)])

                    ref = [proto valueForKey:@"passwordReference"];

                if (!ref || ![ref isKindOfClass:[NSData class]]) continue;

                // iOS 没有 kSecMatchPersistentReference（那是 macOS 的），

                // 要用 persistent ref 定位就得走 kSecUseItemList（数组里放 ref）

                NSDictionary *q = [NSDictionary dictionaryWithObjectsAndKeys:

                                   (id)kSecClassGenericPassword, (id)kSecClass,

                                   [NSArray arrayWithObject:ref], (id)kSecUseItemList,

                                   (id)kCFBooleanTrue,           (id)kSecReturnAttributes,

                                   nil];

                CFTypeRef raw = NULL;

                if (SecItemCopyMatching((CFDictionaryRef)q, &raw) != errSecSuccess || !raw) continue;

                NSDictionary *a = [[(id)raw autorelease] retain];

                if ([a isKindOfClass:[NSDictionary class]]) {

                    NSString *k = rb_kc_key([a objectForKey:(id)kSecAttrService],

                                            [a objectForKey:(id)kSecAttrAccount]);

                    [gVpnKc addObject:k];

                    rb_log("已记下 VPN 凭据项（清 keychain 时跳过）：%s", [k UTF8String]);

                }

                [a release];

            }

        };

        ((void (*)(id, SEL, id))objc_msgSend)(

            C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

    } @catch (NSException *e) { }

}



// aggressive=1：连 service == bundle id 的那一项也删。

// 前面几次都抹了还是归零，说明「VPN 配置引用项」里也带身份，那就别再留了 ——

// 代价是 VPN 配置可能失效（手动重新连一次即可），换来的是额度真的刷新。

// v73：只读导出 keychain 清单（service / account / 类 / 可访问组），不动任何一项。
static void rb_kc_dump(void) {

    NSArray *classes = [NSArray arrayWithObjects:

                        (id)kSecClassGenericPassword, (id)kSecClassInternetPassword,

                        (id)kSecClassCertificate, (id)kSecClassKey,

                        (id)kSecClassIdentity, nil];

    NSMutableString *ms = [NSMutableString string];

    int total = 0;

    for (id cls in classes) {

        NSDictionary *q = [NSDictionary dictionaryWithObjectsAndKeys:

                           cls,                    (id)kSecClass,

                           (id)kSecMatchLimitAll,  (id)kSecMatchLimit,

                           (id)kCFBooleanTrue,     (id)kSecReturnAttributes,

                           nil];

        CFTypeRef raw = NULL;

        if (SecItemCopyMatching((CFDictionaryRef)q, &raw) != errSecSuccess || raw == NULL) continue;

        id obj = [(id)raw autorelease];

        if (![obj isKindOfClass:[NSArray class]]) continue;

        for (NSDictionary *it in (NSArray *)obj) {

            [ms appendFormat:@"class=%@ svc=%@ acct=%@ agrp=%@\n",

             cls,

             [it objectForKey:(id)kSecAttrService]  ?: @"(nil)",

             [it objectForKey:(id)kSecAttrAccount]  ?: @"(nil)",

             [it objectForKey:(id)kSecAttrAccessGroup] ?: @"(nil)"];

            total++;

        }

    }

    NSString *fp = [NSHomeDirectory()

                    stringByAppendingPathComponent:@"Documents/rb-kc.txt"];

    NSString *txt = [NSString stringWithFormat:@"# v73 keychain 清单（只读，%d 项）\n%@", total, ms];

    [txt writeToFile:fp atomically:YES encoding:NSUTF8StringEncoding error:NULL];

    rb_log("keychain 清单：%d 项已导出 Documents/rb-kc.txt（只读，不动任何一项）", total);

}



static int rb_kc_wipe(int aggressive) {

    NSString *bid = rb_bundle_id();

    NSArray *classes = [NSArray arrayWithObjects:

                        (id)kSecClassGenericPassword, (id)kSecClassInternetPassword,

                        (id)kSecClassCertificate, (id)kSecClassKey,

                        (id)kSecClassIdentity, nil];

    int n = 0, skip = 0;

    for (id cls in classes) {

        NSDictionary *q = [NSDictionary dictionaryWithObjectsAndKeys:

                           cls,                        (id)kSecClass,

                           (id)kSecMatchLimitAll,      (id)kSecMatchLimit,

                           (id)kCFBooleanTrue,         (id)kSecReturnAttributes,

                           (id)kCFBooleanTrue,         (id)kSecReturnPersistentRef,

                           nil];

        CFTypeRef raw = NULL;

        OSStatus s = SecItemCopyMatching((CFDictionaryRef)q, &raw);

        if (s != errSecSuccess || raw == NULL) continue;

        id obj = [(id)raw autorelease];

        if (![obj isKindOfClass:[NSArray class]]) continue;



        for (NSDictionary *it in (NSArray *)obj) {

            NSString *svc  = [it objectForKey:(id)kSecAttrService];

            NSString *acct = [it objectForKey:(id)kSecAttrAccount];

#if RB_KEEP_VPN_KC

            // ① service == bundle id 的那一项是 VPN 配置引用的，留着

            if (!aggressive && bid && svc && [svc isEqualToString:bid]) { skip++; continue; }

            // ② v55：从 passwordReference 反查出来的那一项，精确留着

            if (!aggressive && gVpnKc &&

                [gVpnKc containsObject:rb_kc_key(svc, acct)]) { skip++; continue; }

#endif

            // 删除也走 kSecUseItemList（iOS 上最可靠的按 ref 定位方式）；

            // 拿不到 ref 就退回 service + account 精确定位

            id ref = [it objectForKey:(id)kSecValuePersistentRef];

            if (ref) {

                NSDictionary *dq = [NSDictionary dictionaryWithObjectsAndKeys:

                                    cls, (id)kSecClass,

                                    [NSArray arrayWithObject:ref], (id)kSecUseItemList,

                                    nil];

                if (SecItemDelete((CFDictionaryRef)dq) == errSecSuccess) n++;

            } else {

                NSMutableDictionary *dq = [NSMutableDictionary dictionary];

                [dq setObject:cls forKey:(id)kSecClass];

                if (svc)  [dq setObject:svc  forKey:(id)kSecAttrService];

                if (acct) [dq setObject:acct forKey:(id)kSecAttrAccount];

                if (SecItemDelete((CFDictionaryRef)dq) == errSecSuccess) n++;

            }

        }

    }

    if (skip > 0) rb_log("keychain：删掉 %d 项，保留 %d 项（VPN 配置引用）", n, skip);

    return n;

}



#pragma mark - 节点保活（v64）



// Flutter 的 shared_preferences 落在 NSUserDefaults：主 domain（bundle id）、

// "flutter" domain、App Group suite 三处都可能存。全扫一遍。

static NSArray *rb_prefs_domains(void) {

    NSMutableArray *a = [NSMutableArray array];

    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];

    if (bid) [a addObject:bid];

    [a addObject:@"flutter"];

    [a addObject:RB_GROUP_ID];

    return a;

}



// rb_state.plist 是 plist，存进去的必须是 plist 能表达的类型

static BOOL rb_plist_ok(id v) {

    if ([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSNumber class]] ||

        [v isKindOfClass:[NSData class]]   || [v isKindOfClass:[NSDate class]]) return YES;

    if ([v isKindOfClass:[NSArray class]]) {

        for (id x in (NSArray *)v) if (!rb_plist_ok(x)) return NO;

        return YES;

    }

    if ([v isKindOfClass:[NSDictionary class]]) {

        NSDictionary *d = (NSDictionary *)v;

        for (id k in d) {

            if (![k isKindOfClass:[NSString class]]) return NO;

            if (!rb_plist_ok([d objectForKey:k])) return NO;

        }

        return YES;

    }

    return NO;

}



// 节点类键名：命中放行词，且不命中身份词。

// 身份词必须狠 —— 一旦把 device_id / token / license 也恢复回去，

// 服务端认得这台设备，额度就不会刷新，整条链白干。

static BOOL rb_is_node_key(NSString *kk) {

    NSString *low = [kk lowercaseString];

    static const char *deny[] = {"device", "uuid", "token", "licen", "account",

                                 "auth", "secret", "pass", "session", "phone",

                                 "email", "sign", "cert", "key", "install",

                                 "regist", "login", "pay", "order", "expire",

                                 "time", "date", "count", "index", "used",

                                 "quota", "traffic", "credit"};

    for (unsigned i = 0; i < sizeof(deny) / sizeof(deny[0]); i++) {

        if ([low rangeOfString:[NSString stringWithUTF8String:deny[i]]]

                .location != NSNotFound) return NO;

    }

    static const char *allow[] = {"node", "server", "region", "country", "city",

                                  "host", "address", "endpoint", "select",

                                  "current", "last", "proxy", "vpn"};

    for (unsigned i = 0; i < sizeof(allow) / sizeof(allow[0]); i++) {

        if ([low rangeOfString:[NSString stringWithUTF8String:allow[i]]]

                .location != NSNotFound) return YES;

    }

    return NO;

}



// 把三处 domain 的全部键名/值导出来，供下一步精确定位「当前节点」存哪

static void rb_prefs_dump(void) {

    @try {

        NSMutableString *out = [NSMutableString string];

        [out appendString:@"# rb-shim v64 配置键导出\n"];

        [out appendString:@"# 行首带 * = 判定为「节点类」，抹除后会被恢复\n"];

        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];

        NSUserDefaults *gd = [[NSUserDefaults alloc] initWithSuiteName:RB_GROUP_ID];

        int total = 0;

        for (NSString *dom in rb_prefs_domains()) {

            for (int which = 0; which < 2; which++) {

                NSUserDefaults *src = (which == 0) ? ud : gd;

                if (!src) continue;

                NSDictionary *d = [src persistentDomainForName:dom];

                if (!d || [d count] == 0) continue;

                [out appendFormat:@"\n[domain %@ / %@] %lu 键\n", dom,

                                  (which == 0 ? @"标准" : @"AppGroup"),

                                  (unsigned long)[d count]];

                for (NSString *k in d) {

                    id v = [d objectForKey:k];

                    NSString *sv = nil;

                    if ([v isKindOfClass:[NSData class]])

                        sv = [NSString stringWithFormat:@"<data %lu>",

                              (unsigned long)[(NSData *)v length]];

                    else if ([v isKindOfClass:[NSString class]]) sv = v;

                    else sv = [v description];

                    if ([sv length] > 240) sv = [sv substringToIndex:240];

                    [out appendFormat:@"%@%@ = %@\n",

                                      rb_is_node_key(k) ? @"*" : @" ", k, sv];

                    total++;

                }

            }

        }

        [gd release];

        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];

        NSString *path = [dir stringByAppendingPathComponent:RB_PREFS_FILE];

        [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];

        rb_log("配置导出：Library/%s（%d 个键，%lu 字节，带 * 的会被保留）",

               [RB_PREFS_FILE UTF8String], total, (unsigned long)[out length]);

    } @catch (NSException *e) {

        rb_log("配置导出失败：%s", [[e reason] UTF8String]);

    }

}



// 抹之前：把节点类键抓进 rb_state.plist（抹除不删）

static void rb_prefs_snapshot(void) {

    @try {

        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];

        NSUserDefaults *gd = [[NSUserDefaults alloc] initWithSuiteName:RB_GROUP_ID];

        NSMutableDictionary *all = [NSMutableDictionary dictionary];

        int n = 0;

        for (NSString *dom in rb_prefs_domains()) {

            for (int which = 0; which < 2; which++) {

                NSUserDefaults *src = (which == 0) ? ud : gd;

                if (!src) continue;

                NSDictionary *d = [src persistentDomainForName:dom];

                if (!d || [d count] == 0) continue;

                NSMutableDictionary *pick = [NSMutableDictionary dictionary];

                for (NSString *k in d) {

                    if (!rb_is_node_key(k)) continue;

                    id v = [d objectForKey:k];

                    if (!rb_plist_ok(v)) continue;

                    [pick setObject:v forKey:k];

                    n++;

                }

                if ([pick count])

                    [all setObject:pick

                            forKey:[NSString stringWithFormat:@"%@|%d", dom, which]];

            }

        }

        [gd release];

        if (n == 0) {

            rb_log("节点保活：没找到节点类配置键（详见 Library/%s）", [RB_PREFS_FILE UTF8String]);

            return;

        }

        NSMutableDictionary *st = rb_state();

        [st setObject:all forKey:RB_PREFS_SNAP_KEY];

        rb_state_save(st);

        rb_log("节点保活：已存 %d 个节点类配置键，抹完自动写回", n);

    } @catch (NSException *e) {

        rb_log("节点保活快照失败：%s", [[e reason] UTF8String]);

    }

}



// 抹之后：把节点类键写回去（额度身份不恢复，刷新照旧）

static void rb_prefs_restore(void) {

    @try {

        // v75：不再写回。rb-report 实锤：抹后 App 补回来的授权串（f22）
        // 和抹除前那一模一样（534bb848-...），而节点文件里并没有它 ——
        // 唯一来源就是这里写回去的节点类配置键。App 拿旧串不申请新授权，
        // 服务端按旧 license 压 160Kbps。快照继续留着（备查），只是不写回。
        rb_log("节点类配置键快照保留但不写回（v75）：写回去会把旧授权串一起带走，"
               "App 就不去申请新授权，直接吃限速档");
        return;

        NSDictionary *all = [rb_state() objectForKey:RB_PREFS_SNAP_KEY];

        if (![all isKindOfClass:[NSDictionary class]] || [all count] == 0) return;

        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];

        NSUserDefaults *gd = [[NSUserDefaults alloc] initWithSuiteName:RB_GROUP_ID];

        int n = 0;

        for (NSString *slot in all) {

            NSDictionary *pick = [all objectForKey:slot];

            if (![pick isKindOfClass:[NSDictionary class]]) continue;

            NSArray *parts = [slot componentsSeparatedByString:@"|"];

            if ([parts count] != 2) continue;

            NSString *dom = [parts objectAtIndex:0];

            NSUserDefaults *dst = ([[parts objectAtIndex:1] intValue] == 0) ? ud : gd;

            if (!dst) continue;

            NSMutableDictionary *cur =

                [NSMutableDictionary dictionaryWithDictionary:

                    ([dst persistentDomainForName:dom] ?: [NSDictionary dictionary])];

            for (NSString *k in pick) [cur setObject:[pick objectForKey:k] forKey:k];

            [dst setPersistentDomain:cur forName:dom];

            n += (int)[pick count];

        }

        [ud synchronize];

        if (gd) { [gd synchronize]; [gd release]; }

        if (n) rb_log("节点保活：已写回 %d 个节点类配置键（身份键未恢复，额度照常刷新）", n);

    } @catch (NSException *e) {

        rb_log("节点保活恢复失败：%s", [[e reason] UTF8String]);

    }

}



#pragma mark - 节点文件保活（v65）



static NSString *rb_node_dir(void) {

    return [[[NSHomeDirectory() stringByAppendingPathComponent:@"Library"]

             stringByAppendingPathComponent:@"Application Support"]

             stringByAppendingPathComponent:@"RelyVPN"];

}



// 文件名判定：命中节点词、不命中身份词

static BOOL rb_is_node_file(NSString *name) {

    NSString *low = [name lowercaseString];

    static const char *deny[] = {"device", "uuid", "token", "licen", "account",

                                 "auth", "secret", "pass", "session", "key",

                                 "user", "phone", "email", "order", "pay"};

    for (unsigned i = 0; i < sizeof(deny) / sizeof(deny[0]); i++) {

        if ([low rangeOfString:[NSString stringWithUTF8String:deny[i]]]

                .location != NSNotFound) return NO;

    }

    static const char *allow[] = {"node", "server", "region", "country", "city",

                                  "select", "current", "proxy"};

    for (unsigned i = 0; i < sizeof(allow) / sizeof(allow[0]); i++) {

        if ([low rangeOfString:[NSString stringWithUTF8String:allow[i]]]

                .location != NSNotFound) return YES;

    }

    return NO;

}



// 抹之前：把节点类文件整份读进 rb_state.plist（抹除不删）

static void rb_node_files_snapshot(void) {

    @try {

        NSString *dir = rb_node_dir();

        NSFileManager *fm = [NSFileManager defaultManager];

        NSArray *items = [fm subpathsOfDirectoryAtPath:dir error:NULL];

        if (!items || [items count] == 0) {

            rb_log("节点文件保活：Application Support/RelyVPN 下没有文件");

            return;

        }

        NSMutableDictionary *pick = [NSMutableDictionary dictionary];

        int n = 0;

        for (NSString *it in items) {

            if (!rb_is_node_file(it)) continue;

            NSString *full = [dir stringByAppendingPathComponent:it];

            BOOL isDir = NO;

            if (![fm fileExistsAtPath:full isDirectory:&isDir] || isDir) continue;

            NSDictionary *a = [fm attributesOfItemAtPath:full error:NULL];

            unsigned long long sz = a ? [a fileSize] : 0;

            if (sz == 0 || sz > (256ULL * 1024)) continue;

            NSData *d = [NSData dataWithContentsOfFile:full];

            if (!d || [d length] == 0) continue;

            [pick setObject:d forKey:it];

            n++;

        }

        if (n == 0) {

            rb_log("节点文件保活：%lu 个文件里没有节点类的（详见 Documents/rb-nodes.txt）",

                   (unsigned long)[items count]);

            return;

        }

        NSMutableDictionary *st = rb_state();

        [st setObject:pick forKey:RB_NODEFILES_KEY];

        rb_state_save(st);

        NSString *names = [[pick allKeys] componentsJoinedByString:@", "];

        if ([names length] > 200) names = [names substringToIndex:200];

        rb_log("节点文件保活：已存 %d 个节点文件 [%s]，抹完原样写回",

               n, [names UTF8String]);

    } @catch (NSException *e) {

        rb_log("节点文件保活快照失败：%s", [[e reason] UTF8String]);

    }

}



// 抹之后：目录被删了，重建并把节点文件写回去

// v68：这次启动是不是「刚抹完数据」起来的。
// 是的话就不写回旧节点：旧 currentNodeWithReason.bin 里的节点认证串是旧账号签发的，
// 写回去 = 同一条旧身份继续用 → 服务端按老账本压成福利限速。
// rb-shim(12) 第 10~14 行反过来证明：没有节点文件时 App 会自己按服务端下发选节点。
static BOOL rb_just_wiped(void) {

    @try {

        NSDictionary *st = rb_state();

        if ([[st objectForKey:@"pendingStart"] boolValue]) return YES;

        double lw = [[st objectForKey:@"lastWipeTs"] doubleValue];

        return (lw > 0 && rb_now() - lw < RB_NODE_SELF_SEC);

    } @catch (NSException *e) { return NO; }

}



// v70：把节点文件里的「账号-节点授权串」等长替换成随机值。
// 判据来自两份真实导出：大写 36hex（B72009F2-4787-…）两次导出完全一致 = 节点 ID，保留；
// 小写 36hex（988197b0-255c-…）= 授权串，是旧账号签发的，留着就是限速根因。
// 等长替换不改变文件结构（长度前缀编码不受影响），App 解析不会出问题。
static NSData *rb_strip_auth(NSData *d) {

    if (!d || [d length] < 8) return d;

    NSUInteger n = [d length];

    const uint8_t *b = (const uint8_t *)[d bytes];

    NSMutableData *out = [NSMutableData dataWithCapacity:n];

    NSUInteger i = 0;

    int hits = 0;

    while (i < n) {

        NSUInteger st = i;

        uint64_t key = 0;

        int sh = 0;

        while (i < n && sh <= 63) {

            uint8_t c = b[i++];

            key |= (uint64_t)(c & 0x7f) << sh;

            sh += 7;

            if (!(c & 0x80)) break;

        }

        if (sh > 63) break;

        int field = (int)(key >> 3);

        int wt    = (int)(key & 7);

        if (wt == 2) {

            uint64_t L = 0;

            sh = 0;

            while (i < n && sh <= 63) {

                uint8_t c = b[i++];

                L |= (uint64_t)(c & 0x7f) << sh;

                sh += 7;

                if (!(c & 0x80)) break;

            }

            if (sh > 63) break;

            if (i + L > n) break;

            i += (NSUInteger)L;

        } else if (wt == 0) {

            sh = 0;

            while (i < n && sh <= 63) {

                uint8_t c = b[i++];

                sh += 7;

                if (!(c & 0x80)) break;

            }

            if (sh > 63) break;

        } else if (wt == 5) {

            if (i + 4 > n) break;

            i += 4;

        } else if (wt == 1) {

            if (i + 8 > n) break;

            i += 8;

        } else {

            break;      // 组类型（3/4）不处理，直接放弃

        }

        if (field == 22) { hits++; continue; }   // 授权串：整段不拷贝

        [out appendBytes:(b + st) length:(i - st)];

    }

    if (hits) rb_log("节点文件已去掉 %d 处授权串（f22，整段删除，其余字段一字不动）—— "
                     "现在是「有节点凭据、没有授权」，App 应当去申请新授权", hits);

    return (hits && i >= n) ? out : d;

}



// v70：把节点文件原样以 16 进制导出来，下一轮做「授权请求重放」时要用。
static void rb_node_hex_dump(NSData *d, NSString *name) {

    @try {

        if (!d || [d length] == 0) return;

        NSMutableString *ms = [NSMutableString string];

        NSUInteger n = [d length];

        const uint8_t *b = (const uint8_t *)[d bytes];

        for (NSUInteger i = 0; i < n; i++) {

            [ms appendFormat:@"%02x", b[i]];

            if ((i % 32) == 31) [ms appendString:@"\n"];

        }

        NSString *p = [NSHomeDirectory()

                       stringByAppendingPathComponent:@"Documents/rb-node-hex.txt"];

        NSString *txt = [NSString stringWithFormat:@"%@ %lu bytes\n%@\n",

                         name, (unsigned long)n, ms];

        [txt writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];

        rb_log("节点文件原文已导出 Documents/rb-node-hex.txt（%lu 字节）",

               (unsigned long)n);

    } @catch (NSException *e) { }

}



static void rb_node_files_restore(void);   // v68 前向声明（下面的 _direct 要用）

static NSData *gNodeWrote = nil;           // v71：我们最后一次写回的节点文件内容
static int  gPostWipeWatchFired = 0;       // v73：watch 已经替 App 拉过隧道了

// 不论是不是刚抹完、都真的写一次（bounce 兜底用）
static BOOL rb_node_files_restore_direct(void) {

    @try {

        NSDictionary *pick = [rb_state() objectForKey:RB_NODEFILES_KEY];

        if ([pick isKindOfClass:[NSDictionary class]] && [pick count] > 0) {

            rb_node_files_restore();

            return YES;

        }

    } @catch (NSException *e) { }

    return NO;

}



static void rb_node_files_restore(void) {

    @try {

        NSDictionary *pick = [rb_state() objectForKey:RB_NODEFILES_KEY];

        if (![pick isKindOfClass:[NSDictionary class]] || [pick count] == 0) return;

        NSString *dir = rb_node_dir();

        NSFileManager *fm = [NSFileManager defaultManager];

        [fm createDirectoryAtPath:dir

             withIntermediateDirectories:YES attributes:nil error:NULL];

        int n = 0;

        for (NSString *it in pick) {

            NSData *d = [pick objectForKey:it];

            if (![d isKindOfClass:[NSData class]] || [d length] == 0) continue;

            NSString *full = [dir stringByAppendingPathComponent:it];

            // v66：App 自己已经写好的节点文件不覆盖 —— 用户刚手选的新节点
            // 不能被我们写回的旧节点冲掉。只救「抹掉了、还没长回来」的空位。
            NSDictionary *ex = [fm attributesOfItemAtPath:full error:NULL];

            if (ex && [ex fileSize] > 0) continue;

            // v71：写回之前把授权串整段删掉（节点凭据 f14 保留）
            d = rb_strip_auth(d);

            rb_node_hex_dump(d, it);

            [fm createDirectoryAtPath:[full stringByDeletingLastPathComponent]

                 withIntermediateDirectories:YES attributes:nil error:NULL];

            if ([d writeToFile:full atomically:YES]) {

                n++;

                @try { [gNodeWrote release]; gNodeWrote = [d copy]; } @catch (NSException *e) { }

            }

        }

        if (n) rb_log("节点文件保活：已写回 %d 个节点文件（身份文件未动，额度照常刷新）", n);

    } @catch (NSException *e) {

        rb_log("节点文件保活恢复失败：%s", [[e reason] UTF8String]);

    }

}



// v69：把系统里建好的 VPN 配置删干净。
// 配置里的 providerConfiguration 带着旧节点地址与凭据（抹 App 数据不会动系统配置），
// 只要配置还在，隧道起来就一定连回旧节点 —— 这就是「抹完了还是限速」的根。
// rb-shim(13) 第 10~17 行对照：全新进程没有配置，App 自己建，一路跑到 300MB 归零。
static void rb_ne_dump_cfg(NSArray *mans) {

    static int done = 0;

    if (done || ![mans count]) return;

    @try {

        NSMutableString *ms = [NSMutableString string];

        NSUInteger idx = 0;

        for (id man in mans) {

            id pr = nil, pc = nil, sv = nil;

            @try { pr = [man valueForKey:@"protocolConfiguration"]; } @catch (NSException *e) { }

            @try { pc = [pr  valueForKey:@"providerConfiguration"]; } @catch (NSException *e) { }

            @try { sv = [pr  valueForKey:@"serverAddress"]; }          @catch (NSException *e) { }

            [ms appendFormat:@"[%lu] serverAddress=%@\n", (unsigned long)idx, sv];

            if ([pc isKindOfClass:[NSDictionary class]]) {

                for (id k in [(NSDictionary *)pc allKeys])

                    [ms appendFormat:@"    %@ = %@\n", k, [(NSDictionary *)pc objectForKey:k]];

            } else {

                [ms appendFormat:@"    providerConfiguration=%@\n", pc];

            }

            idx++;

        }

        done = 1;

        NSString *fp = [NSHomeDirectory()

                        stringByAppendingPathComponent:@"Documents/rb-necfg.txt"];

        NSString *txt = [NSString stringWithFormat:@"# v72 NE 配置诊断（只读，%lu 个）\n%@",

                         (unsigned long)[mans count], ms];

        [txt writeToFile:fp atomically:YES encoding:NSUTF8StringEncoding error:NULL];

        rb_log("NE 配置诊断：%lu 个配置的 providerConfiguration 已导出 "
               "Documents/rb-necfg.txt（只读，不动配置）", (unsigned long)[mans count]);

    } @catch (NSException *e) { }

}



static void rb_ne_drop_configs(const char *why) {

    @try {

        Class C = objc_getClass("NETunnelProviderManager");

        if (!C) { rb_log("%s：这台机器上没有 NETunnelProviderManager", why); return; }

        void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

            (void)err;

            if (!mans) return;

            if ([mans count] == 0) {

                rb_log("%s：当前 0 个 VPN 配置，无需删除", why);

                return;

            }

            int n = 0;

            SEL rm = sel_registerName("removeFromPreferencesWithCompletionHandler:");

            for (id m in mans) {

                @try {

                    if ([m respondsToSelector:rm]) {

                        ((void (*)(id, SEL, void (^)(NSError *)))objc_msgSend)(

                            m, rm, ^(NSError *e) { (void)e; });

                        n++;

                    }

                } @catch (NSException *e) { }

            }

            rb_log("%s：已删掉 %d 个 VPN 配置 —— providerConfiguration 里的旧节点凭据"
                   "一起清掉，状态回到全新安装（速率才不会按旧账本压）", why, n);

        };

        ((void (*)(id, SEL, void (^)(NSArray *, NSError *)))objc_msgSend)(

            C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

    } @catch (NSException *e) {

        rb_log("清理 VPN 配置失败：%s", [[e reason] UTF8String]);

    }

}



// App 重新把 VPN 配置建回来之后立刻接上（不然它建好了也没人替它按连接）
static void rb_ne_watch_config(int left) {

    if (left <= 0) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            @try {

                Class C = objc_getClass("NETunnelProviderManager");

                if (C) {

                    void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

                        (void)err;

                        if (mans && [mans count] > 0) {

                            rb_log("检测到 App 已重新建立 VPN 配置（%lu 个），立刻拉起隧道",

                                   (unsigned long)[mans count]);

                            rb_start_vpn_once(1);

                        }

                    };

                    ((void (*)(id, SEL, void (^)(NSArray *, NSError *)))objc_msgSend)(

                        C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

                }

            } @catch (NSException *e) { }

            rb_ne_watch_config(left - 1);

        }

    });

}



// v67：丢掉旧节点文件和保活快照 —— App 下次要连就会以新身份重新申请节点凭据。
// 快照也必须一起清，不然下一次 boot/卡连接兜底又会把它写回来，白丢一次。
static void rb_node_rotate(void) {

    @try {

        NSString *dir = rb_node_dir();

        NSFileManager *fm = [NSFileManager defaultManager];

        int n = 0;

        for (NSString *it in ([fm contentsOfDirectoryAtPath:dir error:NULL] ?: @[])) {

            if (!rb_is_node_file(it)) continue;

            if ([fm removeItemAtPath:[dir stringByAppendingPathComponent:it]

                               error:NULL]) n++;

        }

        NSMutableDictionary *st = rb_state();

        [st removeObjectForKey:RB_NODEFILES_KEY];

        [st removeObjectForKey:RB_PREFS_SNAP_KEY];

        rb_state_save(st);

        if (n == 0) {

            // v69：rb-shim(13) 日志实证 —— 没有节点文件的时候 rotate 仍然照停照拉，
            // 4 次下来把本来可能连上的隧道反复打断。没东西可删就别动隧道。
            rb_log("换节点：没有旧节点文件可丢（App 还没选定节点文件）—— 不动隧道");

            return;

        }

        rb_log("换节点：删掉 %d 个旧节点文件、清掉保活快照 —— "
               "App 下次连接会用新身份重新申请节点凭据（旧认证串是限速根因）", n);

        // v72：v69 在这里加了 rb_ne_drop_configs() —— rb-shim(14) 第 72 行
        // 「换节点：已删掉 1 个 VPN 配置」就是它，删完系统每次重建都弹
        // 「允许添加 VPN 配置」授权。配置一律不删、不动，铁律。

        rb_stop_vpn();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(RB_STOP_SETTLE_SEC * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{

            @autoreleasepool { rb_start_vpn_once(0); }

        });

        rb_node_watch_new(RB_NODE_WATCH_MAX);

    } @catch (NSException *e) {

        rb_log("换节点失败：%s", [[e reason] UTF8String]);

    }

}



// App 只有在你选了节点之后才会重写 currentNodeWithReason.bin。盯着这个文件：
// 一出现（说明选好了）就立刻拉起隧道，不用再回到 App 里点连接。
static void rb_node_watch_new(int left) {

    if (left <= 0) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(RB_NODE_WATCH_SEC * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            NSString *f = [rb_node_dir()

                           stringByAppendingPathComponent:@"currentNodeWithReason.bin"];

            NSDictionary *a = [[NSFileManager defaultManager]

                               attributesOfItemAtPath:f error:NULL];

            // v71：v70 日志第 64 行实锤的误判 —— 我们刚写回的文件立刻被当成
            // 「App 已选中新节点」，结果拿无授权的节点文件去连，直接吃到 160Kbps 档。
            // 只有文件内容跟我们写的不一样，才算 App 真的重新选过。
            if (a && [a fileSize] > 0) {

                NSData *cur = [NSData dataWithContentsOfFile:f];

                if (cur && gNodeWrote && [cur isEqualToData:gNodeWrote]) {

                    rb_node_watch_new(left - 1);

                    return;

                }

                rb_log("检测到 App 已选中新节点（%lu 字节），立刻拉起隧道",

                       (unsigned long)[a fileSize]);

                // 顺带把它存成快照，往后抹数据还能再救一次

                NSMutableDictionary *st = rb_state();

                NSMutableDictionary *pick =

                    [[[st objectForKey:RB_NODEFILES_KEY] mutableCopy] ?:

                     [NSMutableDictionary dictionary] autorelease];

                NSData *d = [NSData dataWithContentsOfFile:f];

                if (d) [pick setObject:d forKey:@"currentNodeWithReason.bin"];

                [st setObject:pick forKey:RB_NODEFILES_KEY];

                rb_state_save(st);

                gPostWipeWatchFired = 1;   // v73：告诉兜底别再插一手

                rb_start_vpn_once(1);

                return;

            }

            rb_node_watch_new(left - 1);

        }

    });

}



static int rb_wipe_all(void) {

    if (gWiping) return 0;

    gWiping = 1;



    NSFileManager *fm = [NSFileManager defaultManager];

    NSString *home = NSHomeDirectory();

    NSString *lib  = [home stringByAppendingPathComponent:@"Library"];

    double t0 = rb_now();



    NSArray *keepState = [NSArray arrayWithObjects:RB_STATE_FILE, RB_PREFS_FILE, nil];

    NSArray *keepDoc   = [NSArray arrayWithObjects:RB_LOG_NAME, nil];



    // v53：一律 deep（连子目录一起删）。v52 用 keepSubdirs=1 把

    // Caches / Application Support 里的子目录全跳过了，等于没抹。

    int nf = 0;

    nf += rb_clean_deep([home stringByAppendingPathComponent:@"Documents"], keepDoc);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"Caches"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"Application Support"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"Preferences"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"Cookies"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"HTTPStorages"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"Saved Application State"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"Splashboard"], nil);

    nf += rb_clean_deep([lib stringByAppendingPathComponent:@"WebKit"], nil);

    nf += rb_clean_deep([home stringByAppendingPathComponent:@"tmp"], nil);

    nf += rb_clean_deep([home stringByAppendingPathComponent:@"SystemData"], nil);

    nf += rb_clean(lib, keepState, 1);   // Library 根：只删散落文件，目录骨架留着



    @try {

        SEL sel = sel_registerName("containerURLForSecurityApplicationGroupIdentifier:");

        NSURL *gu = nil;

        if ([fm respondsToSelector:sel])

            gu = ((NSURL *(*)(id, SEL, id))objc_msgSend)(fm, sel, RB_GROUP_ID);

        if (gu) nf += rb_clean_deep([gu path], nil);

    } @catch (NSException *e) { }



    // v73：抹之前先把 keychain 全清单导出来（只读）。
    // 找的是「哪一项决定额度刷新、哪一项决定速度档位」—— 只有 1 项会被删，
    // 而 160Kbps 正好对上 Dart 里的 ISSUE_NODE_TOKEN_LICENSE_NOT_FOUND / EXPIRED。
    @try { rb_kc_dump(); } @catch (NSException *e) { }

    int nk = 0;

#if RB_WIPE_KEYCHAIN

    // 已经抹过 2 次还归零 → 说明保留的那一项里也有身份，这次连它一起清

    // v74：永久关掉（原来 >=2 次就全删）。rb-shim(16) 第 89/91 行实锤：
    // 第 3 次抹除把唯一那项 keychain 删了，而它正是 NE 配置引用的密码项
    // （rb-kc.txt svc=F6210F4B-... acct=E4D8CE0F-...），删完配置悬空，
    // startVPNTunnel 报成功但隧道起不来 —— 连不上、还要重新授权。
    int aggressive = 0;

    if (aggressive) rb_log("第 3 次抹除：本次连 VPN 配置引用的 keychain 项一起清");

    @try { nk = rb_kc_wipe(aggressive); }

    @catch (NSException *e) { rb_log("keychain 清理异常：%s", [[e reason] UTF8String]); }

#endif



    @try {

        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];

        if (bid) [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:bid];

        [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:@"flutter"];

        [[NSUserDefaults standardUserDefaults] synchronize];

        // App Group 的那份也清（Flutter 常把状态写在 group suite 里）

        NSUserDefaults *gd = [[NSUserDefaults alloc] initWithSuiteName:RB_GROUP_ID];

        if (gd) {

            if (bid) [gd removePersistentDomainForName:bid];

            [gd removePersistentDomainForName:RB_GROUP_ID];

            [gd synchronize];

            [gd release];

        }

    } @catch (NSException *e) { }



    // v68：这里**不再**立刻把旧节点写回去。
    // 旧 currentNodeWithReason.bin 带着旧账号签发的节点认证串，写回去就是
    // 「新额度 + 旧身份」——服务端按老账本压成福利限速（v66 日志：抹后 82 秒
    // 只跑 0.7MB、10.8 KB/s）。反过来，rb-shim(12) 第 10~14 行证明：没有节点
    // 文件时 App 会自己按服务端下发选节点，照样连得上、跑得出流量。
    // 快照仍然留着，只有真卡住（45 秒还在连接中）才由 bounce 兜底写回。

    rb_log("抹完是干净状态：不写回旧节点文件（旧认证串会被限速），"
           "由 App 用新身份自己选；真的连不上 45 秒后才兜底");

    // v70：这里**不删** VPN 配置。v69 试过删 —— 删掉之后系统每次都要弹
    // 「允许添加 VPN 配置」授权，每轮抹除多一次授权点击，比不删更糟。
    // 配置留着：节点选择、隧道参数都在，只是不碰它。



    rb_log("抹数据完成：删掉 %d 个文件/目录，keychain %d 项，耗时 %.2fs",

           nf, nk, rb_now() - t0);

    gWiping = 0;

    return nf;

}



#pragma mark - 自拉起



static void rb_relaunch(void);



static void rb_relaunch_try(int attempt) {

#if RB_RELAUNCH

    BOOL sent = NO;

    @try {

        Class ws = objc_getClass("LSApplicationWorkspace");

        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];

        id w = ws ? ((id (*)(id, SEL))objc_msgSend)(ws, sel_registerName("defaultWorkspace")) : nil;

        if (w && bid)

            sent = ((BOOL (*)(id, SEL, id))objc_msgSend)(

                       w, sel_registerName("openApplicationWithBundleID:"), bid);

    } @catch (NSException *e) { sent = NO; }



    if (sent) {

        rb_log("已请求自拉起，1.0 秒后退出（新进程 = 全新数据）");

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),

                       dispatch_get_main_queue(), ^{ exit(0); });

    } else if (attempt < 3) {

        // 刚抹完数据时系统偶尔会拒绝拉起，隔 2 秒再求一次，别让用户手动去点

        rb_log("自拉起第 %d 次被拒绝，2 秒后重试", attempt + 1);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),

                       dispatch_get_main_queue(), ^{ rb_relaunch_try(attempt + 1); });

    } else {

        // 拉不起来就绝不退出 —— 否则 App 直接消失，只能重装。

        rb_log("自拉起被拒绝（已试 %d 次），保持运行（数据已抹，需手动退出再打开一次）",

               attempt + 1);

    }

#else

    (void)attempt;

    rb_log("抹数据完成，RB_RELAUNCH=0：请手动退出并重新打开 App");

#endif

}



static void rb_relaunch(void) { rb_relaunch_try(0); }



#pragma mark - 自动连回 VPN



static void rb_auto_start_vpn(int attempt);



// NEVPNStatus：0 invalid / 1 disconnected / 2 connecting / 3 connected /

//              4 reasserting / 5 disconnecting

// v65：NEVPNManager.sharedManager 对这个 App 恒报 0（v62/v64 日志反复出现
// 「隧道状态 0，拉起一次」紧接着「配置自带状态 3，不动」）—— 两个判据自相矛盾，
// 结果看门狗每轮都白跑一次 start，而且**永远走不到 rb_bg_renew()**，
// 后台时间一次都没续过。改成扫真实的 NETunnelProviderManager 配置为准。

static volatile int    gRealStatus = -1;

static volatile double gRealStatusTs = 0;



static void rb_status_probe(void) {

    @try {

        Class C = objc_getClass("NETunnelProviderManager");

        if (!C) return;

        void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

            (void)err;

            int best = -1;

            for (id m in mans) {

                if (![m respondsToSelector:@selector(connection)]) continue;

                id conn = ((id (*)(id, SEL))objc_msgSend)(

                    m, sel_registerName("connection"));

                if (!conn || ![conn respondsToSelector:@selector(status)]) continue;

                int s = (int)((NSInteger (*)(id, SEL))objc_msgSend)(

                    conn, sel_registerName("status"));

                if (s > best) best = s;

            }

            if (best >= 0) { gRealStatus = best; gRealStatusTs = rb_now(); }

        };

        ((void (*)(id, SEL, id))objc_msgSend)(

            C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

    } @catch (NSException *e) { }

}



static int rb_vpn_status(void) {

    double age = rb_now() - gRealStatusTs;

    if (age > 4.0) rb_status_probe();          // 异步刷新，不阻塞

    if (gRealStatus >= 0 && age < 60.0) return gRealStatus;



    @try {

        Class C = objc_getClass("NEVPNManager");

        if (!C) return -1;

        id m = ((id (*)(id, SEL))objc_msgSend)(C, sel_registerName("sharedManager"));

        if (!m) return -1;

        id conn = ((id (*)(id, SEL))objc_msgSend)(m, sel_registerName("connection"));

        if (!conn) return -1;

        return (int)((NSInteger (*)(id, SEL))objc_msgSend)(

            conn, sel_registerName("status"));

    } @catch (NSException *e) { return -1; }

}



// 抹除之前先把隧道停掉：扩展进程还拿着旧身份在跑，一边清一边被它写回去，

// 清不干净也容易在抹的瞬间把状态写回沙箱。

static void rb_stop_vpn(void) {

    @try {

        Class C = objc_getClass("NETunnelProviderManager");

        if (!C) return;

        void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

            (void)err;

            for (id m in mans) {

                if (![m respondsToSelector:@selector(connection)]) continue;

                id conn = ((id (*)(id, SEL))objc_msgSend)(m, sel_registerName("connection"));

                if (conn && [conn respondsToSelector:@selector(stopVPNTunnel)])

                    ((void (*)(id, SEL))objc_msgSend)(conn, sel_registerName("stopVPNTunnel"));

            }

            rb_log("抹除前已请求停止 %lu 个隧道配置", (unsigned long)[mans count]);

        };

        ((void (*)(id, SEL, id))objc_msgSend)(

            C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

    } @catch (NSException *e) { }

}



// 忽略大小写找子串（iOS 的 strcasestr 不一定能直接用，自己写一个）

static int rb_has_lc(const char *hay, const char *needle) {

    if (!hay || !needle || !*needle) return 0;

    size_t ln = strlen(needle);

    for (const char *p = hay; *p; p++) {

        size_t k = 0;

        while (k < ln && p[k] &&

               tolower((unsigned char)p[k]) == tolower((unsigned char)needle[k])) k++;

        if (k == ln) return 1;

    }

    return 0;

}



// v57：不再信 respondsToSelector。

// v56 日志实证：同一个 manager 对 connection / setOnDemandEnabled: 都认，

// 但对 4 个 start 接口的 respondsToSelector 全部返回 NO（7 次重连全哑火）。

// 现在直接调 + @catch 兜底：真不认就是 unrecognized selector，catch 住换下一个，

// 行为等价但不会再漏；每个候选都把「认不认」打进日志，下次不用再猜。

static BOOL rb_ne_start(id m) {

    // v59：上一版已经确认「manager 上没有 start 接口，connection 上有」——

    // 那就别每次都先撞 4 次 unrecognized selector（v58 日志里刷了 8 行），

    // 记住结论，直接走管用的那一条。

    // 用 if 包住，不用 goto：C 里标签后面必须跟语句，不能直接跟声明

    if (!gUseConnStart) {



    struct { SEL sel; int kind; } cands[4];

    cands[0].sel = @selector(startVPNTunnelAndReturnError:);             cands[0].kind = 0;

    cands[1].sel = @selector(startVPNTunnelWithOptions:andReturnError:); cands[1].kind = 1;

    cands[2].sel = @selector(startVPNTunnel);                            cands[2].kind = 2;

    cands[3].sel = @selector(startVPNTunnel:);                           cands[3].kind = 3;



    for (int i = 0; i < 4 && !gMgrStartLogged; i++) {

        BOOL resp = [m respondsToSelector:cands[i].sel];

        NSError *e = nil;

        BOOL ok = NO;

        @try {

            if (cands[i].kind == 1) {

                ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(

                         m, cands[i].sel, (id)nil, &e);

            } else if (cands[i].kind == 0) {

                ok = ((BOOL (*)(id, SEL, NSError **))objc_msgSend)(m, cands[i].sel, &e);

            } else if (cands[i].kind == 2) {

                ((void (*)(id, SEL))objc_msgSend)(m, cands[i].sel);

                ok = YES;

            } else {

                ((void (*)(id, SEL, id))objc_msgSend)(m, cands[i].sel, (id)nil);

                ok = YES;

            }

        } @catch (NSException *ex) {

            rb_log("自动重连：manager 不认 %s（这台机器的 NEVPNManager 没有 start 接口，"

                   "改走 connection）", sel_getName(cands[i].sel));

            continue;

        }

        rb_log("自动重连：用 %s（responds=%d）→ %s%s", sel_getName(cands[i].sel),

               resp ? 1 : 0, ok ? "成功" : "失败",

               ok ? "" : [[NSString stringWithFormat:@"（%@）",

                           [e localizedDescription]] UTF8String]);

        // v60：manager 认这个接口但调失败了，也**不许**直接返回 ——

        // v57 那 7 次「全都失败」有一半是这个原因：manager 认了却返回 NO，

        // 于是永远轮不到下面 connection 那条真正管用的路径。

        // v61：成功就把「真的拉起过」记下来。之前只有 rb_start_vpn_once 里记，

        // 而自动重连那条链路（rb_auto_start_vpn）是直接调本函数的 ——

        // 于是 gLastStartTs 一直是 0，v60 日志第 52 行才会出现

        // 「距上次拉起 0 秒仍零流量 → 判假连接」，刚连上就被自己打断一次。

        if (ok) { gLastStartTs = rb_now(); return YES; }

    }

    if (!gMgrStartLogged) {

        gMgrStartLogged = 1;

        rb_log("自动重连：manager 上没有可用的 start 接口（只报一次，改走 connection）");

    }

    }   // if (!gUseConnStart)



    // v58：manager 上一个 start 接口都没有（v57 日志已证实：NEVPNManager 只剩

    // copyCurrentUserStartOptions / initWithGrade:connection:tunnelType: /

    // saveToPreferencesWithCompletionHandler:）。再对它的 connection 对象试一轮 ——

    // NEVPNConnection 是真正握着隧道的那个对象，启动接口可能在它身上。

    id conn = nil;

    if ([m respondsToSelector:@selector(connection)])

        conn = ((id (*)(id, SEL))objc_msgSend)(m, @selector(connection));

    if (!conn) return NO;

    struct { SEL sel; int kind; } cc[6];

    cc[0].sel = @selector(startVPNTunnelAndReturnError:);             cc[0].kind = 0;

    cc[1].sel = @selector(startVPNTunnelWithOptions:andReturnError:); cc[1].kind = 1;

    cc[2].sel = @selector(startVPNTunnel);                            cc[2].kind = 2;

    cc[3].sel = @selector(startTunnelWithOptions:andReturnError:);    cc[3].kind = 1;

    cc[4].sel = @selector(startTunnel);                               cc[4].kind = 2;

    cc[5].sel = @selector(start);                                     cc[5].kind = 2;

    for (int i = 0; i < 6; i++) {

        BOOL resp = [conn respondsToSelector:cc[i].sel];

        NSError *e = nil;

        BOOL ok = NO;

        @try {

            if (cc[i].kind == 1) {

                ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(

                         conn, cc[i].sel, (id)nil, &e);

            } else if (cc[i].kind == 0) {

                ok = ((BOOL (*)(id, SEL, NSError **))objc_msgSend)(conn, cc[i].sel, &e);

            } else {

                ((void (*)(id, SEL))objc_msgSend)(conn, cc[i].sel);

                ok = YES;

            }

        } @catch (NSException *ex) {

            rb_log("自动重连：connection.%s（responds=%d）抛异常 %s",

                   sel_getName(cc[i].sel), resp ? 1 : 0, [[ex reason] UTF8String]);

            continue;

        }

        rb_log("自动重连：用 connection.%s → %s%s", sel_getName(cc[i].sel),

               ok ? "成功" : "失败",

               ok ? "" : [[NSString stringWithFormat:@"（%@）",

                           [e localizedDescription]] UTF8String]);

        if (ok) { gUseConnStart = 1; gLastStartTs = rb_now(); }  // v61：同上

        return ok;

    }

    return NO;

}



// v58：把 NE 相关类的**全部**方法打出来（v57 只挑含 start/tunnel/vpn/save 的，

// 结果只看见 3 个方法，反而漏掉了真正可用的入口）。顺便把当前节点信息也打出来，

// 下一步做「自动挑最快节点」要靠它定位字段。

static void rb_ne_dump(id m) {

#if RB_NE_PROBE

    @try {

        Class cls = object_getClass(m);

        rb_log("诊断：配置对象类是 %s", cls ? class_getName(cls) : "(nil)");

        const char *names[] = {"NETunnelProviderManager", "NEVPNManager",

                               "NEVPNConnection", "NETunnelProviderSession"};

        for (int k = 0; k < 4; k++) {

            Class c = NSClassFromString([NSString stringWithUTF8String:names[k]]);

            if (!c) { rb_log("诊断：%s 不存在", names[k]); continue; }

            NSMutableString *s = [NSMutableString string];

            for (Class x = c; x && [s length] < 900; x = class_getSuperclass(x)) {

                unsigned n = 0;

                Method *ms = class_copyMethodList(x, &n);

                for (unsigned i = 0; i < n && [s length] < 900; i++)

                    [s appendFormat:@"%s ", sel_getName(method_getName(ms[i]))];

                if (ms) free(ms);

            }

            rb_log("诊断：%s 全部实例方法 → %s", names[k], [s UTF8String]);

        }

        // 当前连的是哪个节点：下一步做自动换节点要用

        id proto = nil;

        if ([m respondsToSelector:@selector(protocolConfiguration)])

            proto = [m valueForKey:@"protocolConfiguration"];

        if (!proto && [m respondsToSelector:@selector(protocol)])

            proto = [m valueForKey:@"protocol"];

        if (proto) {

            NSString *srv = nil;

            @try {

                if ([proto respondsToSelector:@selector(serverAddress)])

                    srv = [proto valueForKey:@"serverAddress"];

            } @catch (NSException *e) { }

            id pcfg = nil;

            @try {

                if ([proto respondsToSelector:@selector(providerConfiguration)])

                    pcfg = [proto valueForKey:@"providerConfiguration"];

            } @catch (NSException *e) { }

            rb_log("节点：server=%s  provider 键=%s",

                   srv ? [srv UTF8String] : "(读不到)",

                   pcfg ? [[NSString stringWithFormat:@"%@", pcfg] UTF8String] : "(无)");

        }

    } @catch (NSException *e) { }

#endif

}



static NSString *rb_printable(const uint8_t *b, size_t n) {
    NSMutableString *s = [NSMutableString string];
    size_t lim = n < 1024 ? n : 1024;
    for (size_t i = 0; i < lim; i++) {
        uint8_t c = b[i];
        if (c >= 32 && c < 127) [s appendFormat:@"%c", c];
        else if (c == 0) [s appendString:@"."];
    }
    return s;
}

static void rb_export_nodes(void) {
    @try {
        NSMutableString *out = [NSMutableString string];
        [out appendString:@"# rb-shim v76 节点导出\n"];
        NSFileManager *fmr = [NSFileManager defaultManager];
        NSString *home = NSHomeDirectory();
        NSArray *roots = [NSArray arrayWithObjects:
                          [home stringByAppendingPathComponent:@"Documents"],
                          [home stringByAppendingPathComponent:@"Library"], nil];
        NSArray *keys = [NSArray arrayWithObjects:@"node", @"server", @"config",
                         @"uuid", @"host", @"vmess", @"trojan", @"proxy", nil];
        int shown = 0;
        [out appendString:@"\n[沙盒候选文件]\n"];
        for (NSString *root in roots) {
            NSArray *items = [fmr subpathsOfDirectoryAtPath:root error:NULL];
            if (!items) continue;
            for (NSString *it in items) {
                if (shown >= 60) break;
                NSString *low = [it lowercaseString];
                int hit = 0;
                for (NSString *k in keys) {
                    NSRange rg = [low rangeOfString:k];
                    if (rg.location != NSNotFound) { hit = 1; break; }
                }
                if (!hit) continue;
                NSString *full = [root stringByAppendingPathComponent:it];
                NSDictionary *a = [fmr attributesOfItemAtPath:full error:NULL];
                unsigned long long sz = a ? [a fileSize] : 0;
                [out appendFormat:@"\n--- %@ (%llu 字节) ---\n", it, sz];
                if (sz > 0 && sz < (1LL << 20)) {
                    NSData *d = [NSData dataWithContentsOfFile:full];
                    if (d && [d length] > 0)
                        [out appendFormat:@"%@\n", rb_printable((const uint8_t *)[d bytes],
                                                                 (size_t)[d length])];
                }
                shown++;
            }
        }
        NSString *path = [home stringByAppendingPathComponent:@"Documents/rb-nodes.txt"];
        [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        rb_log("节点导出：已写 Documents/rb-nodes.txt（%d 个候选文件，%lu 字节）",
               shown, (unsigned long)[out length]);
    } @catch (NSException *e) {
        rb_log("节点导出失败：%s", [[e reason] UTF8String]);
    }
}

#pragma mark - 节点测速（v64）



// 对节点 IP 做一次 TCP 握手，返回耗时（毫秒）；连不上返回 -1。

// 这是「哪个节点最快」的第一手数据：同一台手机、同一个网络下量的。

static double rb_tcp_rtt(const char *ip, int port) {

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) return -1.0;



    struct timeval tv;

    tv.tv_sec = 2; tv.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));



    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));

    sa.sin_family = AF_INET;

    sa.sin_port = htons((unsigned short)port);

    sa.sin_addr.s_addr = inet_addr(ip);



    struct timeval t0, t1;

    gettimeofday(&t0, NULL);

    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));

    gettimeofday(&t1, NULL);

    close(fd);

    if (r != 0) return -1.0;

    return (double)(t1.tv_sec - t0.tv_sec) * 1000.0

         + (double)(t1.tv_usec - t0.tv_usec) / 1000.0;

}



// 从抓到的服务端报文（Documents/rb-big/*.bin）里提节点 IP，量一遍延迟，

// 排行写进 rb-nodes.txt + 日志。后台线程跑，最多 16 个 × 2 秒。

static void rb_node_speedtest(void) {

    @try {

        // v65：rb-big 经常是空的（本次就没抓到 >32KB 的报文），真正的节点在
        // Library/Application Support/RelyVPN/currentNodeWithReason.bin 里。
        // 两个目录一起扫，哪个有就用哪个。

        NSString *bigDir = [NSHomeDirectory()

                            stringByAppendingPathComponent:@"Documents/rb-big"];

        NSFileManager *fm = [NSFileManager defaultManager];

        NSMutableArray *files = [NSMutableArray array];

        NSArray *a1 = [fm contentsOfDirectoryAtPath:bigDir error:NULL];

        if (a1) for (NSString *it in a1)

            [files addObject:[bigDir stringByAppendingPathComponent:it]];

        NSArray *a2 = [fm subpathsOfDirectoryAtPath:rb_node_dir() error:NULL];

        if (a2) for (NSString *it in a2) {

            NSString *low = [it lowercaseString];

            if ([low hasSuffix:@".bin"] || [low hasSuffix:@".json"] ||

                [low hasSuffix:@".txt"] || [low hasSuffix:@".dat"])

                [files addObject:[rb_node_dir() stringByAppendingPathComponent:it]];

        }

        if ([files count] == 0) {

            rb_log("节点测速：还没抓到节点报文（rb-big 与节点目录都为空），跳过");

            return;

        }



        NSMutableSet *ips = [NSMutableSet set];

        NSRegularExpression *re =

            [NSRegularExpression regularExpressionWithPattern:

                @"(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})"

                                                      options:0 error:NULL];

        if (!re) return;

        for (NSString *full in files) {

            NSData *d = [NSData dataWithContentsOfFile:full];

            if (!d || [d length] == 0) continue;

            NSString *s = rb_printable((const uint8_t *)[d bytes],

                                       (size_t)([d length] > (1 << 20) ?

                                                (1 << 20) : [d length]));

            NSArray *ms = [re matchesInString:s options:0

                                       range:NSMakeRange(0, [s length])];

            for (NSTextCheckingResult *m in ms) {

                @autoreleasepool {

                    int o[4];

                    BOOL ok = YES;

                    for (int i = 0; i < 4; i++) {

                        NSRange rg = [m rangeAtIndex:i + 1];

                        NSString *p = [s substringWithRange:rg];

                        o[i] = [p intValue];

                        if (o[i] > 255) ok = NO;

                    }

                    if (!ok) continue;

                    if (o[0] == 0 || o[0] == 10 || o[0] == 127 ||

                        o[0] == 192 || o[0] == 172 || o[0] == 255) continue;

                    [ips addObject:[NSString stringWithFormat:@"%d.%d.%d.%d",

                                    o[0], o[1], o[2], o[3]]];

                }

            }

            if ([ips count] >= 40) break;

        }



        NSArray *list = [[ips allObjects]

                         sortedArrayUsingSelector:@selector(compare:)];

        if ([list count] == 0) {

            rb_log("节点测速：报文里没解析出节点 IP");

            return;

        }

        NSArray *arr = ([list count] > 16)

                     ? [list subarrayWithRange:NSMakeRange(0, 16)] : list;



        rb_log("节点测速：对 %lu 个节点做 TCP 握手测延迟…",

               (unsigned long)[arr count]);



        dispatch_async(dispatch_get_global_queue(

                           DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{

            @autoreleasepool {

                NSMutableArray *res = [NSMutableArray array];

                for (NSString *ip in arr) {

                    double ms = rb_tcp_rtt([ip UTF8String], 443);

                    [res addObject:[NSDictionary dictionaryWithObjectsAndKeys:

                                    ip, @"ip",

                                    [NSNumber numberWithDouble:ms], @"ms", nil]];

                }

                NSArray *srt = [res sortedArrayUsingComparator:

                    ^NSComparisonResult(id a, id b) {

                        double x = [[a objectForKey:@"ms"] doubleValue];

                        double y = [[b objectForKey:@"ms"] doubleValue];

                        if (x < 0) x = 1e9;

                        if (y < 0) y = 1e9;

                        if (x < y) return NSOrderedAscending;

                        if (x > y) return NSOrderedDescending;

                        return NSOrderedSame;

                    }];



                NSMutableString *out = [NSMutableString string];

                [out appendString:@"\n[节点 TCP 延迟排行（越低越快）]\n"];

                int i = 0;

                NSMutableString *top = [NSMutableString string];

                for (NSDictionary *r in srt) {

                    double ms = [[r objectForKey:@"ms"] doubleValue];

                    NSString *ip = [r objectForKey:@"ip"];

                    i++;

                    if (i <= 10) {

                        if (ms < 0)

                            [out appendFormat:@"%2d. %-16s 连不上\n", i,

                                              [ip UTF8String]];

                        else

                            [out appendFormat:@"%2d. %-16s %6.0f ms\n", i,

                                              [ip UTF8String], ms];

                    }

                    if (i <= 3 && ms >= 0)

                        [top appendFormat:@"%@(%.0fms) ", ip, ms];

                    if (i >= [srt count]) break;

                }

                NSString *path = [NSHomeDirectory()

                    stringByAppendingPathComponent:@"Documents/rb-nodes.txt"];

                NSString *old = [NSString stringWithContentsOfFile:path

                                                         encoding:NSUTF8StringEncoding

                                                            error:NULL];

                NSMutableString *all = [NSMutableString string];

                if (old) [all appendString:old];

                [all appendString:out];

                [all writeToFile:path atomically:YES

                        encoding:NSUTF8StringEncoding error:NULL];



                if ([top length])

                    rb_log("节点测速完成，最快的三个：%s", [top UTF8String]);

                else

                    rb_log("节点测速完成：全部连不上（可能被网络挡了）");

            }

        });

    } @catch (NSException *e) {

        rb_log("节点测速失败：%s", [[e reason] UTF8String]);

    }

}



static volatile int gSharedLogged = 0;
static void rb_ne_sync_shared(void) {
    @try {
        Class C = objc_getClass("NEVPNManager");
        if (!C) return;
        id sm = ((id (*)(id, SEL))objc_msgSend)(C, sel_registerName("sharedManager"));
        if (!sm) return;
        void (^blk)(NSError *) = ^(NSError *e) {
            (void)e;
            @try {
                id proto = nil;
                if ([sm respondsToSelector:@selector(protocolConfiguration)])
                    proto = [sm valueForKey:@"protocolConfiguration"];
                if (!proto) {
                    if (!gSharedLogged) {
                        gSharedLogged = 1;
                        rb_log("App 界面同步：sharedManager 没有协议配置，跳过");
                    }
                    return;
                }
                id conn = nil;
                if ([sm respondsToSelector:@selector(connection)])
                    conn = ((id (*)(id, SEL))objc_msgSend)(sm, sel_registerName("connection"));
                if (!conn) return;
                NSError *e2 = nil;
                BOOL ok = NO;
                @try {
                    ok = ((BOOL (*)(id, SEL, NSError **))objc_msgSend)(
                             conn, sel_registerName("startVPNTunnelAndReturnError:"), &e2);
                } @catch (NSException *ex) {
                    if (!gSharedLogged) {
                        gSharedLogged = 1;
                        rb_log("App 界面同步：sharedManager 不认 start");
                    }
                    return;
                }
                if (!gSharedLogged) {
                    gSharedLogged = 1;
                    rb_log("App 界面同步：sharedManager 也拉了一次 → %s",
                           ok ? "成功" : "失败");
                }
            } @catch (NSException *ex2) { }
        };
        ((void (*)(id, SEL, id))objc_msgSend)(
            sm, sel_registerName("loadFromPreferencesWithCompletionHandler:"), blk);
    } @catch (NSException *e) { }
}

// 真正去拉起一次隧道（v56 抽出来给「自动连接」看门狗和抹后重连共用）

static void rb_start_vpn_once(int force) {

    // v58：开关关着就别拉。上一版日志里 pid 17319 / 17951 明明写着

    // 「自动连接开关：关」，却还在第 1~7 次自动重连 —— 那 7 次全是白跑。

    if (!force && !rb_auto_on()) {

        rb_log("自动连接已关，不主动拉隧道（要连就点悬浮球 → 重连）");

        return;

    }

    // v60：人工介入（面板「重连」/ 开关打开 / 抹后重连）＝ 重新武装，

    // 清掉假连接的封顶计数和冷却，不然点了也没反应。

    if (force) { gFakeFixCount = 0; gFakeFixCoolUntil = 0; gFakeFixCoolLog = 0; }

    // v60：尝试也限流。start 一直失败时 gLastStartTs 不刷新，看门狗 12 秒进来一次

    // 会每次都撞 6 个 connection 候选刷 6 行日志。RB_RECONNECT_GAP 秒内只试一次。

    if (!force && gLastTryTs > 0 && rb_now() - gLastTryTs < RB_RECONNECT_GAP) return;

    gLastTryTs = rb_now();

    // v60：假连接封顶后正在冷却 → 这段时间一次都不拉（就是它防止死循环的）

    // v74：抹完 25 秒内不主动拉。rb-shim(16) 第 43→46→47 行：抹后 4 秒就拉，
    // 抢在 App 前面；那时配置还没建好/密码项刚被删，start 假成功，状态卡 1/3。
    // 这 25 秒留给 App 自己（它被自拉起后会重写节点文件并建配置）。
    if (!force) {

        double lw = [[rb_state() objectForKey:@"lastWipeTs"] doubleValue];

        if (lw > 0 && rb_now() - lw < RB_POST_WIPE_QUIET) {

            if (!gQuietLogged) {

                gQuietLogged = 1;

                rb_log("抹后静默期：%.0f 秒内不抢先拉隧道，等 App 自己建配置连",
                       RB_POST_WIPE_QUIET);

            }

            return;

        }

    }

    if (!force && gFakeFixCoolUntil > 0 && rb_now() < gFakeFixCoolUntil) {

        if (!gFakeFixCoolLog) {

            gFakeFixCoolLog = 1;

            rb_log("自动连接：假连接已连续处理 %d 次仍不通，冷却到 %.0f 秒后（"

                   "这期间不再拉，避免死循环）", RB_FAKE_FIX_MAX,

                   gFakeFixCoolUntil - rb_now());

        }

        return;

    }

    @try {

        Class C = objc_getClass("NETunnelProviderManager");

        if (!C) { rb_log("自动连接：拿不到 NETunnelProviderManager"); return; }

        // v60：这里**不能**刷新 gLastStartTs。看门狗每 12 秒就进来一次，

        // 一进来就刷新 → 「距上次拉起」永远只有十几秒 → 稳定期永远不过 →

        // 既不会再判假连接，也不会真的再去 start。现在只在真的发出 start 时才记。

        void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

            (void)err;

            int vs = rb_vpn_status();

            if (vs == 2 || vs == 3 || vs == 4) return;     // 已经在连了

            if ([mans count] == 0) {

                rb_log("自动连接：一个 VPN 配置都没有（数据刚抹干净）");

                return;

            }

            for (id m in mans) {

                // v62：节点快照恢复。App 抹完数据后记不住「当前节点」，

                // 自动重连会用空节点配置 → 卡「正在连接」转圈。这里每次重连前

                // 校验一次（30 秒节流）：配置和抹前快照不一样就写回去再拉。

                {

                    NSDictionary *snap = [rb_state() objectForKey:RB_NODE_SNAP_KEY];

                    if ([snap isKindOfClass:[NSDictionary class]] &&

                        [snap count] > 0 &&

                        rb_now() - gNodeSnapTs > RB_NODE_RECHECK) {

                        gNodeSnapTs = rb_now();

                        id protoS = nil;

                        if ([m respondsToSelector:@selector(protocolConfiguration)])

                            protoS = [m valueForKey:@"protocolConfiguration"];

                        if (!protoS && [m respondsToSelector:@selector(protocol)])

                            protoS = [m valueForKey:@"protocol"];

                        id curS = nil;

                        @try {

                            if ([protoS respondsToSelector:@selector(providerConfiguration)])

                                curS = [protoS valueForKey:@"providerConfiguration"];

                        } @catch (NSException *eS) { }

                        BOOL same = ([curS isKindOfClass:[NSDictionary class]] &&

                                     [(NSDictionary *)curS isEqualToDictionary:snap]);

                        if (!same) {

                            if ([protoS respondsToSelector:@selector(setProviderConfiguration:)])

                                ((void (*)(id, SEL, id))objc_msgSend)(

                                    protoS, sel_registerName("setProviderConfiguration:"),

                                    snap);

                            if ([m respondsToSelector:@selector(

                                    saveToPreferencesWithCompletionHandler:)]) {

                                rb_log("节点恢复：当前节点配置和抹前快照不一致，写回快照"

                                       "（%lu 个键）再拉",

                                       (unsigned long)[snap count]);

                                // 顺手把键名打出来 —— 下一步做「自动挑最快节点」

                                // 就靠它定位节点字段

                                NSMutableString *ks = [NSMutableString string];

                                for (NSString *kk in snap) {

                                    id vv = [snap objectForKey:kk];

                                    if ([vv isKindOfClass:[NSString class]])

                                        [ks appendFormat:@"%@=\"%@\" ", kk, vv];

                                    else if ([vv isKindOfClass:[NSData class]])

                                        [ks appendFormat:@"%@=<data %lu> ", kk,

                                            (unsigned long)[(NSData *)vv length]];

                                    else if ([vv isKindOfClass:[NSDictionary class]])

                                        [ks appendFormat:@"%@=<dict %lu> ", kk,

                                            (unsigned long)[(NSDictionary *)vv count]];

                                    else

                                        [ks appendFormat:@"%@=%@ ", kk, vv];

                                }

                                if ([ks length] > 600)

                                    [ks deleteCharactersInRange:

                                        NSMakeRange(600, [ks length] - 600)];

                                rb_log("节点快照内容：%s", [ks UTF8String]);

                                ((void (*)(id, SEL, id))objc_msgSend)(

                                    m, sel_registerName(

                                        "saveToPreferencesWithCompletionHandler:"),

                                    ^(NSError *e4) {

                                        rb_log("节点恢复：写回%s%s",

                                               e4 ? "失败：" : "成功",

                                               e4 ? [[e4 localizedDescription]

                                                     UTF8String] : "");

                                        dispatch_after(dispatch_time(

                                            DISPATCH_TIME_NOW,

                                            (int64_t)(0.8 * NSEC_PER_SEC)),

                                            dispatch_get_main_queue(), ^{

                                            @autoreleasepool {

                                                rb_start_vpn_once(force);

                                            }

                                            });

                                    });

                                return;

                            }

                        }

                    }

                }

                // NEVPNManager.sharedManager 对这个 App 的隧道一直报 0（invalid），

                // 所以这里再读一次每个配置自己的 connection.status。

                // v57：不再无条件信它 —— v56 日志实锤，utun 全程 0.1MB 的同时

                // 配置自带状态一直报 2/3，其实隧道早死了，「不动」等于永远连不上。

                // 真连着的隧道有 keepalive 流量；45 秒零流量就是假连接，强制重连。

                int st2 = -1;

                if ([m respondsToSelector:@selector(connection)]) {

                    id conn = ((id (*)(id, SEL))objc_msgSend)(

                        m, sel_registerName("connection"));

                    if (conn && [conn respondsToSelector:@selector(status)])

                        st2 = (int)((NSInteger (*)(id, SEL))objc_msgSend)(

                            conn, sel_registerName("status"));

                }

                if (st2 == 2 || st2 == 3 || st2 == 4) {

                    BOOL fresh = (gLastTrafficTs > 0 &&

                                  rb_now() - gLastTrafficTs < 45.0);

                    // v66：fresh 免检只许用在「已连接(3)」上。
                    // v65 日志 117 行实锤：状态 2 卡死转圈时 gLastTrafficTs
                    // 一直被刷新，fresh 恒真 -> 永远「不动」-> 卡转圈。
                    if (fresh && st2 == 3) {

                        rb_log("自动连接：已连接且有流量（45 秒内），不动");

                        return;

                    }

                    if (fresh && st2 != 3) {

                        rb_log("自动连接：状态 %d 不是已连接，有流量也不免检，走卡死判定", st2);

                    }

                    // v59：刚拉起来的隧道必须先给它稳定时间。

                    // utun 建起来、握手、开始转发都要秒级甚至十几秒，这段时间

                    // 本来就是零流量。v58 就死在这里：拉起 → 12 秒后判「零流量假连接」

                    // → 停 → 再拉 → 再判 → 无限循环（用户看到的就是「卡死」）。

                    double since = (gLastStartTs > 0) ? (rb_now() - gLastStartTs) : 0;

                    if (gLastStartTs <= 0) {

                        // v61：一次都还没真的拉起过，先去拉，不许判假连接。

                        // v60 日志第 52 行就是栽在这：自动重连那条链路直接调

                        // rb_ne_start，没回写 gLastStartTs，于是它一直是 0 →

                        // 「距上次拉起 0 秒仍零流量」→ 刚连上的隧道被自己停掉一次。

                        rb_log("自动连接：还没真的拉起过，先拉一次（这轮不判假连接）");

                    } else if (since < RB_START_SETTLE_SEC) {

                        rb_log("自动连接：刚拉起 %.0f 秒，等它稳定（%.0f 秒内不判假连接）",

                               since, (double)RB_START_SETTLE_SEC);

                        return;

                    } else if (st2 == 2 && since < RB_START_STUCK_SEC) {

                        // 状态 2 = 正在连接，本来就没流量；超过卡死线才算真卡住

                        rb_log("自动连接：连接中已 %.0f 秒（%.0f 秒内不打断），继续等",

                               since, (double)RB_START_STUCK_SEC);

                        return;

                    } else {

                    // v60：封顶。连续处理 RB_FAKE_FIX_MAX 次还不通，说明不是

                    // 「假连接」这么简单（多半是节点/账号本身不通），歇一会儿再说，

                    // 绝不允许像 v58 那样「停→拉→判→停」转成一圈接一圈的死循环。

                    if (gFakeFixCount >= RB_FAKE_FIX_MAX) {

                        // v75：冷却没用 —— 截图实锤（体验餐剩 11.6 MB 还在
                        // 「连接超时」），授权串失效时怎么 start 都过不了握手。
                        // 直接自拉起重启：新进程重新注册/申请授权，最可靠。
                        rb_log("自动连接：假连接已连续 %d 次仍不通（额度可能还没用完）"
                               " —— v75 直接自拉起重启 App，重新走注册/授权",
                               RB_FAKE_FIX_MAX);

                        rb_relaunch();

                        return;

                        gFakeFixCoolUntil = rb_now() + RB_FAKE_FIX_COOL;

                        gFakeFixCoolLog = 0;

                        gFakeFixCount = 0;

                        rb_log("自动连接：假连接已连续处理 %d 次仍不通，冷却 %.0f 秒"

                               "（不再死循环；要马上试就点悬浮球 → 重连）",

                               RB_FAKE_FIX_MAX, (double)RB_FAKE_FIX_COOL);

                        return;

                    }

                    gFakeFixCount++;

                    rb_log("自动连接：配置自带状态 %d、距上次拉起 %.0f 秒仍零流量 —— "

                           "判定假连接（第 %d/%d 次），先补节点文件，%.1f 秒后重拉",

                           st2, since, gFakeFixCount, RB_FAKE_FIX_MAX,

                           (double)RB_STOP_SETTLE_SEC);

                    // v66：bounce 前把节点文件补齐 —— provider 重拉时要读它，

                    // 文件不在就永远卡「连接中」（v65 日志 101->105 行顺序实锤）

                    // v68：这一步是「App 自己选不上」时的兜底，写回的是旧节点，

                    // 有被限速的风险 —— 所以日志里写清楚，别再当成正常路径。

                    if (rb_node_files_restore_direct()) {

                        rb_log("兜底：补回旧节点文件（App 自己没选上）。旧节点带旧认证串，"
                               "若被限速会触发上面的「节点体检」自动丢掉换新");

                    }

                    rb_stop_vpn();

                    // v60：stop 是异步的（要等 loadAllFromPreferences 回调才真停），

                    // 这里同步紧跟一个 start 会被 NE 状态机直接拒掉 ——

                    // 这就是「明明调了 start 成功、隧道却一直起不来」的另半个原因。

                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,

                                                 (int64_t)(RB_STOP_SETTLE_SEC * NSEC_PER_SEC)),

                                   dispatch_get_main_queue(), ^{

                        @autoreleasepool { rb_start_vpn_once(0); }

                    });

                    return;

                    }   // else（真的该判假连接）

                }

                if (rb_ne_start(m)) {

                    // v60：只有真的把 start 发出去了才算一次「拉起」，稳定期从这里起算

                    gLastStartTs = rb_now();

                    rb_ne_sync_shared();
                    return;

                }

                rb_ne_dump(m);

            }

        };

        ((void (*)(id, SEL, id))objc_msgSend)(

            C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

    } @catch (NSException *e) {

        rb_log("自动连接异常：%s", [[e reason] UTF8String]);

    }

}



// on-demand 常连：给配置装一条 NEOnDemandRuleConnect，之后连不连由 iOS 管，

// App 被挂起甚至被杀掉，系统自己也会把隧道接回去。这是「一直保持连接」最稳的一条。

static void rb_set_ondemand(BOOL on) {

#if RB_ONDEMAND_CONNECT

    @try {

        Class C = objc_getClass("NETunnelProviderManager");

        if (!C) return;

        void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

            (void)err;

            for (id m in mans) {

                if (on) {

                    Class rc = NSClassFromString(@"NEOnDemandRuleConnect");

                    id rule = rc ? [[rc alloc] init] : nil;

                    if (rule && [m respondsToSelector:@selector(setOnDemandRules:)])

                        ((void (*)(id, SEL, id))objc_msgSend)(

                            m, sel_registerName("setOnDemandRules:"),

                            [NSArray arrayWithObject:rule]);

                    if (rule) [rule release];

                    if ([m respondsToSelector:@selector(setOnDemandEnabled:)])

                        ((void (*)(id, SEL, BOOL))objc_msgSend)(

                            m, sel_registerName("setOnDemandEnabled:"), YES);

                    if ([m respondsToSelector:@selector(setEnabled:)])

                        ((void (*)(id, SEL, BOOL))objc_msgSend)(

                            m, sel_registerName("setEnabled:"), YES);

                } else if ([m respondsToSelector:@selector(setOnDemandEnabled:)]) {

                    ((void (*)(id, SEL, BOOL))objc_msgSend)(

                        m, sel_registerName("setOnDemandEnabled:"), NO);

                }

                if (![m respondsToSelector:@selector(saveToPreferencesWithCompletionHandler:)])

                    continue;

                ((void (*)(id, SEL, id))objc_msgSend)(

                    m, sel_registerName("saveToPreferencesWithCompletionHandler:"),

                    ^(NSError *e2) {

                        rb_log("on-demand 设为%s：%s%s", on ? "开" : "关",

                               e2 ? "失败" : "成功",

                               e2 ? [[NSString stringWithFormat:@"（%@）",

                                      [e2 localizedDescription]] UTF8String] : "");

                    });

            }

        };

        ((void (*)(id, SEL, id))objc_msgSend)(

            C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

    } @catch (NSException *e) { }

#endif

}



// v54：加日志、先停再起、enabled=NO 的先打开、失败多试几次。

// 上一版用户反馈「不会自动重连，要我自己连」，而这版的日志里连一行

// 「自动重连（第 N 次）」都没有 —— 进程在 3 秒延时到期前就没了（见 rb_clean_deep

// 里对启动崩溃的说明）。崩溃修好后这条路才跑得到。

// v56：start 改成 rb_ne_start（挨个试所有可能的启动接口），失败就 rb_ne_dump。

static void rb_auto_start_vpn(int attempt) {

#if RB_AUTO_RECONNECT

    // v58：开关关着就别重试 7 次刷屏（v57 日志里「自动连接开关：关」之后

    // 还是第 1~7 次自动重连全跑了一遍）

    if (!rb_auto_on()) {

        rb_log("自动连接已关，跳过自动重连");

        return;

    }

    if (gNoStartApi) {

        // 已经证明这台机器的 NE 没有任何可用 start 接口，再试也是刷日志

        if (!gNoStartLogged) {

            gNoStartLogged = 1;

            rb_log("自动重连：本设备的 NetworkExtension 没有可用的 start 接口，"

                   "自动拉起这条路由走不通（连接请在 App 里点一次，或看日志里的诊断方法清单）");

        }

        return;

    }

    if (attempt > RB_RECONNECT_TRIES) return;

    double delay = (attempt == 0) ? 3.0 : 2.5;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            @try {

                Class C = objc_getClass("NETunnelProviderManager");

                if (!C) { rb_log("自动重连：拿不到 NETunnelProviderManager"); return; }

                int cur = rb_vpn_status();

                rb_log("自动重连（第 %d 次）：当前 VPN 状态 %d", attempt + 1, cur);

                if (cur == 2 || cur == 3 || cur == 4) {

                    rb_log("自动重连：已经在连了，不动");

                    return;

                }

                void (^h)(NSArray *, NSError *) = ^(NSArray *mans, NSError *err) {

                    (void)err;

                    rb_log("自动重连：读到 %lu 个配置", (unsigned long)[mans count]);

                    rb_ne_dump_cfg(mans);   // v72：只读导出，不动配置

                    // v55 崩溃根因：NETunnelProviderManager 本身**没有** status 方法

                    // （status 在 NEVPNConnection 上）。给 manager 直接发 status 就是

                    // unrecognized selector → 进程立刻死。v53/v54 日志里「读到 1 个配置」

                    // 之后再无输出、紧接着就是下一次启动，就是死在这一行。

                    // 现在统一用 rb_vpn_status()（读 connection.status）。

                    int vs2 = rb_vpn_status();

                    if (vs2 == 2 || vs2 == 3 || vs2 == 4) {

                        rb_log("自动重连：隧道已在连接中(status=%d)，不动", vs2);

                        return;

                    }

                    for (id m in mans) {

                        if (rb_ne_start(m)) return;



                        // 启动不了：很可能是配置被关掉了（isEnabled=NO），

                        // 打开并保存一次再试；还不行就把这个类的方法全打进日志。

                        BOOL en = YES;

                        if ([m respondsToSelector:@selector(isEnabled)])

                            en = ((BOOL (*)(id, SEL))objc_msgSend)(

                                m, sel_registerName("isEnabled"));

                        if (!en &&

                            [m respondsToSelector:@selector(setEnabled:)] &&

                            [m respondsToSelector:@selector(saveToPreferencesWithCompletionHandler:)]) {

                            rb_log("自动重连：配置 isEnabled=NO，打开保存后再启动");

                            ((void (*)(id, SEL, BOOL))objc_msgSend)(

                                m, sel_registerName("setEnabled:"), YES);

                            ((void (*)(id, SEL, id))objc_msgSend)(

                                m, sel_registerName("saveToPreferencesWithCompletionHandler:"),

                                ^(NSError *e2) {

                                    (void)e2;

                                    if (!rb_ne_start(m) && attempt < RB_RECONNECT_TRIES)

                                        rb_auto_start_vpn(attempt + 1);

                                });

                            return;

                        }

                        if (!gNoStartApi) {

                            gNoStartApi = 1;      // manager 和 connection 都不认 start

                            rb_ne_dump(m);        // 只打一次全量方法清单，够定位了

                        }

                        if (attempt < RB_RECONNECT_TRIES) rb_auto_start_vpn(attempt + 1);

                        return;

                    }

                    if ([mans count] == 0)

                        rb_log("自动重连：一个配置都没有（数据刚抹干净，需要你在 App 里连一次）");

                    if (attempt < RB_RECONNECT_TRIES) rb_auto_start_vpn(attempt + 1);

                };

                ((void (*)(id, SEL, id))objc_msgSend)(

                    C, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"), h);

            } @catch (NSException *e) {

                rb_log("自动重连异常：%s", [[e reason] UTF8String]);

            }

        }

    });

#endif

}



#pragma mark - 流量判据（直接读 utun 走了多少字节）



static void rb_fire(const char *why, BOOL force);   // 定义在下面，先声明

static void rb_tick(void);                          // 手动扳机 / 兜底循环



// getifaddrs 在 iOS 上能列出 utun 接口并给出 ifi_ibytes / ifi_obytes，

// 这就是隧道真实走过的字节数。额度就是流量，这条比猜报文格式稳得多。

// 一个接口在链表里会出现多次（IPv4/IPv6 各一条），按名字去重。

static uint64_t rb_utun_bytes(void) {

    struct ifaddrs *ifa0 = NULL;

    if (getifaddrs(&ifa0) != 0) return 0;

    uint64_t total = 0;

    char seen[8][16];

    int nseen = 0;

    for (struct ifaddrs *p = ifa0; p; p = p->ifa_next) {

        if (!p->ifa_name || !p->ifa_data) continue;

        if (strncmp(p->ifa_name, "utun", 4) != 0) continue;

        int dup = 0;

        for (int k = 0; k < nseen; k++)

            if (strncmp(seen[k], p->ifa_name, 15) == 0) { dup = 1; break; }

        if (dup || nseen >= 8) continue;

        snprintf(seen[nseen++], 16, "%s", p->ifa_name);

        struct if_data *d = (struct if_data *)p->ifa_data;

        total += (uint64_t)d->ifi_ibytes + (uint64_t)d->ifi_obytes;

    }

    freeifaddrs(ifa0);

    return total;

}



static uint64_t rb_quota_limit(void) {

    return (uint64_t)((double)RB_QUOTA_BYTES * RB_FLOW_FACTOR);

}



// 抹完 / 首次安装：把基线拨到当前读数值，累计清零

static void rb_flow_rebase(void) {

    NSMutableDictionary *st = rb_state();

    [st setObject:[NSNumber numberWithUnsignedLongLong:rb_utun_bytes()] forKey:@"flowBase"];

    [st setObject:[NSNumber numberWithUnsignedLongLong:0] forKey:@"flowAcc"];

    rb_state_save(st);

    gFlowAcc = 0;

    gSlowSec = 0;          // v61：限速计时也一起清

    gThrottleHit = 0;

    gFlowRebuilds = 0;

}



static void rb_flow_tick(void);



static void rb_flow_tick(void) {

#if RB_FLOW_ENABLED

    if (gStopped) return;

    @autoreleasepool {

        uint64_t cur = rb_utun_bytes();

        NSMutableDictionary *st = rb_state();

        uint64_t base = [[st objectForKey:@"flowBase"] unsignedLongLongValue];

        uint64_t acc  = [[st objectForKey:@"flowAcc"] unsignedLongLongValue];

        // v61：这里就是「流量监测不对劲」的根因。

        // 旧写法 `if (cur < base) base = cur;` —— utun 一重建（每次隧道重连、

        // 每次 App 重启 VPN、别的 utun 消失）读数就掉回 0，累计跟着被清零，

        // 于是怎么跑都攒不到 285MB，流量判据永远不触发。

        // 现在：重建时把新接口已经跑掉的 cur 照记进累计，只是不让它倒扣。

        uint64_t delta = 0;

        if (cur >= base) {

            delta = cur - base;

        } else {

            // 读数倒退 = 接口集合变了。新接口从 0 涨到 cur，这部分是真流量

            delta = cur;

            gFlowRebuilds++;

            rb_log("流量：utun 读数倒退 %.1f → %.1f MB（第 %d 次重建），"

                   "把新接口的 %.1f MB 计入累计，不再清零",

                   base / 1048576.0, cur / 1048576.0, gFlowRebuilds,

                   cur / 1048576.0);

        }

        if (delta > (uint64_t)RB_FLOW_MAX_STEP) {

            // 一个采样周期不可能跑这么多 —— 多半是别的 utun 加进来把总数抬高了，

            // 这种跳变不计入，否则累计会假爆表、白白抹一次

            rb_log("流量：本次跳变 %.1f MB 超过单周期上限 %.1f MB，判为接口变化，不计入",

                   delta / 1048576.0, (double)RB_FLOW_MAX_STEP / 1048576.0);

            delta = 0;

        }

        acc += delta;

        [st setObject:[NSNumber numberWithUnsignedLongLong:cur] forKey:@"flowBase"];

        [st setObject:[NSNumber numberWithUnsignedLongLong:acc] forKey:@"flowAcc"];

        rb_state_save(st);

        gFlowAcc = acc;



#if RB_RATEMON

        // 实测速率：用两次采样的字节差除以时间差。不猜、不 ping，就是实际吞吐量。

        static uint64_t lastAcc = 0;

        static double   lastTs  = 0;

        double now = rb_now();

        if (lastTs > 0) {

            double dt = now - lastTs;

            if (dt > 0.5 && acc >= lastAcc)

                gRateKBps = (double)(acc - lastAcc) / dt / 1024.0;

        }

        // v57：记录最近一次「隧道真的有数据」的时刻。

        // 隧道协议自带 keepalive，真连着的隧道就算空闲也有零星字节；

        // 状态报「已连接」却长期零字节，就是假连接（v56 日志实锤：

        // utun 全程 0.1MB 的同时配置自带状态一直是 3）。

        // 512 字节起步：隧道 keepalive 也是字节，但 0 字节就是真死了

        if (acc >= lastAcc + 512) gLastTrafficTs = now;

        lastAcc = acc;

        lastTs  = now;

#endif

#if RB_NODE_ROTATE_ON

        // v67：抹除之后的节点体检。抹完 8 秒起算，连着 20 秒速率都上不去（<500 KB/s）
        // 就判定「连的是旧节点/旧身份」→ 丢掉节点让 App 重新申请。
        // 一旦真跑出 3MB 以上流量就说明没限速，观测结束不再打扰。
        {
            double lw = [[st objectForKey:@"lastWipeTs"] doubleValue];
            static int rotN = 0, armed = 0;
            static double obsStart = 0;

            if (lw <= 0 || now - lw > RB_NODE_WAIT_SEC) { rotN = 0; armed = 0; obsStart = 0; }

            else if (armed >= 0) {

                double accMB = (double)acc / 1048576.0;

                if (accMB >= RB_NODE_OK_MB) {

                    rb_log("节点体检：抹后已跑 %.1f MB，速率 %.1f KB/s —— 当前节点没被限速",
                           accMB, gRateKBps);
                    armed = -1;

                } else if (now - lw > RB_NODE_OBS_ARM_SEC) {

                    if (obsStart <= 0) obsStart = now;

                    if (now - obsStart >= RB_NODE_OBS_SEC &&
                        gRateKBps >= 0 && gRateKBps < RB_NODE_LIMIT_KBPS) {

                        if (rotN < RB_NODE_ROTATE_MAX) {

                            rotN++;

                            rb_log("节点体检：抹后 %.0f 秒速率只有 %.1f KB/s（正常 8000+）——"
                                   "判定旧节点的旧认证串被限速，丢掉换新的（第 %d/%d 次）",
                                   now - lw, gRateKBps, rotN, RB_NODE_ROTATE_MAX);

                            rb_node_rotate();

                            obsStart = now;

                        } else {

                            armed = -1;

                            rb_log("节点体检：连换 %d 次仍然限速 —— 剩下的要在 App 里手选一个新节点"
                                   "（选中后 shim 会自动拉隧道）", RB_NODE_ROTATE_MAX);

                        }

                    }

                }

            }

        }

#endif



        static int tickN = 0;

        if (++tickN * (int)RB_FLOW_TICK_SEC >= (int)RB_STATUS_LOG_SEC) {

            tickN = 0;

            double lastTs = [[st objectForKey:@"lastWipeTs"] doubleValue];

            // v61：状态行里带上实测速率和低速计时 —— 「是不是已经被限速」一眼可见

            if (lastTs > 0)

                rb_log("状态：额度 %s %.1f / %.0f MB（剩 %.1f），utun 计 %.1f MB，"
                       "速率 %.1f KB/s，低速 %.0f 秒，"

                       "归零命中 %d 次，已抹除 %d 次，距上次抹除 %.0f 秒（重建 %d 次）",

                       (gSrvTotal > 0) ? "服务端" : "本地",
                       (gSrvTotal > 0) ? (double)rb_used_est() / 1048576.0
                                       : (double)acc / 1048576.0,
                       (gSrvTotal > 0) ? (double)gSrvTotal / 1048576.0
                                       : (double)rb_quota_limit() / 1048576.0,
                       (gSrvTotal > 0)
                           ? (double)(gSrvTotal - rb_used_est()) / 1048576.0
                           : (double)(rb_quota_limit() - acc) / 1048576.0,
                       acc / 1048576.0, gRateKBps,

                       gSlowSec, gHits,

                       [[st objectForKey:@"wipeCount"] intValue], rb_now() - lastTs,

                       gFlowRebuilds);

            else

                rb_log("状态：额度 %s %.1f / %.0f MB（剩 %.1f），utun 计 %.1f MB，"
                       "速率 %.1f KB/s，低速 %.0f 秒，"

                       "归零命中 %d 次，已抹除 %d 次（从未抹除）（重建 %d 次）",

                       (gSrvTotal > 0) ? "服务端" : "本地",
                       (gSrvTotal > 0) ? (double)rb_used_est() / 1048576.0
                                       : (double)acc / 1048576.0,
                       (gSrvTotal > 0) ? (double)gSrvTotal / 1048576.0
                                       : (double)rb_quota_limit() / 1048576.0,
                       (gSrvTotal > 0)
                           ? (double)(gSrvTotal - rb_used_est()) / 1048576.0
                           : (double)(rb_quota_limit() - acc) / 1048576.0,
                       acc / 1048576.0, gRateKBps,

                       gSlowSec, gHits,

                       [[st objectForKey:@"wipeCount"] intValue], gFlowRebuilds);

        }



        // v61：限速判据。App 上那个「剩 31.9 GB」是服务端的展示值，

        // 真实额度用完的表现是掉到福利速度（≈20KB/s）。字节数判据会因为

        // utun 重建而攒不满，速率这条才抓得住「其实已经用完」。

#if RB_THROTTLE_DETECT

        if (!gThrottleHit) {

            int moving = (delta >= (uint64_t)RB_THROTTLE_MIN_DELTA);   // 这周期确有数据在走

            if (gRateKBps > 0 && gRateKBps <= RB_THROTTLE_KBPS && moving) {

                gSlowSec += RB_FLOW_TICK_SEC;

                if (gSlowSec >= RB_THROTTLE_HOLD_SEC &&

                    acc >= (uint64_t)(RB_THROTTLE_MIN_MB * 1048576.0)) {

                    gThrottleHit = 1;

                    gSlowSec = 0;

                    rb_log("限速判据：连续 %.0f 秒速率只有 %.1f KB/s（阈值 %.0f KB/s），"

                           "已跑 %.1f MB —— 判定已掉到福利速度，触发抹除",

                           RB_THROTTLE_HOLD_SEC, gRateKBps, (double)RB_THROTTLE_KBPS,

                           acc / 1048576.0);

                    rb_fire("限速判据", NO);

                    return;

                }

            } else {

                if (gSlowSec >= RB_FLOW_TICK_SEC * 3)

                    rb_log("限速判据：速率回到 %.1f KB/s，低速计时清零（%.0f 秒）",

                           gRateKBps, gSlowSec);

                gSlowSec = 0;

            }

        }

#endif



        if (acc >= rb_quota_limit()) {

            rb_log("流量用完：utun 累计 %.1f MB（阈值 %.1f MB），触发抹除",

                   acc / 1048576.0, rb_quota_limit() / 1048576.0);

            rb_fire("流量判据", NO);

            return;

        }

        // v65：服务端报的数才是权威 —— 它说用完了就是用完了，
        // 本地 utun 计数只是漏得多的近似，别让它抢在前面或拖后腿。
        if (gSrvTotal > 0 &&

            (uint64_t)((double)gSrvUsed / (double)gSrvTotal * 100.0) >=
            (uint64_t)(RB_WIPE_THRESHOLD * 100.0)) {

            rb_log("服务端额度用完：已用 %.1f / %.1f MB，触发抹除",

                   (double)gSrvUsed / 1048576.0,

                   (double)gSrvTotal / 1048576.0);

            rb_fire("服务端额度判据", NO);

            return;

        }

    }

#endif

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,

                                 (int64_t)(RB_FLOW_TICK_SEC * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{ rb_flow_tick(); });

}



#pragma mark - 保活（v56：让 shim 在后台也能看见额度归零）



// ① 后台任务续期：每次到期就再要一段，能多撑一会儿是一会儿

static void rb_bg_renew(void) {

#if RB_BGTASK_KEEP

    @try {

        UIApplication *app = [UIApplication sharedApplication];

        if (!app) return;

        if (gBgTaskHeld) { [app endBackgroundTask:gBgTask]; gBgTaskHeld = NO; }

        gBgTask = [app beginBackgroundTaskWithExpirationHandler:^{ rb_bg_renew(); }];

        gBgTaskHeld = (gBgTask != UIBackgroundTaskInvalid);

    } @catch (NSException *e) { }

#endif

}



// ② RunningBoard / BoardServices 断言：拿到之后进程不会被系统挂起

static void rb_take_assertion(void) {

#if RB_ASSERTION_KEEP

    if (gAssertion) return;

    @try {

        Class attrCls = NSClassFromString(@"RBSDomainAttribute");

        Class tgtCls  = NSClassFromString(@"RBSTarget");

        Class asCls   = NSClassFromString(@"RBSAssertion");

        if (attrCls && tgtCls && asCls) {

            id attr = ((id (*)(id, SEL, id, id))objc_msgSend)(

                attrCls, sel_registerName("attributeWithDomain:name:"),

                @"com.apple.frontboard", @"Background");

            id target = ((id (*)(id, SEL, int))objc_msgSend)(

                tgtCls, sel_registerName("targetWithPid:"), (int)getpid());

            id raw = ((id (*)(id, SEL))objc_msgSend)((id)asCls, sel_registerName("alloc"));

            id a = ((id (*)(id, SEL, id, id, id))objc_msgSend)(

                raw, sel_registerName("initWithExplanation:target:attributes:"),

                @"rb-keepalive", target, [NSArray arrayWithObject:attr]);

            NSError *e = nil;

            BOOL ok = ((BOOL (*)(id, SEL, NSError **))objc_msgSend)(

                a, sel_registerName("acquireWithError:"), &e);

            rb_log("保活：RBS 断言%s%s", ok ? "已拿到" : "失败",

                   ok ? "" : [[NSString stringWithFormat:@"（%@）",

                               [e localizedDescription]] UTF8String]);

            if (ok) { gAssertion = [a retain]; return; }

        } else {

            rb_log("保活：RunningBoard 类不可用（系统版本差异）");

        }

    } @catch (NSException *e) {

        rb_log("保活：RBS 断言异常 %s", [[e reason] UTF8String]);

    }

    @try {

        Class bks = NSClassFromString(@"BKSProcessAssertion");

        if (!bks) { rb_log("保活：BKSProcessAssertion 也不可用"); return; }

        id raw = ((id (*)(id, SEL))objc_msgSend)((id)bks, sel_registerName("alloc"));

        SEL s = sel_registerName("initWithPID:flags:reason:name:");

        if (![raw respondsToSelector:s]) { rb_log("保活：BKS 接口签名变了"); return; }

        id a = ((id (*)(id, SEL, int, unsigned, unsigned, id))objc_msgSend)(

            raw, s, (int)getpid(), (unsigned)0x1F, (unsigned)1, @"rb-keepalive");

        BOOL ok = NO;

        SEL ac = sel_registerName("acquire");

        if ([a respondsToSelector:ac]) { ((void (*)(id, SEL))objc_msgSend)(a, ac); ok = YES; }

        rb_log("保活：BKS 断言%s", ok ? "已请求" : "失败");

        if (ok) gAssertion = [a retain];

    } @catch (NSException *e) {

        rb_log("保活：BKS 断言异常 %s", [[e reason] UTF8String]);

    }

#endif

}



// ③ 兜底：循环播放一段静音音频。上面两条都拿不到时用它——

// 有活跃音频会话的 App 系统不会挂起（需要 Info.plist 里有 audio 背景模式，

// 打包脚本已经加进去了；加不上就只是这一条不生效，别的不受影响）。

static void rb_start_audio_keep(void) {

#if RB_AUDIO_KEEP

    if (gKeepAudio) return;

    @try {

        Class sess = NSClassFromString(@"AVAudioSession");

        Class pc   = NSClassFromString(@"AVAudioPlayer");

        if (!sess || !pc) { rb_log("保活：AVAudioSession/AVAudioPlayer 不可用"); return; }



        NSString *p = [NSTemporaryDirectory()

                       stringByAppendingPathComponent:@"rb_silence.wav"];

        if (![[NSFileManager defaultManager] fileExistsAtPath:p]) {

            const int dataLen = 8000 * 2;           // 8kHz / 16bit / 单声道 / 1 秒

            uint8_t hdr[44];

            memset(hdr, 0, sizeof(hdr));

            uint32_t v; uint16_t s;

            memcpy(hdr,     "RIFF", 4);

            v = 36 + dataLen; memcpy(hdr + 4,  &v, 4);

            memcpy(hdr + 8, "WAVEfmt ", 8);

            v = 16;          memcpy(hdr + 16, &v, 4);

            s = 1;           memcpy(hdr + 20, &s, 2);   // PCM

            s = 1;           memcpy(hdr + 22, &s, 2);   // mono

            v = 8000;        memcpy(hdr + 24, &v, 4);   // 采样率

            v = 16000;       memcpy(hdr + 28, &v, 4);   // 字节率

            s = 2;           memcpy(hdr + 32, &s, 2);   // 块对齐

            s = 16;          memcpy(hdr + 34, &s, 2);   // 位深

            memcpy(hdr + 36, "data", 4);

            v = dataLen;     memcpy(hdr + 40, &v, 4);

            NSMutableData *w = [NSMutableData dataWithBytes:hdr length:44];

            [w increaseLengthBy:dataLen];               // 全 0 就是静音

            [w writeToFile:p atomically:YES];

        }



        id s = ((id (*)(id, SEL))objc_msgSend)(sess, sel_registerName("sharedInstance"));

        ((BOOL (*)(id, SEL, id, NSUInteger, NSError **))objc_msgSend)(

            s, sel_registerName("setCategory:withOptions:error:"),

            @"AVAudioSessionCategoryPlayback", (NSUInteger)1 /*MixWithOthers*/, nil);

        ((BOOL (*)(id, SEL, BOOL, NSError **))objc_msgSend)(

            s, sel_registerName("setActive:error:"), YES, nil);



        NSError *e = nil;

        id raw = ((id (*)(id, SEL))objc_msgSend)((id)pc, sel_registerName("alloc"));

        id player = ((id (*)(id, SEL, id, NSError **))objc_msgSend)(

            raw, sel_registerName("initWithContentsOfURL:error:"),

            [NSURL fileURLWithPath:p], &e);

        if (!player) {

            rb_log("保活：静音播放器创建失败 %s",

                   [[NSString stringWithFormat:@"%@", [e localizedDescription]] UTF8String]);

            return;

        }

        ((void (*)(id, SEL, NSInteger))objc_msgSend)(

            player, sel_registerName("setNumberOfLoops:"), (NSInteger)-1);

        BOOL ok = ((BOOL (*)(id, SEL))objc_msgSend)(player, sel_registerName("play"));

        gPlayer = [player retain];

        gKeepAudio = ok ? 1 : 0;

        rb_log("保活：静音音频%s", ok ? "已启动（进程不会被挂起）" : "启动失败");

    } @catch (NSException *e) {

        rb_log("保活：静音音频异常 %s", [[e reason] UTF8String]);

    }

#endif

}



// 看门狗：开关打开时盯着隧道状态，不是「已连接」就拉起来

static void rb_keepalive_tick(void) {

#if RB_KEEPALIVE

    if (gStopped) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,

                                 (int64_t)(RB_KEEPALIVE_SEC * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            if (!gStopped && rb_auto_on()) {

                int vs = rb_vpn_status();

                if (vs == 0 || vs == 1 || vs == 5) {

                    if (rb_now() - gLastStartTs > RB_RECONNECT_GAP) {

                        rb_log("自动连接：隧道状态 %d（不是已连接），拉起一次", vs);

                        rb_start_vpn_once(0);

                    }

                } else {

                    rb_bg_renew();      // 连着就续一下后台时间

                }

            }

        }

        rb_keepalive_tick();

    });

#endif

}



// 保活整套启动：后台任务 → 断言 →（失败才）静音音频 → 看门狗

static void rb_keepalive_boot(void) {

    if (gStopped) return;

    rb_bg_renew();

#if RB_ASSERTION_KEEP

    rb_take_assertion();

#endif

#if RB_AUDIO_KEEP

    // v62：改成无条件开。原来只在拿不到断言时才开，可 BKS 断言拿到了不代表

    // 后台真能持续跑（RBS 那条一直报 Could not find attribute name）；

    // 用户的诉求是「额度用完不用手动进 App」，那后台必须真的活着。

    // 静音音频是 iOS 上唯一稳定的后台执行通道，代价只是多一点点电。

    rb_start_audio_keep();

#endif

#if RB_KEEPALIVE

    rb_keepalive_tick();

#endif

    static int obs = 0;

    if (!obs) {

        obs = 1;

        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

        [nc addObserverForName:UIApplicationDidEnterBackgroundNotification

                        object:nil queue:[NSOperationQueue mainQueue]

                    usingBlock:^(NSNotification *n) { (void)n; rb_bg_renew(); }];

        [nc addObserverForName:UIApplicationDidBecomeActiveNotification

                        object:nil queue:[NSOperationQueue mainQueue]

                    usingBlock:^(NSNotification *n) {

            (void)n;

            rb_bg_renew();

            rb_panel_refresh();

        }];

    }

}



#pragma mark - 触发



// v57：宽限/冷却期内的命中不再丢掉 —— 到点自动补一刀。

// v56 日志实证：pid 16638 打出「启动宽限 4 秒内不动手（快速通道）」之后就没下文了，

// 而归零回调是一次性的，宽限一过没有任何东西会再触发，第二次抹除就永远等不到，

// 用户只能手动进 App 再等一次闪退。现在命中被挡时排一个定时器，条件一过就重试。

static volatile double gRetryAt = 0;



static void rb_fire(const char *why, BOOL force);   // 定义在下面



static void rb_fire_later(const char *why, double delay) {

    if (delay < 0.2) delay = 0.2;

    double now = rb_now();

    if (gRetryAt > now) return;                     // 已经排了补刀，不重复排

    gRetryAt = now + delay;

    NSString *w = [[NSString alloc] initWithUTF8String:(why ? why : "?")];

    rb_log("命中被挡住：%.1f 秒后自动重试（v56 这里是直接丢掉）", delay);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            gRetryAt = 0;

            // v59：补刀前必须复核，不能无条件再抹一次。

            // v58 日志实证：58 秒后那刀照抹不误，可额度早就刷新好了 ——

            // 白抹一次、白自拉起一次、用户白等一次。

            // 判据：抹完之后跑出了真实流量、并且没再收到归零 → 已经刷新好了。

            NSMutableDictionary *s = rb_state();

            double lw = [[s objectForKey:@"lastWipeTs"] doubleValue];

            uint64_t acc = gFlowAcc;

            if (lw > 0 && !gHitAfterWipe &&

                acc >= (uint64_t)RB_REFRESH_MB * 1048576ULL) {

                rb_log("补刀复核：上次抹除后已跑掉 %.1f MB 流量且没再收到归零 —— "

                       "额度已刷新，这次不抹", acc / 1048576.0);

                return;

            }

            rb_fire([w UTF8String], NO);

        }

        [w release];

    });

}



// force=1 走手动扳机/面板按钮：跳过冷却与熔断，但依然会正常抹 + 拉起

static void rb_fire(const char *why, BOOL force) {

#if !RB_ENABLED

    return;

#endif

    if (gWiping) return;

    double now = rb_now();



    NSMutableDictionary *st = rb_state();

    double last = [[st objectForKey:@"lastWipeTs"] doubleValue];

    // v76：抹后 120 秒内且本地 utun 累计 < 20MB —— 不可能真用完 300MB。
    // rb-shim(17) 第 52→70 行实锤：新身份注册期服务端心跳异常（len=101
    // 短包被判归零），1.5 秒后把刚建好的新身份又抹了，连续两次把 App
    // 摁死在注册阶段（截图：体验餐剩 300 MB 却「连接超时」）。
    // 真用完必然有约 300MB 过 utun，这个守卫不会漏掉真实归零。
    if (!force && last > 0 && now - last < 120.0 &&

        gFlowAcc < (uint64_t)(20ull << 20)) {

        rb_log("抹后 %.0f 秒本地只跑 %.1f MB —— 不可能真用完，挡掉这次「%s」"
               "（v76：注册期服务端心跳不可信）", now - last,
               (double)gFlowAcc / 1048576.0, why);

        return;

    }



    if (gStopped && !force) return;



    if (force) {

        // 手动扳机 = 用户明确要再来一次：解除熔断、清空连续计数，重新武装

        BOOL was = gStopped;

        gStopped = 0;

        [st removeObjectForKey:@"autoOff"];

        [st removeObjectForKey:@"rapidCount"];

        [st removeObjectForKey:@"rapidTs"];

        // 熔断/闪退循环时采样链与定时器链都已停摆，这里重新拉起来

        if (was) { rb_flow_tick(); rb_tick(); rb_keepalive_boot(); }

    } else {

        // 刚抹完重开的进程：宽限与冷却都走快速通道，让它自己接着抹第二次

        double grace = gFastLane ? RB_GRACE_FAST_SEC : RB_GRACE_SEC;

        double cool  = gFastLane ? RB_COOL_FAST_SEC  : RB_COOL_SEC;

        // 保险 1：启动宽限

        if (now - gBootAt < grace) {

            rb_log("命中归零（%s），启动宽限 %.0f 秒内不动手%s", why, grace,

                   gFastLane ? "（快速通道）" : "");

            rb_fire_later(why, grace - (now - gBootAt) + 0.3);

            return;

        }

        // 保险 2：冷却

        if (last > 0 && now - last < cool) {

            rb_log("命中归零（%s），距上次抹除仅 %.0f 秒，冷却中%s", why, now - last,

                   gFastLane ? "（快速通道）" : "");

            rb_fire_later(why, cool - (now - last) + 0.3);

            return;

        }

        // 保险 3：连续抹还是归零 → 抹数据这条路对当前账号无效，停用

        int rapid = [[st objectForKey:@"rapidCount"] intValue];

        double rts = [[st objectForKey:@"rapidTs"] doubleValue];

        rapid = (rts > 0 && now - rts < RB_RAPID_WIN) ? rapid + 1 : 1;

        [st setObject:[NSNumber numberWithInt:rapid] forKey:@"rapidCount"];

        [st setObject:[NSNumber numberWithDouble:now] forKey:@"rapidTs"];

        if (rapid > RB_MAX_RAPID) {

            [st setObject:[NSNumber numberWithBool:YES] forKey:@"autoOff"];

            gStopped = 1;

            rb_log("15 分钟内已连续抹除 %d 次仍然归零 —— 停止自动抹除"

                   "（避免反复闪退）。要再试就放 Documents/%s 扳机文件",

                   rapid - 1, RB_TRIGGER_C);

            rb_state_save(st);

            return;

        }

    }



    // 先落时间戳再动手：中途出事也不会重入

    [st setObject:[NSNumber numberWithDouble:now] forKey:@"lastWipeTs"];

    [st setObject:[NSNumber numberWithInt:[[st objectForKey:@"wipeCount"] intValue] + 1]

           forKey:@"wipeCount"];

    [st setObject:[NSNumber numberWithBool:YES] forKey:@"pendingStart"];

    // 流量计数归零：不然新进程一读 utun 还是满的，立刻又触发一次

    [st setObject:[NSNumber numberWithUnsignedLongLong:0] forKey:@"flowAcc"];

    [st setObject:[NSNumber numberWithUnsignedLongLong:rb_utun_bytes()] forKey:@"flowBase"];

    rb_state_save(st);

    gFlowAcc = 0;

    // v65：抹完 = 新账号 = 新额度，旧的服务端报数作废，等下一条报文再记
    gSrvTotal = 0;

    gSrvUsed  = 0;

    gSrvTs    = 0;

    gSlowSec = 0;          // v61：抹完限速判据重新武装

    gThrottleHit = 0;

    gFlowRebuilds = 0;



    // v62：抹前把当前选中的节点配置快照进白名单文件。

    // 异步 loadAll（1.5 秒的延迟足够它回来），抹完新进程重连前写回去，

    // 用户就不用再手动进 App 重选一次节点了。

    {

        Class C2 = objc_getClass("NETunnelProviderManager");

        if (C2) {

            void (^h2)(NSArray *, NSError *) = ^(NSArray *mans2, NSError *e3) {

                (void)e3;

                for (id m2 in mans2) {

                    id proto2 = nil;

                    if ([m2 respondsToSelector:@selector(protocolConfiguration)])

                        proto2 = [m2 valueForKey:@"protocolConfiguration"];

                    if (!proto2 && [m2 respondsToSelector:@selector(protocol)])

                        proto2 = [m2 valueForKey:@"protocol"];

                    if (!proto2) continue;

                    id pcfg2 = nil;

                    @try {

                        if ([proto2 respondsToSelector:@selector(providerConfiguration)])

                            pcfg2 = [proto2 valueForKey:@"providerConfiguration"];

                    } @catch (NSException *ex2) { }

                    if (![pcfg2 isKindOfClass:[NSDictionary class]] ||

                        [(NSDictionary *)pcfg2 count] == 0) continue;

                    NSMutableDictionary *st2 = rb_state();

                    [st2 setObject:pcfg2 forKey:RB_NODE_SNAP_KEY];

                    rb_state_save(st2);

                    rb_log("抹前快照：节点配置已存（%lu 个键）—— 抹完自动恢复，"

                           "不用再手动选节点",

                           (unsigned long)[(NSDictionary *)pcfg2 count]);

                    break;

                }

            };

            ((void (*)(id, SEL, id))objc_msgSend)(

                C2, sel_registerName("loadAllFromPreferencesWithCompletionHandler:"),

                h2);

        }

    }



    NSString *w = [[NSString alloc] initWithUTF8String:(why ? why : "?")];

    [gLastWhy release];

    gLastWhy = w;



    // v64：抹之前先把配置键导出 + 节点类键快照（同步做，不等异步回调）

    rb_prefs_dump();

    rb_prefs_snapshot();

    rb_node_files_snapshot();



    rb_log("额度归零（%s）：%.1f 秒后抹数据", why, (double)RB_DELAY_SEC);

#if RB_STOP_BEFORE_WIPE

    // 现在就发（异步），1.5 秒后再抹 —— 上一版放在抹的那一刻才发，异步回调

    // 慢半拍，日志里「抹除前已请求停止」反而排在「抹数据完成」后面，等于没停

    rb_stop_vpn();

#endif

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,

                                 (int64_t)(RB_DELAY_SEC * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            rb_wipe_all();

            rb_relaunch();

        }

    });

}



#pragma mark - 报文扫描



#define RB_SCAN_MAX (256u << 10)



static uint8_t *gBuf = NULL;

static size_t   gCap = 0;

static double   gLastScan = 0;



static void rb_scan(uint64_t p, uint64_t len, const char *from) {

    if (gStopped || len < 8 || len > RB_SCAN_MAX) return;

    double now = rb_now();

    if (now - gLastScan < 0.2) return;      // 200ms 一次，够用了

    gLastScan = now;



    if (gCap < (size_t)len) {

        free(gBuf);

        gBuf = (uint8_t *)malloc((size_t)len + 16);

        gCap = gBuf ? (size_t)len + 16 : 0;

    }

    if (!gBuf) return;

    size_t got = rb_read((const void *)(uintptr_t)p, gBuf, (size_t)len);

    if (got < 8) return;



    @autoreleasepool {

        if (rb_dead(gBuf, got)) {

            gHits++;

            rb_log("[%s] 侦测到额度归零（第 %d 次，len=%lu）",

                   from, gHits, (unsigned long)got);

            // 抹除之后又收到归零 → 这次抹除没换回额度，补刀复核时要用这个信号

            if ([[rb_state() objectForKey:@"lastWipeTs"] doubleValue] > 0)

                gHitAfterWipe = 1;

            rb_fire(from, NO);

        }

    }

}



#pragma mark - 原实现转发（8 个导出）



typedef uint64_t (*fn8)(uint64_t, uint64_t, uint64_t, uint64_t,

                        uint64_t, uint64_t, uint64_t, uint64_t);



static void *gLib = NULL;

static fn8  gNew, gRequest, gFireAndForget, gFree,

            gFreeBuffer, gIsConnected, gForceReconnect, gSetNetworkAvailable;

static char gOrigPath[1024];

static uint64_t rb_cb_orig[4];

static int      rb_cb_on[4];



static uint64_t rb_cb_dispatch(int slot, uint64_t a0, uint64_t a1, uint64_t a2,

                               uint64_t a3, uint64_t a4, uint64_t a5,

                               uint64_t a6, uint64_t a7);



#define RB_CB_T(n)                                                            \
static uint64_t rb_cb_t##n(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, \
                           uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) { \
    return rb_cb_dispatch(n, a0, a1, a2, a3, a4, a5, a6, a7);                 \
}

RB_CB_T(0) RB_CB_T(1) RB_CB_T(2) RB_CB_T(3)



static uint64_t (*rb_cb_tramp[4])(uint64_t, uint64_t, uint64_t, uint64_t,

                                  uint64_t, uint64_t, uint64_t, uint64_t) =

    { rb_cb_t0, rb_cb_t1, rb_cb_t2, rb_cb_t3 };



static uint64_t rb_cb_dispatch(int slot, uint64_t a0, uint64_t a1, uint64_t a2,

                               uint64_t a3, uint64_t a4, uint64_t a5,

                               uint64_t a6, uint64_t a7) {

    uint64_t v[8] = {a0, a1, a2, a3, a4, a5, a6, a7};

    @autoreleasepool {

        for (int i = 0; i + 1 < 8; i++) {

            uint64_t p = v[i], L = v[i + 1];

            if (L >= 8 && L <= RB_SCAN_MAX) rb_scan(p, L, "cb");

        }

    }

    uint64_t (*f)(uint64_t, uint64_t, uint64_t, uint64_t,

                  uint64_t, uint64_t, uint64_t, uint64_t) =

        (uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t,

                      uint64_t, uint64_t, uint64_t, uint64_t))(void *)rb_cb_orig[slot];

    return f ? f(a0, a1, a2, a3, a4, a5, a6, a7) : 0;

}



// 把 new() 参数里的回调地址换成我们的转发函数，才看得到服务端下发了什么。

// 只认落在可执行区里的地址 —— 数据指针不会被误换。

static void rb_cb_wrap(uint64_t *v) {

    if (!gNew) return;

    for (int i = 4; i <= 6; i++) {

        uint64_t a = v[i];

        if (!a) continue;

        int slot = -1;

        for (int k = 0; k < 4; k++)

            if (rb_cb_on[k] && rb_cb_orig[k] == a) { slot = k; break; }

        if (slot < 0) {

            if (!rb_is_exec(a)) continue;

            for (int k = 0; k < 4; k++) if (!rb_cb_on[k]) { slot = k; break; }

            if (slot < 0) return;

            rb_cb_orig[slot] = a;

            rb_cb_on[slot] = 1;

            rb_log("已包裹传输层回调 arg%d -> slot%d", i, slot);

        }

        v[i] = (uint64_t)(uintptr_t)rb_cb_tramp[slot];

    }

}



#define FWD(name, slot)                                                        \
uint64_t name(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,              \
              uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {            \
    if (!slot) return (uint64_t)-1;                                            \
    return slot(a0, a1, a2, a3, a4, a5, a6, a7);                               \
}



uint64_t rely_transport_new(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,

                            uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {

    if (!gNew) return (uint64_t)-1;

    uint64_t v[8] = {a0, a1, a2, a3, a4, a5, a6, a7};

    rb_cb_wrap(v);

    return gNew(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);

}



uint64_t rely_transport_request(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,

                                uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {

    if (!gRequest) return (uint64_t)-1;

    return gRequest(a0, a1, a2, a3, a4, a5, a6, a7);

}



uint64_t rely_transport_send_fire_and_forget(uint64_t a0, uint64_t a1, uint64_t a2,

                                             uint64_t a3, uint64_t a4, uint64_t a5,

                                             uint64_t a6, uint64_t a7) {

    if (!gFireAndForget) return (uint64_t)-1;

    return gFireAndForget(a0, a1, a2, a3, a4, a5, a6, a7);

}



uint64_t rely_transport_free_buffer(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,

                                    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {

    if (a0) {

        size_t sz = malloc_size((const void *)(uintptr_t)a0);

        if (sz >= 8 && sz <= RB_SCAN_MAX) rb_scan(a0, (uint64_t)sz, "fb");

    }

    if (!gFreeBuffer) return (uint64_t)-1;

    return gFreeBuffer(a0, a1, a2, a3, a4, a5, a6, a7);

}



FWD(rely_transport_free, gFree)

FWD(rely_transport_is_connected, gIsConnected)

FWD(rely_transport_force_reconnect, gForceReconnect)

FWD(rely_transport_set_network_available, gSetNetworkAvailable)



static void compute_orig_path(void) {

    Dl_info info;

    if (dladdr((void *)(uintptr_t)&compute_orig_path, &info) && info.dli_fname) {

        snprintf(gOrigPath, sizeof(gOrigPath), "%s", info.dli_fname);

        char *slash = strrchr(gOrigPath, '/');

        if (slash && (size_t)(slash - gOrigPath) + 24 < sizeof(gOrigPath)) {

            strcpy(slash + 1, "rely_transport_orig");

            return;

        }

    }

    char exe[1024];

    uint32_t sz = (uint32_t)sizeof(exe);

    if (_NSGetExecutablePath(exe, &sz) == 0) {

        char *slash = strrchr(exe, '/');

        if (slash) {

            *slash = '\0';

            snprintf(gOrigPath, sizeof(gOrigPath),

                     "%s/Frameworks/rely_transport.framework/rely_transport_orig", exe);

            return;

        }

    }

    gOrigPath[0] = '\0';

}



static void *resolve(const char *name) {

    return gLib ? dlsym(gLib, name) : NULL;

}



static int load_orig(void) {

    if (gLib) return 1;

    if (!gOrigPath[0]) compute_orig_path();

    if (!gOrigPath[0]) return 0;

    gLib = dlopen(gOrigPath, RTLD_NOW | RTLD_LOCAL);

    if (!gLib) {

        rb_log("dlopen 失败 %s: %s", gOrigPath, dlerror());

        return 0;

    }

    gNew                 = (fn8)resolve("rely_transport_new");

    gRequest             = (fn8)resolve("rely_transport_request");

    gFireAndForget       = (fn8)resolve("rely_transport_send_fire_and_forget");

    gFree                = (fn8)resolve("rely_transport_free");

    gFreeBuffer          = (fn8)resolve("rely_transport_free_buffer");

    gIsConnected         = (fn8)resolve("rely_transport_is_connected");

    gForceReconnect      = (fn8)resolve("rely_transport_force_reconnect");

    gSetNetworkAvailable = (fn8)resolve("rely_transport_set_network_available");

    return gRequest != NULL;

}



#pragma mark - 面板（右上角小窗，用来手动验证整条链路）



#if RB_PANEL

static UIWindow *gWin = nil;

static UILabel  *gLbl = nil;

static int       gPanelObs = 0;

// v58：常驻悬浮球。之前是一整块面板 + 「隐藏」按钮，一按就再也找不回来 ——

// 现在默认收成一个 56x56 的小球（可拖动），点一下展开完整面板，面板上是

// 「收起」而不是「隐藏」，小球永远在，不会丢。

static int       gExpanded = 0;

static UIView   *gBubble = nil;

static UIView   *gPanelView = nil;

static UILabel  *gBubbleLbl = nil;

static CGPoint   gBubblePos = {-1, -1};



static NSString *rb_status_text(void) {

    NSDictionary *st = rb_state();

    double last = [[st objectForKey:@"lastWipeTs"] doubleValue];

    int cnt = [[st objectForKey:@"wipeCount"] intValue];

    NSString *when = last > 0

        ? [NSDateFormatter localizedStringFromDate:

              [NSDate dateWithTimeIntervalSince1970:last]

                                         dateStyle:NSDateFormatterNoStyle

                                         timeStyle:NSDateFormatterMediumStyle]

        : @"从未";

    NSString *why = gLastWhy ? gLastWhy : @"尚未触发";

    double left = (gSrvTotal > 0)

                ? (double)(gSrvTotal - gSrvUsed)          // 服务端报的，准

                : (double)rb_quota_limit() - (double)gFlowAcc;

    if (left < 0) left = 0;

    static const char *vst[] = {"无效", "未连接", "连接中", "已连接", "重连中", "断开中"};

    int vs = rb_vpn_status();

    NSString *vsName = (vs >= 0 && vs <= 5) ? [NSString stringWithUTF8String:vst[vs]]

                                            : @"未知";

    NSString *rate = (vs == 3)

        ? [NSString stringWithFormat:@"%.0f KB/s%@", gRateKBps,

           (gRateKBps < RB_SLOW_KBPS) ? @"（慢）" : @""]

        : @"—";

    return [NSString stringWithFormat:

        @"RelyVPN 自动抹数据 v65\n"

        @"额度 %.1f / %.0f MB（还剩 %.1f）%@\n"

        @"隧道状态：%@%@   速率 %@\n"

        @"已抹除 %d 次   归零命中 %d 次\n"

        @"上次抹除：%@\n"

        @"最近原因：%@\n"

        @"日志：文件 App → RelyVPN → %@",

        (gSrvTotal > 0) ? (double)rb_used_est() / 1048576.0
                        : (double)gFlowAcc / 1048576.0,
        (gSrvTotal > 0) ? (double)gSrvTotal / 1048576.0
                        : (double)rb_quota_limit() / 1048576.0,

        left / 1048576.0,
        (gSrvTotal > 0) ? @"［服务端］" : @"［本地计数］",
        vsName, gFastLane ? @"（快速通道）" : @"", rate,

        cnt, gHits, when, why, RB_LOG_NAME];

}



static void rb_panel_refresh(void) {

    if (gLbl) gLbl.text = rb_status_text();

}



static void rb_wipe_now(void) {

    rb_log("面板：手动点「立即抹数据」");

    rb_fire("面板按钮", YES);

}



// 悬浮球上显示的一行：连通/未连 + 剩余额度，不用展开也能看个大概

static NSString *rb_bubble_text(void) {

    int vs = rb_vpn_status();

    double left = (gSrvTotal > 0)

                ? (double)(gSrvTotal - gSrvUsed)          // 服务端报的，准

                : (double)rb_quota_limit() - (double)gFlowAcc;

    if (left < 0) left = 0;

    return [NSString stringWithFormat:@"%@\n%.0fMB",

            (vs == 3 || vs == 2) ? @"●" : @"○", left / 1048576.0];

}



static void rb_panel_set_expanded(int on);   // 定义在 RbPanelVC 之后



@interface RbPanelVC : UIViewController

@end



@implementation RbPanelVC

- (void)viewDidLoad {

    [super viewDidLoad];

    UIView *root = self.view;

    root.backgroundColor = [UIColor clearColor];



    // —— 悬浮球（默认可见）——

    UIView *bb = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 56, 56)];

    bb.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.95];

    bb.layer.cornerRadius = 28;

    bb.clipsToBounds = YES;

    bb.layer.borderWidth = 1.2;

    bb.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.35].CGColor;

    UILabel *bl = [[UILabel alloc] initWithFrame:bb.bounds];

    bl.textColor = [UIColor colorWithRed:0.5 green:1.0 blue:0.6 alpha:1];

    bl.font = [UIFont systemFontOfSize:12];

    bl.numberOfLines = 2;

    bl.textAlignment = NSTextAlignmentCenter;

    bl.text = rb_bubble_text();

    [bb addSubview:bl];

    [bl release];

    gBubbleLbl = bl;

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]

        initWithTarget:self action:@selector(rbExpand:)];

    [bb addGestureRecognizer:tap];

    [tap release];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]

        initWithTarget:self action:@selector(rbDrag:)];

    [bb addGestureRecognizer:pan];

    [pan release];

    [root addSubview:bb];

    [bb release];

    gBubble = bb;



    // —— 展开后的完整面板 ——

    UIView *v = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 330, 334)];

    v.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.94];

    v.layer.cornerRadius = 10;

    v.clipsToBounds = YES;

    [root addSubview:v];

    [v release];

    gPanelView = v;



    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(12, 10, 300, 132)];

    lbl.textColor = [UIColor whiteColor];

    lbl.font = [UIFont systemFontOfSize:11];

    lbl.numberOfLines = 0;

    lbl.text = rb_status_text();

    [v addSubview:lbl];

    [lbl release];

    gLbl = lbl;



    // 「自动连接」开关：开 = 一直保持连接（断了自动拉起，抹完自动接回）；

    // 关 = 立刻断开并且再也不自动连。不用再去点 App 里那个连接按钮。

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(12, 146, 51, 31)];

    sw.on = rb_auto_on() ? YES : NO;

    [sw addTarget:self action:@selector(rbAuto:) forControlEvents:UIControlEventValueChanged];

    [v addSubview:sw];

    [sw release];



    UILabel *sl = [[UILabel alloc] initWithFrame:CGRectMake(72, 146, 200, 31)];

    sl.text = @"自动连接（开=常连，关=断开不用）";

    sl.textColor = [UIColor colorWithRed:0.6 green:1.0 blue:0.6 alpha:1];

    sl.font = [UIFont systemFontOfSize:11];

    [v addSubview:sl];

    [sl release];



    UIButton *b1 = [UIButton buttonWithType:UIButtonTypeSystem];

    b1.frame = CGRectMake(12, 184, 132, 32);

    b1.backgroundColor = [UIColor colorWithRed:0.85 green:0.2 blue:0.2 alpha:1];

    [b1 setTitle:@"立即抹数据重来" forState:UIControlStateNormal];

    [b1 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

    b1.titleLabel.font = [UIFont systemFontOfSize:12];

    [b1 addTarget:self action:@selector(rbWipe:) forControlEvents:UIControlEventTouchUpInside];

    [v addSubview:b1];



    UIButton *b2 = [UIButton buttonWithType:UIButtonTypeSystem];

    b2.frame = CGRectMake(150, 184, 62, 32);

    b2.backgroundColor = [UIColor colorWithWhite:0.3 alpha:1];

    [b2 setTitle:@"重连" forState:UIControlStateNormal];

    [b2 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

    b2.titleLabel.font = [UIFont systemFontOfSize:12];

    [b2 addTarget:self action:@selector(rbReconn:) forControlEvents:UIControlEventTouchUpInside];

    [v addSubview:b2];



    UIButton *b3 = [UIButton buttonWithType:UIButtonTypeSystem];

    b3.frame = CGRectMake(218, 184, 48, 32);

    b3.backgroundColor = [UIColor colorWithWhite:0.3 alpha:1];

    [b3 setTitle:@"刷新" forState:UIControlStateNormal];

    [b3 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

    b3.titleLabel.font = [UIFont systemFontOfSize:12];

    [b3 addTarget:self action:@selector(rbRefresh:) forControlEvents:UIControlEventTouchUpInside];

    [v addSubview:b3];



    UIButton *b4 = [UIButton buttonWithType:UIButtonTypeSystem];

    b4.frame = CGRectMake(272, 184, 46, 32);

    b4.backgroundColor = [UIColor colorWithWhite:0.3 alpha:1];

    [b4 setTitle:@"收起" forState:UIControlStateNormal];

    [b4 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];

    b4.titleLabel.font = [UIFont systemFontOfSize:12];

    [b4 addTarget:self action:@selector(rbCollapse:) forControlEvents:UIControlEventTouchUpInside];

    [v addSubview:b4];

    UIButton *b5 = [UIButton buttonWithType:UIButtonTypeSystem];
    b5.frame = CGRectMake(12, 222, 306, 30);
    b5.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
    [b5 setTitle:@"导出节点信息" forState:UIControlStateNormal];
    [b5 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b5.titleLabel.font = [UIFont systemFontOfSize:12];
    [b5 addTarget:self action:@selector(rbExport:) forControlEvents:UIControlEventTouchUpInside];
    [v addSubview:b5];

    UIButton *b6 = [UIButton buttonWithType:UIButtonTypeSystem];
    b6.frame = CGRectMake(12, 258, 150, 30);
    b6.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
    [b6 setTitle:@"节点测速" forState:UIControlStateNormal];
    [b6 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b6.titleLabel.font = [UIFont systemFontOfSize:12];
    [b6 addTarget:self action:@selector(rbSpeed:) forControlEvents:UIControlEventTouchUpInside];
    [v addSubview:b6];

    UIButton *b7 = [UIButton buttonWithType:UIButtonTypeSystem];
    b7.frame = CGRectMake(168, 258, 150, 30);
    b7.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
    [b7 setTitle:@"导出配置键" forState:UIControlStateNormal];
    [b7 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b7.titleLabel.font = [UIFont systemFontOfSize:12];
    [b7 addTarget:self action:@selector(rbPrefs:) forControlEvents:UIControlEventTouchUpInside];

    [v addSubview:b7];

    UIButton *b8 = [UIButton buttonWithType:UIButtonTypeSystem];
    b8.frame = CGRectMake(12, 294, 306, 30);
    b8.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
    [b8 setTitle:@"换节点（丢旧节点重申请）" forState:UIControlStateNormal];
    [b8 setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b8.titleLabel.font = [UIFont systemFontOfSize:12];
    [b8 addTarget:self action:@selector(rbNodeRot:) forControlEvents:UIControlEventTouchUpInside];
    [v addSubview:b8];



    v.hidden = YES;      // 默认收起成球

    gExpanded = 0;

}

- (void)rbWipe:(id)sender    { (void)sender; rb_wipe_now(); }
- (void)rbExport:(id)sender  { (void)sender; rb_export_nodes(); }
- (void)rbSpeed:(id)sender   { (void)sender; rb_node_speedtest(); }
- (void)rbPrefs:(id)sender   { (void)sender; rb_prefs_dump(); }

- (void)rbNodeRot:(id)sender { (void)sender; rb_node_rotate(); }

- (void)rbRefresh:(id)sender { (void)sender; rb_panel_refresh(); }

- (void)rbExpand:(id)sender  { (void)sender; rb_panel_set_expanded(1); }

- (void)rbCollapse:(id)sender{ (void)sender; rb_panel_set_expanded(0); }

- (void)rbAuto:(id)sender    { rb_auto_set(((UISwitch *)sender).on ? YES : NO); }

- (void)rbReconn:(id)sender  {

    (void)sender;

    rb_log("面板：手动重连（换一条路）");

    rb_stop_vpn();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{ rb_start_vpn_once(1); });

}

// 拖动悬浮球：想把球挪开就挪，App 的按钮不会被挡住

- (void)rbDrag:(UIPanGestureRecognizer *)g {

    if (!gWin) return;

    CGPoint d = [g translationInView:gWin];

    if (g.state == UIGestureRecognizerStateBegan || gBubblePos.x < 0) {

        CGPoint c = gWin.center;

        gBubblePos = c;

    }

    gBubblePos = CGPointMake(gBubblePos.x + d.x, gBubblePos.y + d.y);

    [g setTranslation:CGPointZero inView:gWin];

    CGRect f = gWin.frame;

    f.origin.x = gBubblePos.x - f.size.width / 2;

    f.origin.y = gBubblePos.y - f.size.height / 2;

    gWin.frame = f;

}

@end



// 展开 / 收起：改窗口尺寸，切两个子视图。小球永远不会消失。

static void rb_panel_set_expanded(int on) {

    if (!gWin) return;

    gExpanded = on ? 1 : 0;

    @try {

        CGRect f = [UIScreen mainScreen].bounds;

        CGFloat wdt = MIN(330.0, f.size.width - 16.0);

        CGFloat top = f.size.height >= 812 ? 56.0 : 28.0;

        CGRect fr;

        if (on) {

            fr = CGRectMake(8, top, wdt, 334);

        } else {

            CGFloat x = (gBubblePos.x > 0) ? gBubblePos.x - 28

                                           : f.size.width - 8 - 56;

            CGFloat y = (gBubblePos.y > 0) ? gBubblePos.y - 28 : top;

            fr = CGRectMake(x, y, 56, 56);

        }

        gWin.frame = fr;

        gWin.rootViewController.view.frame = gWin.bounds;

        if (gBubble)    gBubble.frame = on ? CGRectMake(0, 0, 0, 0) : gWin.bounds;

        if (gBubble)    gBubble.hidden = on ? YES : NO;

        if (gPanelView) gPanelView.hidden = on ? NO : YES;

        rb_panel_refresh();

    } @catch (NSException *e) { }

}



static void rb_panel_tick(void) {

    if (!gWin) return;

    if (!gWin.hidden) {

        if (gExpanded) rb_panel_refresh();

        if (gBubbleLbl) gBubbleLbl.text = rb_bubble_text();

    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{ rb_panel_tick(); });

}



// v53：之前面板「日志说显示了但你根本看不到」的真凶 —— iOS 13 起 [[UIWindow alloc]

// initWithFrame:] 造出来的窗口不挂在任何 UIWindowScene 上，系统不会把它合成到屏幕，

// 于是代码一路走完、日志照打，屏幕上什么都没有。必须拿 foregroundActive 的

// UIWindowScene 来 initWithWindowScene:。

static id rb_active_scene(void) {

    UIApplication *app = [UIApplication sharedApplication];

    if (!app) return nil;

    if (@available(iOS 13.0, *)) {

        id fallback = nil;

        for (UIScene *s in [app connectedScenes]) {

            if (![s isKindOfClass:[UIWindowScene class]]) continue;

            if (s.activationState == UISceneActivationStateForegroundActive) return s;

            if (!fallback) fallback = s;

        }

        return fallback;

    }

    return nil;

}



static void rb_panel_bring_front(void) {

    if (!gWin) return;

    @try {

        if (@available(iOS 13.0, *)) {

            id s2 = rb_active_scene();

            if (s2 && gWin.windowScene != (UIWindowScene *)s2) return;

        }

        [gWin makeKeyAndVisible];

    } @catch (NSException *e) { }

}



static void rb_install_panel(void) {

    if (gWin) return;

    @try {

        id scene = rb_active_scene();

        CGRect f = [UIScreen mainScreen].bounds;

        CGFloat wdt = MIN(330.0, f.size.width - 16.0);

        CGFloat top = f.size.height >= 812 ? 56.0 : 28.0;   // 刘海/灵动岛往下让一让

        // v58：初始就是球的大小，展开时再放大

        CGRect fr = CGRectMake(f.size.width - 8 - 56, top, 56, 56);



        if (!scene) {

            // 还在后台：等 App 真正进前台再装一次

            if (!gPanelObs) {

                gPanelObs = 1;

                rb_log("面板：还没拿到前台 scene，等 App 进前台再装");

                [[NSNotificationCenter defaultCenter]

                    addObserverForName:UIApplicationDidBecomeActiveNotification

                                object:nil

                                 queue:[NSOperationQueue mainQueue]

                            usingBlock:^(NSNotification *n) {

                    (void)n; rb_install_panel();

                }];

            }

            return;

        }



        UIWindow *w = nil;

        if (@available(iOS 13.0, *)) {

            w = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];

            w.frame = fr;

        }

        if (!w) w = [[UIWindow alloc] initWithFrame:fr];



        w.backgroundColor = [UIColor clearColor];

        w.windowLevel = UIWindowLevelAlert + 100;   // 压过 App 自己的浮层

        w.userInteractionEnabled = YES;

        RbPanelVC *vc = [[RbPanelVC alloc] init];

        vc.view.frame = w.bounds;

        w.rootViewController = vc;

        [vc release];

        w.hidden = NO;

        gWin = w;

        rb_panel_set_expanded(0);

        rb_log("悬浮球已显示（右上角，可拖动）：点一下展开面板，里面有「立即抹数据重来」");



        // 每次回前台都重新置顶，防止被 App 自己的 window / 弹窗盖掉

        [[NSNotificationCenter defaultCenter]

            addObserverForName:UIApplicationDidBecomeActiveNotification

                        object:nil

                         queue:[NSOperationQueue mainQueue]

                    usingBlock:^(NSNotification *n) {

            (void)n; rb_panel_bring_front();

        }];

        rb_panel_tick();

    } @catch (NSException *e) {

        rb_log("面板创建失败（不影响后台逻辑）：%s", [[e reason] UTF8String]);

    }

}

#endif



#pragma mark - 手动扳机



static void rb_check_trigger(void) {

#if RB_TRIGGER_FILE

    NSString *t = [NSHomeDirectory() stringByAppendingPathComponent:

                   [@"Documents/" stringByAppendingString:RB_TRIGGER]];

    NSFileManager *fm = [NSFileManager defaultManager];

    if ([fm fileExistsAtPath:t]) {

        [fm removeItemAtPath:t error:NULL];

        rb_log("发现手动扳机 Documents/%s，立即抹数据", RB_TRIGGER_C);

        rb_fire("手动扳机", YES);

    }

#endif

}



static void rb_tick(void) {

    if (gStopped) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

            rb_check_trigger();

#if RB_FALLBACK_ON

            double last = [[rb_state() objectForKey:@"lastWipeTs"] doubleValue];

            double now  = rb_now();

            if (last > 0 && (now - last) > RB_WIPE_MAX_HOURS * 3600.0) {

                rb_log("兜底：距上次抹除 %.1f 小时，超过 %.1f 小时，抹一次",

                       (now - last) / 3600.0, (double)RB_WIPE_MAX_HOURS);

                rb_fire("兜底间隔", YES);

            }

#endif

        }

        rb_tick();

    });

}



#pragma mark - 入口



__attribute__((constructor))

static void rb_init(void) {

    @autoreleasepool {

        gBootAt = rb_now();

        if (rb_just_wiped()) {

            // v70：照常写回节点文件（否则 App 一定弹节点选择页、要你手点），
            // 但写回时授权串已被作废 —— 有节点、无有效授权，让 App 用新身份重新签发。
            rb_log("这次是抹数据后启动：写回节点文件但作废旧授权串，"
                   "让 App 用新身份重新签发（不弹节点选择页）");

            rb_node_files_restore();

            rb_prefs_restore();

            // App 一旦自己重新签发并重写文件，立刻拉隧道
            rb_node_watch_new(RB_NODE_WATCH_MAX);

        } else {

            // v66：节点文件/配置键的恢复提到第一行同步做 —— 之前放在 10 秒后，
            // 但系统 on-demand 在 1 秒内就把隧道拉起了（v65 日志 101->105 行），
            // provider 起来时节点文件还没写回 → 永远卡「连接中」。
            rb_node_files_restore();

            rb_prefs_restore();

        }

        double now = gBootAt;



        NSMutableDictionary *st = rb_state();



        // 闪退循环自愈：12 秒内反复重启超过 RB_MAX_BOOT_LOOP 次 → 全部停用。

        // 这样即使问题不是我们引起的，shim 也不会继续添乱。

        double bts = [[st objectForKey:@"bootTs"] doubleValue];

        int    bct = [[st objectForKey:@"bootCount"] intValue];

        bct = (bts > 0 && now - bts < 12.0) ? bct + 1 : 1;

        [st setObject:[NSNumber numberWithInt:bct] forKey:@"bootCount"];

        [st setObject:[NSNumber numberWithDouble:now] forKey:@"bootTs"];



        if ([[st objectForKey:@"autoOff"] boolValue]) gStopped = 1;

        if (bct > RB_MAX_BOOT_LOOP) {

            gStopped = 1;

            [st setObject:[NSNumber numberWithBool:YES] forKey:@"autoOff"];

            rb_log("12 秒内第 %d 次启动 —— 判定为闪退循环，自动停用全部功能", bct);

        }

        if (gStopped) {

            rb_log("rb-shim v76 已停用（只读转发，不做任何事）pid=%d", (int)getpid());

            rb_state_save(st);

        } else {

            rb_log("rb-shim v76 已加载 pid=%d（已抹除 %d 次，本次启动第 %d 次，"

                   "流量阈值 %.0f MB）",

                   (int)getpid(), [[st objectForKey:@"wipeCount"] intValue], bct,

                   (double)rb_quota_limit() / 1048576.0);

        }

        rb_state_save(st);



        if (!load_orig()) rb_log("原实现加载失败，App 可能连不上");



        // v55：快速通道不再只认 pendingStart。上次抹除之后还没稳定跑满

        // RB_FAST_LANE_SEC 秒就又起来了（中间那次进程崩了），新进程同样该走快速通道

        // —— 否则崩一次就掉回 60 秒冷却，又得你手动进 App。

        double steady = [[st objectForKey:@"steadyTs"] doubleValue];

        double lastW = [[st objectForKey:@"lastWipeTs"] doubleValue];

        BOOL postWipe = !gStopped && lastW > 0 && lastW > steady;



        // 「自动连接」开关：第一次跑用配置里的默认值，之后都按你面板上设的来

        id av = [st objectForKey:@"autoConnect"];

        gAutoOn = av ? ([av boolValue] ? 1 : 0) : (RB_AUTO_CONNECT ? 1 : 0);

        if (!av) {

            [st setObject:[NSNumber numberWithBool:(gAutoOn ? YES : NO)]

                   forKey:@"autoConnect"];

            rb_state_save(st);

        }

        rb_log("自动连接开关：%s", gAutoOn ? "开" : "关");



        if (!gStopped && [[st objectForKey:@"pendingStart"] boolValue]) {

            [st removeObjectForKey:@"pendingStart"];

            rb_state_save(st);

        }



        if (postWipe) {

            gFastLane = 1;

            rb_log("抹除后重开：进入快速通道（宽限 %.0fs / 冷却 %.0fs），即将自动重连",

                   (double)RB_GRACE_FAST_SEC, (double)RB_COOL_FAST_SEC);

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,

                                         (int64_t)(RB_FAST_LANE_SEC * NSEC_PER_SEC)),

                           dispatch_get_main_queue(), ^{

                if (gFastLane) {

                    gFastLane = 0;

                    NSMutableDictionary *s2 = rb_state();

                    [s2 setObject:[NSNumber numberWithDouble:rb_now()] forKey:@"steadyTs"];

                    rb_state_save(s2);

                    rb_log("已稳定运行 %.0f 秒，退出快速通道（恢复冷却 %.0f 秒）",

                           (double)RB_FAST_LANE_SEC, (double)RB_COOL_SEC);

                }

            });

#if RB_AUTO_RECONNECT

            // v73：rb-shim(15) 第 58 行（我们抢先 startVPNTunnel）早于第 59 行
            // （App 才把节点文件从 280 字节补成带授权串的 319 字节）—— 隧道拿
            // 「没有授权串」的那份文件起，服务端按无授权压到 160Kbps 档，这就是
            // 抹完只剩 21.2 KB/s 的直接原因（同一个节点抹除前能跑 4931 KB/s）。
            // 抹完之后先等 App 自己重写完（rb_node_watch_new 盯着），等不到再兜底。
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)(RB_POST_WIPE_FALLBACK_SEC * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{

                @autoreleasepool {

                    if (gPostWipeWatchFired) {

                        rb_log("抹后流程：App 已自己重写节点文件并由 watch 拉起隧道，兜底不动手");

                    } else {

                        rb_log("抹后兜底：%.0f 秒内 App 没重写节点文件 —— 走正常自动重连",

                               (double)RB_POST_WIPE_FALLBACK_SEC);

                        rb_auto_start_vpn(0);

                    }

                }

            });

#endif

        }



        if (gAutoOn) {

            // 开着常连：把 iOS 系统级的 on-demand 常连规则装上，之后连不连由系统管

#if RB_ONDEMAND_CONNECT

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),

                           dispatch_get_main_queue(), ^{ rb_set_ondemand(YES); });

#endif

        }



        // 顺手把 VPN 凭据项记下来，待会儿清 keychain 时好跳过它

        rb_collect_vpn_kc();



        // 流量基线：首次安装时从当前读数起算（抹除时 rb_fire 已经重设过一次，

        // utun 若被重建则由 rb_flow_tick 里的 cur<base 分支自动兜住）

        if (!gStopped && [st objectForKey:@"flowBase"] == nil) rb_flow_rebase();

    }



    if (gStopped) return;



    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool { rb_check_trigger(); }

        rb_flow_tick();

        rb_tick();

        rb_keepalive_boot();

        if (rb_auto_on()) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool { if (!rb_just_wiped()) { rb_node_files_restore(); rb_prefs_restore(); }
                               rb_prefs_dump(); rb_export_nodes(); }
        });

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(28 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool { rb_node_speedtest(); }
        });

            // 开着常连：进来就保证隧道是连着的（on-demand 装在 4 秒后，start 在 6 秒后）

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),

                           dispatch_get_main_queue(), ^{ rb_start_vpn_once(0); });

        }

    });



    // 面板晚一点装：等 App 自己的 UI 起来再盖一层，避免抢在初始化之前出事

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),

                   dispatch_get_main_queue(), ^{

        @autoreleasepool {

#if RB_PANEL

            rb_install_panel();

#endif

        }

    });

}

