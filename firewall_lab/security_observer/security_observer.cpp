// DDS Security 稽核觀測者。
//
// 為什麼需要它
// ------------
// 2026-08-18 查證的結論（文件/DDS_Security_audit_log_不可用_2026-08-18.md）：
// 一旦啟用 SROS2，`librmw_fastrtps_shared_cpp.so` 會自行從 keystore 組出
// participant 的安全屬性清單，其中只有 dds.sec.auth.* / access.* / crypto.*，
// **沒有 dds.sec.log.plugin**，而且不提供附加額外 property 的途徑。XML profile
// 的 propertiesPolicy 不被保留。因此經由 ROS 建立的 participant 永遠拿不到
// DDS Security 稽核日誌。
//
// 那份文件把「直接用 Fast DDS API」列為不可行，理由是「會失去整個 ROS 生態」。
// 那個判斷針對的是**取代**整個系統，是對的。這支程式是另一個作法：**不取代
// 任何東西，只在旁邊多加一個觀測者**。ROS 堆疊原封不動照跑，這個 participant
// 用 Fast DDS API 直接建立，所以它自己的屬性不會被 rmw 覆蓋，可以同時設定
// 安全外掛與 logging 外掛。
//
// 它做的事只有一件：以合法身分加入同一個 domain，然後把自己遇到的
// DDS Security 事件寫進稽核檔。因為 DDS 的握手是雙向的，當一個憑證由錯誤 CA
// 簽發的 participant（N28）宣告自己時，這個觀測者會嘗試驗證它、失敗，
// 並產生一筆 authentication 記錄——那正是 P2 契約要求的
// `authenticated_identity` 證據來源。
//
// 邊界
// ----
// * 只讀。不發布、不訂閱任何使用者 topic，不影響受測系統。
// * 不需要 root。
// * `distribute=false`：稽核記錄不回送到 DDS 匯流排上——攻擊者就在那條匯流排上。
// * 這支程式**不證明**任何事；它是取得證據的工具。是否真的能記到，
//   要實際跑過才知道，而那需要 Jesse 對該次 live 操作的授權。

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include <fstream>
#include <map>
#include <mutex>

#include <openssl/sha.h>

#include <iomanip>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantListener.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/qos/DomainParticipantQos.hpp>
#include <fastdds/rtps/common/Locator.h>
#include <fastrtps/utils/IPLocator.h>

using eprosima::fastdds::dds::DomainParticipant;
using eprosima::fastdds::dds::DomainParticipantFactory;
using eprosima::fastdds::dds::DomainParticipantQos;
using eprosima::fastdds::dds::DomainParticipantListener;

namespace {

std::atomic<bool> keep_running{true};

void handle_signal(int) {
    keep_running.store(false);
}

// 缺少必要參數時直接失敗，不要靜默退回不安全的預設值。這個專案已經被
// 「設定看起來成功但其實沒生效」咬過好幾次。
std::string required_env(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr || std::string(value).empty()) {
        std::cerr << "missing required environment variable: " << name << "\n";
        std::exit(2);
    }
    return std::string(value);
}

void add_property(DomainParticipantQos& qos, const std::string& name,
                  const std::string& value) {
    qos.properties().properties().emplace_back(name, value);
}

// SPDP discovery 預設走多播 239.255.0.1。有線上沒問題，**Wi-Fi 對 Wi-Fi 常常
// 會被吃掉**——AP 用最低 basic rate 發多播，加上 IGMP snooping 或
// multicast-to-unicast 轉換，封包可能根本不到對面。
//
// 這件事危險的地方不是不通，是它的失敗形態：攻擊者跑滿整個視窗、log 乾乾淨淨、
// 觀測者一筆都沒記到——與「防禦成功攔阻」外觀完全相同。這個專案已經被同一類
// 混淆咬過五次。
//
// 所以支援明確指定 unicast initial peer。指定之後 discovery 不再依賴多播：
// 觀測者會直接對那些位址發 SPDP。這不會關掉多播，只是多一條路。
//
// 注意 ROS 的 ROS_STATIC_PEERS 對這支程式**無效**——它是 rmw_fastrtps 讀的，
// 而這個 participant 是用 Fast DDS API 直接建的，不經 rmw。
//
// 格式：OBSERVER_PEERS="192.168.0.30,192.168.0.31"
// port 留 0，Fast DDS 會自己展開成該 domain 的 well-known participant 埠範圍。
std::size_t add_initial_peers(DomainParticipantQos& qos,
                              const std::string& spec) {
    std::size_t added = 0;
    std::size_t start = 0;
    while (start <= spec.size()) {
        const std::size_t comma = spec.find(',', start);
        std::string item = spec.substr(
            start, comma == std::string::npos ? std::string::npos
                                              : comma - start);
        // 去掉前後空白，避免 "a, b" 這種寫法變成 " b"。
        const std::size_t first = item.find_first_not_of(" \t");
        const std::size_t last = item.find_last_not_of(" \t");
        if (first != std::string::npos) {
            item = item.substr(first, last - first + 1);
            eprosima::fastrtps::rtps::Locator_t peer;
            peer.kind = LOCATOR_KIND_UDPv4;
            peer.port = 0;
            if (eprosima::fastrtps::rtps::IPLocator::setIPv4(peer, item)) {
                qos.wire_protocol().builtin.initialPeersList.push_back(peer);
                ++added;
            } else {
                // 打錯位址時大聲失敗。安靜地忽略一個 peer，症狀會變成
                // 「什麼都沒收到」——正是我們最怕被誤讀的那一種。
                std::cerr << "invalid initial peer address: " << item << "\n";
                std::exit(2);
            }
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return added;
}


// 稽核檔（`dds.sec.log.*`）在 2026-08-26 的實測中只記到**本地**憑證錯誤，
// 即使把 logging_level 開到 DEBUG_LEVEL，遠端握手失敗仍然一筆都沒有。
// 所以改用 listener 回呼：`onParticipantAuthentication` 直接給
// status（AUTHORIZED／UNAUTHORIZED）與遠端 GUID，那正是契約需要的兩個欄位，
// 而且是結構化事件而不是要再解析一次的文字日誌。
//
// 同時記錄 discovery：如果連 discovery 都沒發生，那「沒有認證失敗」的原因
// 是兩邊根本沒見到面，而不是失敗沒被記錄——這兩件事必須分得開。

// 遙測發送端：把身份事件送進 IDS 已經在讀的那條串流。
//
// 這是整個 IDS↔SROS2 接法的 Half A。ROS 把 DDS 身份完全抽象掉，所以偵測層
// 原本說得出「這像攻擊」卻說不出「是哪一個 participant」。協定與
// `runtime_telemetry.py` 相同：Unix SOCK_DGRAM ＋ 一行 JSON。
//
// 刻意重用既有通道而不是另開 IPC：收集器已經在跑、已經寫進 session 的
// telemetry_events.jsonl、特徵抽取也已經讀它。

// GUID prefix 在 Fast DDS 的輸出是點分隔的十六進位位元組（`a2.5a.10...`），
// 但契約要的是 24 個連續小寫十六進位字元。去掉點就是。
std::string compact_guid(const std::string& dotted) {
    std::string out;
    for (char character : dotted) {
        if (character != '.') {
            out.push_back(static_cast<char>(std::tolower(
                static_cast<unsigned char>(character))));
        }
    }
    return out;
}

// 契約存的是 subject 的 SHA-256，不是明文——subject 是憑證的 CN，
// 屬於身份資訊，沒有必要在遙測串流裡以明文流通。
std::string sha256_hex(const std::string& text) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(),
           digest);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char byte : digest) {
        out << std::setw(2) << static_cast<int>(byte);
    }
    return out.str();
}

class TelemetrySink {
public:
    explicit TelemetrySink(const std::string& path) : path_(path) {
        if (path_.empty()) {
            return;
        }
        // 路徑長度上限來自 sun_path；超過就直接不啟用，不要截斷後送到別的地方。
        if (path_.size() >= sizeof(sockaddr_un::sun_path)) {
            std::cerr << "telemetry socket path too long; sink disabled\n";
            return;
        }
        fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    }

    ~TelemetrySink() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    bool enabled() const { return fd_ >= 0; }
    unsigned long sent() const { return sent_; }
    unsigned long dropped() const { return dropped_; }

    // `subject` 空字串代表沒有經驗證的身份，送 JSON null——收集端會拒絕
    // 「已認證卻沒有 subject」與「未認證卻帶 subject」兩種矛盾組合。
    void emit_identity(const std::string& guid_prefix, bool authorized,
                       const std::string& subject) {
        if (fd_ < 0) {
            return;
        }
        std::ostringstream json;
        json << "{\"schema_version\":\"sros2-firewall-runtime-telemetry/v1\""
             << ",\"ts_unix_ns\":" << now_ns()
             << ",\"monotonic_ns\":" << monotonic_ns()
             << ",\"source\":\"security_observer\""
             << ",\"event_type\":\"dds_identity\""
             << ",\"details\":{\"guid_prefix\":\"" << guid_prefix
             << "\",\"subject_sha256\":"
             << (subject.empty() ? "null" : "\"" + subject + "\"")
             << ",\"verdict\":\"" << (authorized ? "authorized" : "unauthorized")
             << "\"}}";
        const std::string payload = json.str();

        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                      path_.c_str());
        const ssize_t written = ::sendto(
            fd_, payload.data(), payload.size(), 0,
            reinterpret_cast<sockaddr*>(&address), sizeof(address));
        if (written == static_cast<ssize_t>(payload.size())) {
            ++sent_;
        } else {
            // 送不出去只計數，不要讓遙測故障影響觀測本身。
            ++dropped_;
        }
    }

private:
    static long long now_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    static long long monotonic_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    std::string path_;
    int fd_ = -1;
    unsigned long sent_ = 0;
    unsigned long dropped_ = 0;
};

class ObserverListener : public DomainParticipantListener {
public:
    ObserverListener(const std::string& path, TelemetrySink& sink)
        : out_(path, std::ios::app), sink_(sink) {}

    void onParticipantAuthentication(
            eprosima::fastdds::dds::DomainParticipant* /*participant*/,
            eprosima::fastrtps::rtps::ParticipantAuthenticationInfo&& info) override {
        const bool authorized =
            info.status == eprosima::fastrtps::rtps::
                           ParticipantAuthenticationInfo::AUTHORIZED_PARTICIPANT;
        std::ostringstream guid_text;
        guid_text << info.guid.guidPrefix;
        const std::string prefix = compact_guid(guid_text.str());
        {
            std::lock_guard<std::mutex> guard(mutex_);
            auto& state = states_[prefix];
            state.verdict_known = true;
            state.authorized = authorized;
            maybe_emit(prefix, state);
        }
        write("participant_authentication",
              authorized ? "AUTHORIZED" : "UNAUTHORIZED", info.guid, "", "");
    }

    void on_participant_discovery(
            eprosima::fastdds::dds::DomainParticipant* /*participant*/,
            eprosima::fastrtps::rtps::ParticipantDiscoveryInfo&& info,
            bool& should_be_ignored) override {
        should_be_ignored = false;
        // identity token 帶 `dds.cert.sn`，也就是憑證的 subject name。
        // 契約的 `identity_subject_sha256` 需要它，而 onParticipantAuthentication
        // 只給 status 與 GUID，拿不到 subject——所以必須從 discovery 這一側取。
        //
        // ⚠️ 這裡取到的 subject 是**對方宣稱的**。只有在同一個 GUID 之後拿到
        // AUTHORIZED 時，那個宣稱才算被密碼學驗證過；UNAUTHORIZED 的 subject
        // 只是一個未經驗證的字串，不可當成身份。兩者的區別由 status 欄位承載。
        // 宣告的 locator。⚠️ 這是**對方自己宣告的位址**，不是封包的實際來源
        // IP——participant 可以宣告任意位址。契約的 claim boundary 說 SPDP
        // 欄位是 spoofable，指的就是這個。真正的歸因要拿封包擷取的來源 IP
        // 與這裡的宣告值交叉比對；兩者不一致本身就是一個訊號。
        std::string locators;
        for (const auto& locator : info.info.metatraffic_locators.unicast) {
            std::ostringstream text;
            text << locator;
            if (!locators.empty()) {
                locators += " ";
            }
            locators += text.str();
        }

        std::string subject;
        for (const auto& property : info.info.identity_token_.properties()) {
            if (property.name() == "dds.cert.sn") {
                subject = property.value();
                break;
            }
        }
        if (!subject.empty()) {
            std::ostringstream prefix_text;
            prefix_text << info.info.m_guid.guidPrefix;
            std::lock_guard<std::mutex> guard(mutex_);
            auto& state = states_[compact_guid(prefix_text.str())];
            state.subject = subject;
            maybe_emit(compact_guid(prefix_text.str()), state);
        }
        write("participant_discovery", std::to_string(info.status),
              info.info.m_guid, subject, locators);
    }


    // Endpoint discovery 產出契約的 `sedp_endpoint` 證據：GUID ＋ entity ＋ topic。
    // 這一層與認證是分開的：一個 participant 可以認證成功，但它宣告的某個
    // endpoint 仍可能因為 permissions 不允許而無法配對。
    void on_publisher_discovery(
            eprosima::fastdds::dds::DomainParticipant* /*participant*/,
            eprosima::fastrtps::rtps::WriterDiscoveryInfo&& info) override {
        write_endpoint("writer", std::to_string(info.status), info.info.guid(),
                       info.info.topicName().to_string());
    }

    void on_subscriber_discovery(
            eprosima::fastdds::dds::DomainParticipant* /*participant*/,
            eprosima::fastrtps::rtps::ReaderDiscoveryInfo&& info) override {
        write_endpoint("reader", std::to_string(info.status), info.info.guid(),
                       info.info.topicName().to_string());
    }

private:
    void write_endpoint(const std::string& role, const std::string& status,
                        const eprosima::fastrtps::rtps::GUID_t& guid,
                        const std::string& topic) {
        std::ostringstream guid_text;
        guid_text << guid;
        std::lock_guard<std::mutex> guard(mutex_);
        out_ << "{\"event\":\"endpoint_discovery\",\"role\":\"" << role
             << "\",\"status\":\"" << status
             << "\",\"guid\":\"" << guid_text.str()
             << "\",\"topic\":\"" << topic << "\"}" << std::endl;
    }

    void write(const std::string& kind, const std::string& status,
               const eprosima::fastrtps::rtps::GUID_t& guid,
               const std::string& subject, const std::string& locators) {
        std::ostringstream guid_text;
        guid_text << guid;
        std::lock_guard<std::mutex> guard(mutex_);
        out_ << "{\"event\":\"" << kind << "\",\"status\":\"" << status
             << "\",\"guid\":\"" << guid_text.str()
             << "\",\"claimed_subject\":\"" << subject
             << "\",\"announced_locators\":\"" << locators << "\"}" << std::endl;
    }

    // 認證判定與 subject 來自兩個不同的回呼，**而且順序不固定**：實測
    // onParticipantAuthentication 通常先於 on_participant_discovery，所以在
    // 認證當下 subject 往往還沒到手。先前的版本在那個時點就送出，於是合法
    // 節點被送成「authorized 但沒有 subject」，被收集端正確地拒絕、事件掉了。
    //
    // 現在改成兩邊都到齊才發，而且每個 GUID 只發一次。
    struct IdentityState {
        bool verdict_known = false;
        bool authorized = false;
        bool emitted = false;
        std::string subject;
    };

    // 呼叫前必須持有 mutex_。
    void maybe_emit(const std::string& prefix, IdentityState& state) {
        if (state.emitted || !state.verdict_known) {
            return;
        }
        if (state.authorized) {
            // 通過認證卻說不出身份的記錄沒有意義，等 subject 到齊。
            if (state.subject.empty()) {
                return;
            }
            sink_.emit_identity(prefix, true, sha256_hex(state.subject));
        } else {
            // 認證失敗的沒有經驗證的 subject，這是實測結果不是設計選擇。
            sink_.emit_identity(prefix, false, "");
        }
        state.emitted = true;
    }

    std::mutex mutex_;
    std::ofstream out_;
    TelemetrySink& sink_;
    std::map<std::string, IdentityState> states_;
};

}  // namespace

int main(int argc, char** argv) {
    const int domain_id = (argc > 1) ? std::atoi(argv[1]) : 30;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 60;

    // 憑證由 SROS2 keystore 提供。刻意用環境變數而不是寫死路徑，
    // 這樣觀測者可以用自己的 enclave，不必借用其他節點的身分。
    const std::string identity_ca = required_env("OBSERVER_IDENTITY_CA");
    const std::string certificate = required_env("OBSERVER_CERTIFICATE");
    const std::string private_key = required_env("OBSERVER_PRIVATE_KEY");
    const std::string governance = required_env("OBSERVER_GOVERNANCE");
    const std::string permissions = required_env("OBSERVER_PERMISSIONS");
    const std::string permissions_ca = required_env("OBSERVER_PERMISSIONS_CA");
    const std::string audit_log = required_env("OBSERVER_AUDIT_LOG");

    // 等級由 EMERGENCY（最嚴重）排到 DEBUG；「等於或嚴重於」設定值的才會被記。
    // 預設 WARNING_LEVEL 會漏掉 NOTICE 以下的事件——2026-08-26 的第一次實驗
    // 就是這樣：本地憑證錯誤（EMERGENCY）記到了，遠端握手失敗卻沒有。
    // 所以做成可設定，先用 DEBUG_LEVEL 確認事件到底存不存在，再談過濾。
    const char* level_env = std::getenv("OBSERVER_LOG_LEVEL");
    const std::string logging_level =
        (level_env != nullptr && *level_env != 0) ? level_env : "WARNING_LEVEL";

    DomainParticipantQos qos;
    qos.name("sros2_firewall_security_observer");

    // 安全外掛：與 rmw 會設的那一組相同，差別在於我們自己設，所以不會被覆蓋。
    add_property(qos, "dds.sec.auth.plugin", "builtin.PKI-DH");
    add_property(qos, "dds.sec.auth.builtin.PKI-DH.identity_ca",
                 "file://" + identity_ca);
    add_property(qos, "dds.sec.auth.builtin.PKI-DH.identity_certificate",
                 "file://" + certificate);
    add_property(qos, "dds.sec.auth.builtin.PKI-DH.private_key",
                 "file://" + private_key);
    add_property(qos, "dds.sec.access.plugin", "builtin.Access-Permissions");
    add_property(qos, "dds.sec.access.builtin.Access-Permissions.governance",
                 "file://" + governance);
    add_property(qos, "dds.sec.access.builtin.Access-Permissions.permissions",
                 "file://" + permissions);
    add_property(qos, "dds.sec.access.builtin.Access-Permissions.permissions_ca",
                 "file://" + permissions_ca);
    add_property(qos, "dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC");

    // 這四個就是 rmw 不會幫你設、也不讓你附加的那一組。
    // 屬性名稱取自安裝版二進位：logging_level 與 log_file 才是對的拼法，
    // log_level 與 logging_file 在 libfastrtps.so 裡不存在，寫錯會被靜默忽略。
    add_property(qos, "dds.sec.log.plugin", "builtin.DDS_LogTopic");
    add_property(qos, "dds.sec.log.builtin.DDS_LogTopic.logging_level",
                 logging_level);
    add_property(qos, "dds.sec.log.builtin.DDS_LogTopic.log_file", audit_log);
    // 不要把稽核記錄再發回 DDS 匯流排——攻擊者就在那條匯流排上。
    add_property(qos, "dds.sec.log.builtin.DDS_LogTopic.distribute", "false");

    // 跨主機且兩端都在 Wi-Fi 時建議指定，見 add_initial_peers 的說明。
    const char* peers_env = std::getenv("OBSERVER_PEERS");
    std::size_t peer_count = 0;
    if (peers_env != nullptr && *peers_env != 0) {
        peer_count = add_initial_peers(qos, peers_env);
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // 事件檔與稽核檔分開：稽核檔是 Fast DDS 自己寫的，事件檔是 listener 寫的。
    // 兩者都留著，才能分辨「沒有事件」與「事件沒被記錄」。
    const char* events_env = std::getenv("OBSERVER_EVENTS_LOG");
    // 遙測是**選用**的：沒設就只寫事件檔。這樣觀測者可以獨立跑，
    // 不強迫每次都要先把收集器拉起來。
    const char* telemetry_env = std::getenv("SROS2_FIREWALL_TELEMETRY_SOCKET");
    TelemetrySink sink(telemetry_env != nullptr ? telemetry_env : "");
    ObserverListener listener(
        (events_env != nullptr && *events_env != 0)
            ? events_env
            : audit_log + ".events.jsonl",
        sink);

    DomainParticipant* participant =
        DomainParticipantFactory::get_instance()->create_participant(
            domain_id, qos, &listener);
    if (participant == nullptr) {
        // 建立失敗最常見的原因是憑證鏈不對或 governance 不允許加入。
        // 這種情形必須大聲失敗：安靜地跑起來但沒有安全，比直接失敗更糟。
        std::cerr << "failed to create secure participant on domain "
                  << domain_id << "\n";
        return 1;
    }

    std::cout << "security observer running on domain " << domain_id
              << " for " << seconds << "s; audit log: " << audit_log << "\n";
    if (peer_count > 0) {
        std::cout << "unicast initial peers: " << peer_count
                  << " (discovery does not depend on multicast)\n";
    } else {
        std::cout << "discovery via multicast only "
                     "(set OBSERVER_PEERS for Wi-Fi links)\n";
    }
    std::cout << std::flush;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (keep_running.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    DomainParticipantFactory::get_instance()->delete_participant(participant);
    std::cout << "security observer stopped\n" << std::flush;
    return 0;
}
