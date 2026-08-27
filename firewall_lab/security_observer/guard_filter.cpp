// 第二層：依發送者 GUID 丟棄訊息的**可撤銷**守衛（原型）。
//
// 為什麼是這一層
// --------------
// 三層回應鏈裡（見 文件/IDS與SROS2協作設計_2026-08-26.md）：
//
//   密碼學證據（認證失敗） → DDS ignore_participant  ❌ 不可逆
//   行為證據（IDS 判定）   → **本層**                ✅ 可撤銷
//   網路證據（持續濫用）   → nftables                需 root ＋ IP 歸因
//
// 設計原則是「動作的不可逆程度必須配得上證據的確定程度」。IDS 的判定是統計
// 的、會錯（處女 holdout recall 只有 0.0273），所以它只能觸發可撤銷的動作。
// `ignore_participant` 不可逆，一次誤判就永久封鎖到重啟為止，不符合本專題
// 「可恢復回應」的要求。
//
// 為什麼用 C++
// ------------
// 2026-08-26 實測：`publisher_gid` 在 rclpy 完全沒有露出（message_info 只有
// 四個時間／序號欄位），只有 rclcpp 拿得到，而且 rmw_fastrtps 確實有填。
// 沒有發送者身份就無法依身份丟棄，所以這一層只能用 C++ 寫。
//
// 黑名單為什麼用檔案
// ------------------
// 不用 ROS topic：控制訊息不該走在攻擊者所在的那條匯流排上。檔案可稽核、
// 可撤銷、重啟後仍在，與本專案既有的 fault seam 慣例一致。
//
// 邊界
// ----
// * **原型**：只做判定與量測，不轉送訊息。要真的擋在資料路徑上必須改變拓撲
//   （發送者 → 守衛 → 消費者），那是下一步，不在本檔範圍。
// * 判定一律寫進決策日誌，允許與丟棄都寫——只記丟棄的話就無法分辨
//   「沒有丟棄」與「守衛沒在跑」。

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <cctype>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>

#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>

namespace {

std::string to_hex(const uint8_t* data, size_t length) {
    std::string out;
    char buffer[3];
    for (size_t index = 0; index < length; ++index) {
        std::snprintf(buffer, sizeof(buffer), "%02x", data[index]);
        out += buffer;
    }
    return out;
}

long long now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

}  // namespace

class GuardFilter : public rclcpp::Node {
public:
    GuardFilter() : Node("guard_filter") {
        topic_ = declare_parameter<std::string>("guarded_topic", "chatter");
        blocklist_path_ = declare_parameter<std::string>("blocklist_path", "");
        decisions_path_ = declare_parameter<std::string>("decisions_path", "");
        const double reload_sec =
            declare_parameter<double>("reload_sec", 0.2);

        if (blocklist_path_.empty() || decisions_path_.empty()) {
            // 沒有黑名單就等於沒有守衛。安靜地放行所有訊息比直接失敗更糟，
            // 所以這裡大聲失敗。
            RCLCPP_FATAL(get_logger(),
                         "blocklist_path and decisions_path are required");
            throw std::runtime_error("guard_filter requires both paths");
        }

        decisions_.open(decisions_path_, std::ios::app);
        reload();

        subscription_ = create_subscription<std_msgs::msg::String>(
            topic_, 10,
            [this](std_msgs::msg::String::ConstSharedPtr message,
                   const rclcpp::MessageInfo& info) {
                on_message(message, info);
            });

        timer_ = create_wall_timer(
            std::chrono::milliseconds(
                static_cast<int>(reload_sec * 1000.0)),
            [this]() { reload(); });

        RCLCPP_INFO(get_logger(), "guarding %s; blocklist %s",
                    topic_.c_str(), blocklist_path_.c_str());
    }

private:
    // 只在 mtime 變動時重讀，避免每 200ms 都做一次檔案 I/O。
    void reload() {
        struct stat info {};
        if (::stat(blocklist_path_.c_str(), &info) != 0) {
            // 檔案不存在 = 空黑名單。這是刻意的：讓「還沒有任何封鎖」
            // 與「黑名單被刪掉」表現一致，都是全部放行。
            if (!blocked_.empty()) {
                blocked_.clear();
                write_reload(0);
            }
            last_mtime_ = 0;
            return;
        }
        if (info.st_mtime == last_mtime_) {
            return;
        }
        last_mtime_ = info.st_mtime;

        // 格式：`<guid_prefix> <ticket_sha256> <expires_unix>`
        //
        // **只有三個欄位齊全的行才算數。** 舊格式的裸 GUID 一律忽略，因為
        // 那種行沒有辦法證明它是授權器發的——任何能寫這個檔的東西都寫得出來。
        // 拒絕它們是這一版的重點，不是相容性疏漏。
        std::map<std::string, double> next;
        std::ifstream handle(blocklist_path_);
        std::string line;
        size_t rejected = 0;
        while (std::getline(handle, line)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }
            std::istringstream fields(line);
            std::string prefix, ticket, expires_text;
            if (!(fields >> prefix >> ticket >> expires_text)) {
                // 全空白的行不算錯，直接略過；欄位不足才是被拒絕的項目。
                if (line.find_first_not_of(" \t\r\n") != std::string::npos) {
                    ++rejected;
                }
                continue;
            }
            std::string extra;
            if (fields >> extra) {
                ++rejected;
                continue;
            }
            std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            std::transform(ticket.begin(), ticket.end(), ticket.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (!is_hex(prefix, 24) || !is_hex(ticket, 64)) {
                ++rejected;
                continue;
            }
            double expires = 0.0;
            try {
                size_t consumed = 0;
                expires = std::stod(expires_text, &consumed);
                if (consumed != expires_text.size()) {
                    ++rejected;
                    continue;
                }
            } catch (const std::exception&) {
                ++rejected;
                continue;
            }
            next.emplace(prefix, expires);
        }
        if (rejected > 0) {
            decisions_ << "{\"event\":\"blocklist_rejected_entries\""
                       << ",\"ts_unix_ns\":" << now_ns()
                       << ",\"count\":" << rejected << "}" << std::endl;
        }
        if (next != blocked_) {
            blocked_ = next;
            write_reload(blocked_.size());
        }
    }

    static bool is_hex(const std::string& value, size_t length) {
        if (value.size() != length) {
            return false;
        }
        for (unsigned char c : value) {
            if (!std::isxdigit(c)) {
                return false;
            }
        }
        return true;
    }

    void write_reload(size_t count) {
        decisions_ << "{\"event\":\"blocklist_reload\",\"ts_unix_ns\":"
                   << now_ns() << ",\"entries\":" << count << "}" << std::endl;
    }

    void on_message(std_msgs::msg::String::ConstSharedPtr message,
                    const rclcpp::MessageInfo& info) {
        static_cast<void>(message);
        const auto& raw = info.get_rmw_message_info();
        const std::string gid =
            to_hex(raw.publisher_gid.data, RMW_GID_STORAGE_SIZE);
        // 前 12 個位元組是 participant 的 GUID prefix；後 4 個是 entity。
        // 黑名單以 participant 為單位，所以比對前綴。
        const std::string prefix = gid.substr(0, 24);

        // 到期檢查在**判定當下**做，不是在重讀時做。
        //
        // 這一條是三道撤銷保證裡最重要的一道：到期不會改變檔案的 mtime，
        // 所以靠重讀永遠不會發現它過期；而且它完全不依賴那個負責撤銷的
        // Python 行程還活著。行程死掉、機器斷線、腳本被 kill——封鎖照樣解除。
        const auto found = blocked_.find(prefix);
        bool blocked = false;
        bool expired = false;
        if (found != blocked_.end()) {
            const double now = now_ns() / 1e9;
            if (now < found->second) {
                blocked = true;
            } else {
                expired = true;
            }
        }

        // 允許與丟棄都要記：只記丟棄的話，無法分辨「沒有丟棄」與
        // 「守衛根本沒在跑」。過期也單獨標記，否則放行看起來像沒有封鎖過。
        decisions_ << "{\"event\":\"decision\",\"ts_unix_ns\":" << now_ns()
                   << ",\"guid_prefix\":\"" << prefix
                   << "\",\"action\":\"" << (blocked ? "drop" : "allow")
                   << "\",\"expired\":" << (expired ? "true" : "false")
                   << "}" << std::endl;
    }

    std::string topic_;
    std::string blocklist_path_;
    std::string decisions_path_;
    std::ofstream decisions_;
    std::map<std::string, double> blocked_;
    time_t last_mtime_ = 0;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscription_;
    rclcpp::TimerBase::SharedPtr timer_;
};

int main(int argc, char** argv) {
    rclcpp::init(argc, argv);
    try {
        rclcpp::spin(std::make_shared<GuardFilter>());
    } catch (const std::exception& error) {
        std::fprintf(stderr, "guard_filter failed: %s\n", error.what());
        rclcpp::shutdown();
        return 1;
    }
    rclcpp::shutdown();
    return 0;
}
