// 訂閱端拿不拿得到發送者的 GUID？
//
// 這決定 IDS↔SROS2 第二層（可撤銷的應用層黑名單）做不做得成：有黑名單卻不
// 知道訊息來自誰，就無法丟棄，而不可逆的 `ignore_participant` 不符合本專題
// 「可恢復回應」的要求。
//
// 已知：
//   * `rmw_message_info_t` 有 `publisher_gid`（16 bytes，DDS GUID 剛好是
//     12 byte prefix ＋ 4 byte entity）。
//   * **rclpy 沒有把它露出來**——2026-08-26 實測，Python 的 message_info 只有
//     publication_sequence_number／received_timestamp／reception_sequence_number
//     ／source_timestamp 四個鍵。而 monitor_node 是 Python 寫的。
//   * `rclcpp::MessageInfo::get_rmw_message_info()` 回傳完整結構。
//
// 但「結構有這個欄位」不等於「rmw_fastrtps 有填」。這支就是去驗那件事，
// 並且把 GUID 印出來，好與 security_observer 看到的 GUID 對照。
//
// 只訂閱、不發布，不影響受測系統。

#include <cstdio>
#include <memory>
#include <string>

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

}  // namespace

class GidProbe : public rclcpp::Node {
public:
    GidProbe() : Node("gid_probe") {
        const std::string topic =
            declare_parameter<std::string>("probe_topic", "chatter");
        subscription_ = create_subscription<std_msgs::msg::String>(
            topic, 10,
            [this](std_msgs::msg::String::ConstSharedPtr message,
                   const rclcpp::MessageInfo& info) {
                const auto& raw = info.get_rmw_message_info();
                const std::string gid =
                    to_hex(raw.publisher_gid.data, RMW_GID_STORAGE_SIZE);
                // 全零代表 rmw 沒有填——那和「拿不到」是一樣的結果。
                const bool populated = gid.find_first_not_of('0') != std::string::npos;
                if (seen_.insert(gid).second) {
                    std::printf(
                        "publisher_gid=%s  populated=%s  prefix12=%s  impl=%s\n",
                        gid.c_str(), populated ? "yes" : "NO",
                        gid.substr(0, 24).c_str(),
                        raw.publisher_gid.implementation_identifier
                            ? raw.publisher_gid.implementation_identifier
                            : "(null)");
                    std::fflush(stdout);
                }
                static_cast<void>(message);
            });
    }

private:
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscription_;
    std::set<std::string> seen_;
};

int main(int argc, char** argv) {
    rclcpp::init(argc, argv);
    auto node = std::make_shared<GidProbe>();
    rclcpp::spin(node);
    rclcpp::shutdown();
    return 0;
}
