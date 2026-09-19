#include <chrono>
#include <cmath>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>

#include "rclcpp/rclcpp.hpp"
#include "rclcpp_action/rclcpp_action.hpp"
#include "nav2_msgs/action/navigate_to_pose.hpp"

using namespace std::chrono_literals;

class NavClient : public rclcpp::Node
{
public:
    using NavigateToPose = nav2_msgs::action::NavigateToPose;
    using GoalHandleNav = rclcpp_action::ClientGoalHandle<NavigateToPose>;

    NavClient() : Node("nav_to_pose_client")
    {
        this->client_ptr_ = rclcpp_action::create_client<NavigateToPose>(this, "navigate_to_pose");
    }

    bool send_goal(double x, double y)
    {
        if (!this->client_ptr_->wait_for_action_server(10s))
        {
            RCLCPP_ERROR(this->get_logger(), "找不到 Nav2 Action Server！請確認導航系統已啟動。");
            return false;
        }

        auto goal_msg = NavigateToPose::Goal();
        goal_msg.pose.header.frame_id = "map";
        goal_msg.pose.header.stamp = this->now();

        // 設定目標座標 (X, Y)
        goal_msg.pose.pose.position.x = x;
        goal_msg.pose.pose.position.y = y;
        goal_msg.pose.pose.orientation.w = 1.0;

        RCLCPP_INFO(this->get_logger(), "DSS 決策發送目標: X=%.2f, Y=%.2f", x, y);

        auto send_goal_options = rclcpp_action::Client<NavigateToPose>::SendGoalOptions();
        send_goal_options.goal_response_callback =
            [this](const GoalHandleNav::SharedPtr & goal_handle)
            {
                if (!goal_handle) {
                    RCLCPP_ERROR(this->get_logger(), "Nav2 拒絕目標，程式結束。");
                    this->finish(3);
                    rclcpp::shutdown();
                    return;
                }
                this->goal_handle_ = goal_handle;
                RCLCPP_INFO(this->get_logger(), "Nav2 已接受目標。");
            };
        send_goal_options.result_callback =
            [this](const GoalHandleNav::WrappedResult & result)
            {
                switch (result.code) {
                    case rclcpp_action::ResultCode::SUCCEEDED:
                        RCLCPP_INFO(this->get_logger(), "導航目標已完成。");
                        this->finish(0);
                        break;
                    case rclcpp_action::ResultCode::ABORTED:
                        RCLCPP_ERROR(this->get_logger(), "導航目標遭 Nav2 中止。");
                        this->finish(4);
                        break;
                    case rclcpp_action::ResultCode::CANCELED:
                        RCLCPP_WARN(this->get_logger(), "導航目標已取消。");
                        this->finish(5);
                        break;
                    default:
                        RCLCPP_ERROR(this->get_logger(), "收到未知的導航結果狀態。");
                        this->finish(6);
                        break;
                }
                rclcpp::shutdown();
            };
        // Action server 存活不代表一定會回結果；逾時要讓 shell/CI 得到非零狀態，
        // 不能讓展示腳本永久掛住或把失敗誤判成成功。
        this->result_timeout_ = this->create_wall_timer(
            120s,
            [this]()
            {
                RCLCPP_ERROR(
                    this->get_logger(),
                    "等待導航結果超過 120 秒，先取消已接受的目標再結束。");
                this->timed_out_ = true;
                this->exit_code_ = 124;
                this->result_timeout_->cancel();

                if (!this->goal_handle_) {
                    RCLCPP_ERROR(
                        this->get_logger(),
                        "逾時時尚未取得 GoalHandle，無法確認 Nav2 是否接受／取消目標。");
                    rclcpp::shutdown();
                    return;
                }

                try {
                    // 保持 executor 再跑最多 2 秒，讓 cancel request 與結果 callback
                    // 有機會完成；不能關掉 CLI 後任由 Nav2 繼續駕駛。
                    this->client_ptr_->async_cancel_goal(this->goal_handle_);
                    this->cancel_grace_timeout_ = this->create_wall_timer(
                        2s,
                        [this]()
                        {
                            RCLCPP_ERROR(
                                this->get_logger(),
                                "取消目標 2 秒內未收到結果；以 timeout 狀態結束。");
                            this->finish(124);
                            rclcpp::shutdown();
                        });
                } catch (const std::exception & error) {
                    RCLCPP_ERROR(
                        this->get_logger(), "送出取消要求失敗：%s", error.what());
                    this->finish(124);
                    rclcpp::shutdown();
                }
            });
        try {
            this->client_ptr_->async_send_goal(goal_msg, send_goal_options);
        } catch (const std::exception & error) {
            RCLCPP_ERROR(this->get_logger(), "發送導航目標失敗：%s", error.what());
            this->finish(1);
            return false;
        }
        return true;
    }

    int exit_code() const
    {
        return exit_code_;
    }

private:
    void finish(int code)
    {
        exit_code_ = timed_out_ ? 124 : code;
        if (result_timeout_) {
            result_timeout_->cancel();
        }
        if (cancel_grace_timeout_) {
            cancel_grace_timeout_->cancel();
        }
    }

    rclcpp_action::Client<NavigateToPose>::SharedPtr client_ptr_;
    GoalHandleNav::SharedPtr goal_handle_;
    rclcpp::TimerBase::SharedPtr result_timeout_;
    rclcpp::TimerBase::SharedPtr cancel_grace_timeout_;
    bool timed_out_{false};
    int exit_code_{1};
};

namespace
{
constexpr double kWorldBound = 2.5;

bool parse_coordinate(const char * text, double & value)
{
    try {
        std::size_t parsed = 0;
        const std::string input{text};
        value = std::stod(input, &parsed);
        return parsed == input.size() && std::isfinite(value);
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    }
}
}  // namespace

int main(int argc, char ** argv)
{
    rclcpp::init(argc, argv);
    auto node = std::make_shared<NavClient>();

    // 檢查指令行參數數量 (程式名 + X + Y，共 3 個)
    if (argc != 3) {
        RCLCPP_WARN(node->get_logger(), "未偵測到座標參數！用法: ros2 run my_nav_dss nav_client [X] [Y]");
        RCLCPP_INFO(node->get_logger(), "範例: ros2 run my_nav_dss nav_client 2.0 -1.0");
        rclcpp::shutdown();
        return 2;
    }

    double target_x = 0.0;
    double target_y = 0.0;
    if (!parse_coordinate(argv[1], target_x) || !parse_coordinate(argv[2], target_y)) {
        RCLCPP_ERROR(node->get_logger(), "座標必須是有限數字，不能包含其他字元。");
        rclcpp::shutdown();
        return 2;
    }

    if (std::abs(target_x) > kWorldBound || std::abs(target_y) > kWorldBound) {
        RCLCPP_ERROR(
            node->get_logger(),
            "座標超出 Gazebo 場地邊界：X/Y 必須介於 %.1f 與 %.1f。",
            -kWorldBound, kWorldBound);
        rclcpp::shutdown();
        return 2;
    }

    RCLCPP_INFO(
        node->get_logger(),
        "接收到外部決策指令：前往座標 (%.2f, %.2f)", target_x, target_y);
    if (!node->send_goal(target_x, target_y)) {
        rclcpp::shutdown();
        return 1;
    }

    rclcpp::spin(node);
    if (rclcpp::ok()) {
        rclcpp::shutdown();
    }
    return node->exit_code();
}
