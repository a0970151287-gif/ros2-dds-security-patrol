#include <memory>
#include <chrono>
#include "rclcpp/rclcpp.hpp"
#include "rclcpp_action/rclcpp_action.hpp"
#include "nav2_msgs/action/navigate_to_pose.hpp"

using namespace std;

class NavClient : public rclcpp::Node
{
public:
    using NavigateToPose = nav2_msgs::action::NavigateToPose;
    using GoalHandleNav = rclcpp_action::ClientGoalHandle<NavigateToPose>;

    explicit NavClient() : Node("nav_to_pose_client")
    {
        this->client_ptr_ = rclcpp_action::create_client<NavigateToPose>(this, "navigate_to_pose");
    }

    void send_goal(float x, float y)
    {
        if (!this->client_ptr_->wait_for_action_server(chrono::seconds(10)))
        {
            RCLCPP_ERROR(this->get_logger(), "找不到 Nav2 Action Server！請確認導航系統已啟動。");
            return;
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
        this->client_ptr_->async_send_goal(goal_msg, send_goal_options);
    }

private:
    rclcpp_action::Client<NavigateToPose>::SharedPtr client_ptr_;
};

int main(int argc, char ** argv) {
    rclcpp::init(argc, argv);
    auto node = std::make_shared<NavClient>();

    // 檢查指令行參數數量 (程式名 + X + Y，共 3 個)
    if (argc == 3) {
        // 將字串參數轉換為浮點數
        float target_x = atof(argv[1]);
        float target_y = atof(argv[2]);
        
        RCLCPP_INFO(node->get_logger(), "接收到外部決策指令：前往座標 (%.2f, %.2f)", target_x, target_y);
        node->send_goal(target_x, target_y);
    } 
    else {
        RCLCPP_WARN(node->get_logger(), "未偵測到座標參數！用法: ros2 run my_nav_dss nav_client [X] [Y]");
        RCLCPP_INFO(node->get_logger(), "範例: ros2 run my_nav_dss nav_client 2.5 -1.0");
        
        // 若無參數，可選擇結束程式或停留在原地
        rclcpp::shutdown();
        return 0;
    }

    rclcpp::spin(node);
    rclcpp::shutdown();
    return 0;
}