# DDS Security 稽核觀測者。
#
# 刻意不用 ament／colcon：這支程式的整個重點就是**不經過 ROS 的 RMW 層**
# ——rmw_fastrtps 會覆寫 participant 的安全屬性並丟掉 logging plugin。
# 直接連 Fast DDS，用 ROS 安裝目錄裡的那份函式庫，版本才會與受測系統一致。
#
# 建置：
#   cmake -S firewall_lab/security_observer -B <build> \
#         -DCMAKE_PREFIX_PATH=/opt/ros/jazzy
#   cmake --build <build>

cmake_minimum_required(VERSION 3.16)
project(sros2_firewall_security_observer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(fastrtps REQUIRED)
# subject 以 SHA-256 存放，不在遙測串流裡放明文 CN。
find_package(OpenSSL REQUIRED)

add_executable(security_observer security_observer.cpp)
target_link_libraries(security_observer PRIVATE fastrtps OpenSSL::Crypto)

# gid_probe：驗證訂閱端拿不拿得到發送者的 GUID。
# 這一支需要 rclcpp（observer 刻意不需要），所以設成選用——
# 沒有 ROS 開發套件時不要讓整個專案建不起來。
find_package(rclcpp QUIET)
find_package(std_msgs QUIET)
if(rclcpp_FOUND AND std_msgs_FOUND)
  add_executable(gid_probe gid_probe.cpp)
  target_link_libraries(gid_probe PRIVATE rclcpp::rclcpp
                        ${std_msgs_TARGETS})

  # 第二層：依發送者 GUID 丟棄訊息的可撤銷守衛。同樣需要 rclcpp，
  # 因為 rclpy 拿不到 publisher_gid。
  add_executable(guard_filter guard_filter.cpp)
  target_link_libraries(guard_filter PRIVATE rclcpp::rclcpp
                        ${std_msgs_TARGETS})
else()
  message(STATUS "rclcpp/std_msgs not found; skipping gid_probe")
endif()
