#!/usr/bin/env bash
# 共用 ROS2 環境載入器。
#
# 用法（必須 source）：
#   source ~/ros2_ws/工具腳本/load_ros_environment.sh
#
# credentials 只允許保存明確白名單內的非秘密 ROS/DDS 設定，以及非秘密的
# LINE_USER_ID。HMAC 與 LINE token 必須分別放在
# ~/.config/dds-monitor/alert_secret 與 line_token（chmod 600）。

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "錯誤：請用 source 載入 ${BASH_SOURCE[0]}，不要直接執行。" >&2
    exit 2
fi

# 即使呼叫端曾經 source 過舊 credentials，也不讓秘密繼續傳給 ROS process。
unset DDS_ALERT_SECRET LINE_CHANNEL_TOKEN

_dds_env_helper_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || {
    echo "錯誤：無法解析 ROS 環境載入器路徑。" >&2
    return 1
}
_dds_env_ws="${ROS2_WS:-}"
if [[ -z "$_dds_env_ws" ]]; then
    _dds_env_ws="$(cd -- "$_dds_env_helper_dir/.." && pwd -P)" || {
        echo "錯誤：無法解析 ROS2 workspace 路徑。" >&2
        unset _dds_env_helper_dir _dds_env_ws
        return 1
    }
fi

_dds_env_credentials="${DDS_MONITOR_CREDENTIALS_FILE:-$HOME/.config/dds-monitor/credentials}"
_dds_env_setup="$_dds_env_ws/install/setup.bash"
_dds_env_underlay="/opt/ros/jazzy/setup.bash"
_dds_env_input="$_dds_env_credentials"

if [[ -e "$_dds_env_credentials" && ! -r "$_dds_env_credentials" ]]; then
    echo "錯誤：非秘密 ROS 設定檔存在但無法讀取：$_dds_env_credentials" >&2
    unset _dds_env_helper_dir _dds_env_ws _dds_env_credentials
    unset _dds_env_setup _dds_env_underlay _dds_env_setup_to_source _dds_env_input
    return 1
fi
if [[ ! -e "$_dds_env_credentials" ]]; then
    # credentials 是選用設定；首次安裝或不需額外 ROS 設定時可不存在。
    _dds_env_input="/dev/null"
fi

# 連註解中的舊秘密名稱也拒絕，避免使用者誤以為此檔仍可保存秘密。
if [[ "$_dds_env_input" != "/dev/null" ]] &&
        grep -Eq '(^|[^[:alnum:]_])(DDS_ALERT_SECRET|LINE_CHANNEL_TOKEN)([^[:alnum:]_]|$)' \
            "$_dds_env_input"; then
    echo "錯誤：$_dds_env_credentials 仍含 DDS_ALERT_SECRET 或 LINE_CHANNEL_TOKEN。" >&2
    echo "請把秘密移到 alert_secret / line_token（chmod 600）後再啟動。" >&2
    unset _dds_env_helper_dir _dds_env_ws _dds_env_credentials
    unset _dds_env_setup _dds_env_underlay _dds_env_setup_to_source _dds_env_input
    return 1
fi

# 不直接 source credentials，避免其中的命令或任意環境變數被執行／匯出。
# 僅解析下列明確允許的非秘密 ROS/DDS 設定；LINE_USER_ID 是為了相容舊
# 啟動設定而保留的非秘密通知目的地。
declare -a _dds_env_keys=()
declare -a _dds_env_values=()
_dds_env_parse_error=0

while IFS= read -r _dds_env_line || [[ -n "$_dds_env_line" ]]; do
    _dds_env_line="${_dds_env_line%$'\r'}"
    _dds_env_line="${_dds_env_line#"${_dds_env_line%%[![:space:]]*}"}"
    _dds_env_line="${_dds_env_line%"${_dds_env_line##*[![:space:]]}"}"

    [[ -z "$_dds_env_line" || "${_dds_env_line:0:1}" == "#" ]] && continue
    if [[ "$_dds_env_line" =~ ^export[[:space:]]+(.+)$ ]]; then
        _dds_env_line="${BASH_REMATCH[1]}"
    fi
    [[ "$_dds_env_line" == *=* ]] || continue

    _dds_env_key="${_dds_env_line%%=*}"
    _dds_env_value="${_dds_env_line#*=}"
    _dds_env_key="${_dds_env_key#"${_dds_env_key%%[![:space:]]*}"}"
    _dds_env_key="${_dds_env_key%"${_dds_env_key##*[![:space:]]}"}"
    _dds_env_value="${_dds_env_value#"${_dds_env_value%%[![:space:]]*}"}"
    _dds_env_value="${_dds_env_value%"${_dds_env_value##*[![:space:]]}"}"

    case "$_dds_env_key" in
        ROS_DOMAIN_ID|ROS_LOCALHOST_ONLY|ROS_AUTOMATIC_DISCOVERY_RANGE|\
        ROS_STATIC_PEERS|ROS_DISCOVERY_SERVER|RMW_IMPLEMENTATION|\
        ROS_SECURITY_KEYSTORE|ROS_SECURITY_ENABLE|ROS_SECURITY_STRATEGY|\
        ROS_SECURITY_ENCLAVE_OVERRIDE|CYCLONEDDS_URI|\
        FASTRTPS_DEFAULT_PROFILES_FILE|TURTLEBOT3_MODEL|LINE_USER_ID)
            ;;
        *)
            # 非白名單項目不載入；尤其不把 PATH/PYTHONPATH 等任意設定帶入。
            continue
            ;;
    esac

    if [[ "${_dds_env_value:0:1}" == '"' ]]; then
        if (( ${#_dds_env_value} < 2 )) || [[ "${_dds_env_value: -1}" != '"' ]]; then
            echo "錯誤：$_dds_env_credentials 的 $_dds_env_key 雙引號未閉合。" >&2
            _dds_env_parse_error=1
            break
        fi
        _dds_env_value="${_dds_env_value:1:${#_dds_env_value}-2}"
    elif [[ "${_dds_env_value:0:1}" == "'" ]]; then
        if (( ${#_dds_env_value} < 2 )) || [[ "${_dds_env_value: -1}" != "'" ]]; then
            echo "錯誤：$_dds_env_credentials 的 $_dds_env_key 單引號未閉合。" >&2
            _dds_env_parse_error=1
            break
        fi
        _dds_env_value="${_dds_env_value:1:${#_dds_env_value}-2}"
    else
        # 支援常見的「值 # 註解」，但拒絕未加引號的空白值。
        if [[ "$_dds_env_value" =~ ^(.*[^[:space:]])[[:space:]]+\#.*$ ]]; then
            _dds_env_value="${BASH_REMATCH[1]}"
        fi
        if [[ "$_dds_env_value" == *[[:space:]]* ]]; then
            echo "錯誤：$_dds_env_credentials 的 $_dds_env_key 含未加引號空白。" >&2
            _dds_env_parse_error=1
            break
        fi
    fi

    # 只展開受控的 HOME / ROS2_WS；不 eval，也不允許命令替換。
    case "$_dds_env_value" in
        "~") _dds_env_value="$HOME" ;;
        "~/"*) _dds_env_value="$HOME/${_dds_env_value:2}" ;;
    esac
    _dds_env_home_braced='${HOME}'
    _dds_env_home_plain='$HOME'
    _dds_env_ws_braced='${ROS2_WS}'
    _dds_env_ws_plain='$ROS2_WS'
    _dds_env_value="${_dds_env_value//$_dds_env_home_braced/$HOME}"
    _dds_env_value="${_dds_env_value//$_dds_env_home_plain/$HOME}"
    _dds_env_value="${_dds_env_value//$_dds_env_ws_braced/$_dds_env_ws}"
    _dds_env_value="${_dds_env_value//$_dds_env_ws_plain/$_dds_env_ws}"
    if [[ "$_dds_env_value" == *'$'* || "$_dds_env_value" == *'`'* ]]; then
        echo "錯誤：$_dds_env_credentials 的 $_dds_env_key 含不允許的 shell 展開。" >&2
        _dds_env_parse_error=1
        break
    fi

    _dds_env_keys+=("$_dds_env_key")
    _dds_env_values+=("$_dds_env_value")
done < "$_dds_env_input"

if (( _dds_env_parse_error != 0 )); then
    unset _dds_env_helper_dir _dds_env_ws _dds_env_credentials
    unset _dds_env_setup _dds_env_underlay _dds_env_setup_to_source _dds_env_input
    unset _dds_env_keys _dds_env_values _dds_env_parse_error
    unset _dds_env_line _dds_env_key _dds_env_value
    unset _dds_env_home_braced _dds_env_home_plain
    unset _dds_env_ws_braced _dds_env_ws_plain
    return 1
fi

for _dds_env_index in "${!_dds_env_keys[@]}"; do
    export "${_dds_env_keys[$_dds_env_index]}=${_dds_env_values[$_dds_env_index]}"
done

# 在載入 overlay 前再清一次，確保秘密不會被子程序繼承。
unset DDS_ALERT_SECRET LINE_CHANNEL_TOKEN

if [[ -r "$_dds_env_setup" ]]; then
    _dds_env_setup_to_source="$_dds_env_setup"
elif [[ -r "$_dds_env_underlay" ]]; then
    # 首次 build 前尚無 install/setup.bash；先載入固定 Jazzy underlay，
    # 讓環境設定與 colcon build 腳本也可使用本 helper。
    _dds_env_setup_to_source="$_dds_env_underlay"
else
    echo "錯誤：讀不到 ROS2 Jazzy underlay 或 workspace setup。" >&2
    echo "  $_dds_env_underlay" >&2
    echo "  $_dds_env_setup" >&2
    unset _dds_env_helper_dir _dds_env_ws _dds_env_credentials
    unset _dds_env_setup _dds_env_underlay _dds_env_setup_to_source _dds_env_input
    unset _dds_env_keys _dds_env_values _dds_env_parse_error _dds_env_index
    unset _dds_env_line _dds_env_key _dds_env_value
    unset _dds_env_home_braced _dds_env_home_plain
    unset _dds_env_ws_braced _dds_env_ws_plain
    return 1
fi

_dds_env_restore_nounset=0
if [[ "$-" == *u* ]]; then
    _dds_env_restore_nounset=1
    set +u
fi
source "$_dds_env_setup_to_source"
_dds_env_source_status=$?
if (( _dds_env_restore_nounset != 0 )); then
    set -u
fi
# workspace environment hook 也不能把舊秘密重新帶回來。
unset DDS_ALERT_SECRET LINE_CHANNEL_TOKEN

if (( _dds_env_source_status != 0 )); then
    unset _dds_env_helper_dir _dds_env_ws _dds_env_credentials
    unset _dds_env_setup _dds_env_underlay _dds_env_setup_to_source _dds_env_input
    unset _dds_env_keys _dds_env_values _dds_env_parse_error _dds_env_index
    unset _dds_env_line _dds_env_key _dds_env_value
    unset _dds_env_home_braced _dds_env_home_plain
    unset _dds_env_ws_braced _dds_env_ws_plain _dds_env_source_status
    unset _dds_env_restore_nounset
    return 1
fi

unset _dds_env_helper_dir _dds_env_ws _dds_env_credentials
unset _dds_env_setup _dds_env_underlay _dds_env_setup_to_source _dds_env_input
unset _dds_env_keys _dds_env_values _dds_env_parse_error _dds_env_index
unset _dds_env_line _dds_env_key _dds_env_value
unset _dds_env_home_braced _dds_env_home_plain
unset _dds_env_ws_braced _dds_env_ws_plain _dds_env_source_status
unset _dds_env_restore_nounset
return 0
