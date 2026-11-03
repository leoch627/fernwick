package core

import "errors"

type ErrorCode string

var Messages = map[ErrorCode]string{
	"UPDATE_PERMISSION_REQUIRED": "安装更新未获系统授权，请重试并允许授权，或手动安装",
	"UPDATE_STORAGE_FAILED":      "无法保存更新文件，请检查磁盘空间和文件夹权限",
	"UPDATE_DISK_FULL":           "磁盘可用空间不足，请清理空间后重试",
	"UPDATE_CHECK_FAILED":        "无法连接更新服务器，请检查网络后重试",
	"FAVORITES_FULL":             "收藏已达到 256 条，请先取消一些收藏",
	"AUTH_INVALID":               "登录已失效，请重新登录", "LOGIN_FAILED": "登录未成功，请检查账号、密码及面板验证要求",
	"ACCOUNT_EXPIRED": "套餐已到期", "ACCOUNT_BANNED": "账号暂不可使用", "NO_SERVICE": "当前账号没有可用套餐", "QUOTA_EXHAUSTED": "套餐流量已用完",
	"CONTROL_UNAVAILABLE": "暂时无法同步，请稍后重试", "RATE_LIMITED": "请求过于频繁，请稍后重试", "SNAPSHOT_EXPIRED": "上次数据已超过可用时间，请在线刷新",
	"SUBSCRIPTION_INVALID": "订阅数据异常，请重试或导出诊断", "SUBSCRIPTION_CREDENTIAL_INVALID": "订阅凭据暂不可用，请重新同步",
	"NO_AUTHORIZED_NODES": "当前没有可用节点", "NO_COMPATIBLE_NODES": "当前节点暂不兼容", "PERMISSION_REQUIRED": "需要系统网络权限", "NETWORK_CONFLICT": "另一会话正在接管网络",
	"COMPONENTS_UNAVAILABLE": "网络组件不可用，请安装完整客户端或修复组件", "CONNECT_TIMEOUT": "连接未成功", "NETWORK_RECOVERY_REQUIRED": "网络恢复未完成，请修复", "SYSTEM_PROXY_FAILED": "系统代理设置未成功",
	"CLOCK_UNTRUSTED": "时间状态异常，请校正系统时间后在线刷新", "CONFIGURATION_REQUIRED": "客户端缺少服务配置，请从官网下载完整安装包或联系客服", "POLICY_INVALID": "运营策略未通过验证，保留此前有效设置",
	"UPDATE_VERIFY_FAILED": "更新信息或安装包未通过安全校验，请重新下载；仍失败请联系客服", "UPDATE_DOWNLOAD_FAILED": "更新下载中断，请检查网络后重试，或手动下载安装包", "STORAGE_LOCKED": "安全存储暂时无法解锁，请解锁系统钥匙串后重试",
	"UPDATE_OPEN_FAILED": "无法打开手动下载页，请重试或从官网下载", "UPDATE_INSTALL_FAILED": "更新安装没有完成，请关闭程序后手动安装",
	"STORAGE_FAILED": "无法安全保存数据，本次变更未提交", "CANCELLED": "操作已取消", "INVALID_INPUT": "输入不符合要求",
}

type AppError struct {
	Code         ErrorCode
	RetryAfterMs int64
}

func (e *AppError) Error() string {
	if message, ok := Messages[e.Code]; ok {
		return message
	}
	return Messages["CONTROL_UNAVAILABLE"]
}
func NewAppError(code ErrorCode) error { return &AppError{Code: code} }
func CodeOf(err error) ErrorCode {
	var app *AppError
	if errors.As(err, &app) && app != nil {
		return app.Code
	}
	return "CONTROL_UNAVAILABLE"
}
