export const messages = {
  AUTH_INVALID: '登录已失效，请重新登录',
  LOGIN_FAILED: '登录未成功，请检查账号、密码及面板验证要求',
  ACCOUNT_EXPIRED: '套餐已到期', ACCOUNT_BANNED: '账号暂不可使用',
  NO_SERVICE: '当前账号没有可用套餐', QUOTA_EXHAUSTED: '套餐流量已用完',
  CONTROL_UNAVAILABLE: '暂时无法同步，请稍后重试',
  RATE_LIMITED: '请求过于频繁，请稍后重试',
  SNAPSHOT_EXPIRED: '上次数据已超过可用时间，请在线刷新',
  SUBSCRIPTION_INVALID: '订阅数据异常，请重试或导出诊断',
  SUBSCRIPTION_CREDENTIAL_INVALID: '订阅凭据暂不可用，请重新同步',
  NO_AUTHORIZED_NODES: '当前没有可用节点', NO_COMPATIBLE_NODES: '当前节点暂不兼容',
  PERMISSION_REQUIRED: '需要系统网络权限', NETWORK_CONFLICT: '另一会话正在接管网络',
  COMPONENTS_UNAVAILABLE: '网络组件不可用，请安装完整客户端或修复组件',
  CONNECT_TIMEOUT: '连接未成功', NETWORK_RECOVERY_REQUIRED: '网络恢复未完成，请修复',
  CLOCK_UNTRUSTED: '时间状态异常，请校正系统时间后在线刷新',
  CONFIGURATION_REQUIRED: '尚未配置并确认真实面板合同',
  POLICY_INVALID: '运营策略未通过验证，保留此前有效设置',
  UPDATE_VERIFY_FAILED: '更新未通过验证，未安装',
  UPDATE_DOWNLOAD_FAILED: '更新下载未完成，当前安装未改动',
  STORAGE_LOCKED: '安全存储暂时无法解锁，请解锁系统钥匙串后重试',
  STORAGE_FAILED: '无法安全保存数据，本次变更未提交',
  CANCELLED: '操作已取消', INVALID_INPUT: '输入不符合要求',
} as const;
export type ErrorCode = keyof typeof messages;
export class AppError extends Error {
  constructor(public readonly code: ErrorCode, public readonly retryAfterMs = 0) { super(messages[code]); this.name = 'AppError'; }
}
export const errorCode = (e: unknown): ErrorCode => e instanceof AppError ? e.code : 'CONTROL_UNAVAILABLE';
export function assert(condition: unknown, code: ErrorCode = 'INVALID_INPUT'): asserts condition { if (!condition) throw new AppError(code); }
