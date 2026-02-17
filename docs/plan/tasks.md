# 二开实施任务清单 (Implementation Roadmap)

## Phase 1: 基础设施迁移与修复 (100%)
- [x] 创建 `manager` 独立包
- [x] 建立 `device/export.go` 导出层
- [x] 彻底修复 `manager/webui.go` 的编译错误
- [x] 修改 `main.go` 适配新的 `manager.WebUI`

## Phase 2: JSON 持久化大脑 (100%)
- [x] 创建 `manager/config.go` 定义 JSON 模型
- [x] 实现 `LoadConfig`：启动时自动扫描 `wg_data/config.json`
- [x] 实现 `SaveConfig`：数据变动自动触发 Atomic Write
- [x] 在 `main.go` 注入持久化逻辑

## Phase 3: 邀请码管理系统 (100%)
- [x] 增加 `InviteRecord` 内存与 JSON 存储
- [x] 实现 `/api/invites/generate` (已包含备注与过期时间)
- [x] 编写 **IP 自动分配算法** (基于 netip 遍历子网)

## Phase 4: 极简注册 API (100%)
- [x] 实现 `POST /api/register`：校验 Token -> 设置 UAPI -> 响应配置
- [x] 实现 Token 的 “方案 B” 失效策略 (注册成功即删除)

## Phase 5: 小白专用引路页 (100%)
- [x] 设计客户端专用的 8080 极简入驻表单 (已包含二维码与配置展示)
- [x] 实现自动跳转与状态检查 (通过 /join/{token} 引导)

---
*注：每完成一项，请在对话中提醒我打勾。*
