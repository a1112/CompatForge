# Application Service API 0.12

CompatForge `0.12.0` 把应用管理和自动化调试收敛到 `compatforge-service`。Tauri 只负责显示和文件选择，C ABI、CLI 与桌面端调用同一个 `AutomationService::call` Dispatcher，不再各自拼装 LaunchRequest。

## 生命周期

1. 使用已有 `CoreConfig` 创建 `AutomationService`，`serviceRoot` 与 `storageRoot` 必须为绝对路径。
2. Service 在 `serviceRoot` 持久化应用、设置、Job 与 Bottle 归档收据；Bottle 内容继续位于 Core `storageRoot`。
3. Job submit 会执行 PE inspection、PreparedLaunch prepare/authorize 和 ProcessSupervisor start。
4. 调用方使用 `jobs.poll` 拉取 RuntimeEvent；使用 `jobs.cancel` 终止；视觉或交互检查完成后使用 `jobs.assess` 写入 accepted、failed 或 unverified 结论。
5. Service 释放时终止其拥有的活动任务。再次打开时，未到达终态的旧 Job 会标记为 failed，不伪装成仍在运行。

## 公共操作

| 分组 | 操作 |
| --- | --- |
| Applications | `applications.seed-defaults/list/get/upsert/remove` |
| Bottles | `bottles.list/get/create/archive/archives.list/restore` |
| Settings | `settings.get/update` |
| Jobs | `jobs.submit/list/get/poll/cancel/assess` |
| Desktop | `desktop.launchers`（仅选中的已验证托管版本） |

`jobs.submit` 支持 `install`、`launch`、`compatibility-test` 与 `adaptation-trial`。托管安装必须匹配 Application 中固定文件名和必需的 SHA-256，使用 `immutableArtifact`；安装后入口从选中版本的物理 Bottle `drive_c` 相对路径解析并使用 `bottleInPlace` 和已存储摘要。适配试验可以追加参数和环境变量，但不能覆盖 Core 的网络、路径、摘要和 Runtime 证据边界。版本安装、回退、卸载和恢复见 `docs/guides/managed-application-lifecycle.md`。

## JSON 请求

```json
{
  "schemaVersion": "1",
  "requestId": "agent-request-01",
  "operation": "jobs.submit",
  "payload": {
    "schemaVersion": "1",
    "applicationId": "7zip",
    "kind": "launch"
  }
}
```

响应保持 `schemaVersion/requestId/operation/result`。错误不伪装成成功响应：Rust 返回 `ServiceError`；C ABI 通过 status 与 `cf_last_error_json` 返回；CLI 返回非零退出码。

## 接入方式

- Rust：`AutomationService::new` 与 typed methods，或 `call(ServiceRequest)`。
- C ABI：`cf_service_create`、`cf_service_call`、`cf_service_release`；ABI major 保持 `1`。
- CLI 单次：`compatforge-cli api <context.json> <service.json> <request.json>`。
- CLI 常驻：`compatforge-cli api-session <context.json> <service.json>`，stdin/stdout 使用一行一个 JSON。需要 submit/poll/cancel 的 Agent 必须使用常驻会话，避免进程退出时 Service 清理任务。
- Tauri：后端只公开相同的 `service_call`，主窗口和独立设置窗口均通过版本化请求使用它。
- Linux 独立桌面入口与 ForgeStore：`service-daemon` 是唯一用户级所有者；`service-call`、`desktop-launch` 和 `desktop-export` 经验证双方 UID 的私有 Unix socket 访问它。界面/客户端退出不终止应用，后台轮询提交完成的安装。`service-stop` 在真正清理后确认。已有 `api-session` 的错误/EOF 清理约定保持不变；两者不能竞争同一存储根。详见 `docs/guides/linux-shared-service.md`。

JSON Schema 位于 `schemas/application.schema.json`、`service-config.schema.json`、`service-request.schema.json`、`service-response.schema.json`、`service-settings.schema.json` 和 `job.schema.json`。
