# sealvault 本地业务处理

本项目保存业务原始记录、版本及可核对的处理历史，命令入口通过 JSON 参数调用领域操作。现有业务模块位于 sealvault/，测试位于 tests/。数据文件与运行输出放在工作目录之外或 var/ 中。

## 运行环境

Python 3.11，标准库与 SQLite。项目不包含生产账号或真实用户数据。先执行 docker build -t sealvault-local .，之后 docker run --rm --network none sealvault-local；依赖在构建阶段准备，正式测试与演示不需要公网。

## 测试与语法检查

python3 -m unittest discover -s tests -v
python3 -m compileall -q sealvault lab tests

## 现有操作示例

python3 -m sealvault commands
python3 -m sealvault --database vault.sqlite execute request.json
python3 -m sealvault replay fixtures/sealing.json
python3 -m unittest discover -s tests -v
python3 -m compileall -q sealvault
python3 -m sealvault --database vault.sqlite check
python3 -m sealvault --database vault.sqlite archive-export MANIFEST output.tar
python3 -m sealvault archive-verify output.tar
python3 -m sealvault --database vault.sqlite warc-ingest INGEST source.warc collector
python3 -m sealvault --database vault.sqlite warc-resolve INGEST collector
python3 -m sealvault --database vault.sqlite warc-mount INGEST CASE REVISION collector
python3 -m sealvault --database vault.sqlite warc-describe RECORD-ID

## 网页归档（WARC）接收

sealvault/webarchive/ 接收本地 WARC 1.1 的 response、revisit、metadata 记录，支持未压缩与单成员/拼接 gzip，按 Content-Length 分帧，块摘要与正文摘要分开校验（HTTP 头不计入正文）。revisit 引用可前向、跨包解析；依赖缺失、引用成环、摘要不符保留待处理原因并阻止整包挂载。重复 record-id 同内容复用对象、换内容冲突，不按 URL 合并访问；正文按内容去重，访问证据独立保留。默认总量 64 MiB、单记录 16 MiB。运行 python3 -m lab.warc_demo 查看先重访后原文、跨包引用、重复记录与截断等场景，以及重启后对象、捕获、案件附件之间的关系。协议细节见 docs/来源协议.md。

## 本地来源

lab/ 提供独立的合作方协议或合成文档发生器，不连接生产服务。协议、样本含义和操作见 docs/来源协议.md。运行 python3 -m lab.demo 可查看来源行为，python3 -m lab.check 依次执行测试、语法检查、业务演示和来源演示。HTTP 服务默认绑定回环地址，测试使用自动分配端口并在结束时清理。
