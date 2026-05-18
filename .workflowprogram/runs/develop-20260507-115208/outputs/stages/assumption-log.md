# Assumption Log

- workflow_name: `stride-security-audit`
- trigger_command: `/stride-audit`

## Current Assumptions

- 1. 用户环境已安装 Python 3.10+ 和 pip

## External Dependencies

- 1. cppcheck（C/C++ 静态分析——验证阶段使用）

## Edge Cases

- 1. 无代码仓库 → 对话引导模式（跳过自动DFD和SAST，交互式威胁识别）

## Non-Goals

- 1. 不修改目标代码
