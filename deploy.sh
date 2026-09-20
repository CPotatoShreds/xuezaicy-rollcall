#!/usr/bin/env bash
# 一键部署：拉取最新代码并重建容器
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 拉取最新代码"
git pull

if [ ! -f .env ]; then
  echo "!! 警告：.env 不存在，Caddy 无法签发证书（参考 .env.example 创建）"
fi
if [ ! -d data ]; then
  echo "!! 提示：data/ 不存在（数据库 + fernet.key）——首次部署可忽略，会自动生成；迁移老库需手动上传"
fi

echo "==> 构建并启动容器"
docker compose up -d --build

echo "==> 容器状态"
docker compose ps
echo "==> 完成：https://<你的域名>:8200  （首次启动等 Caddy 签证书约 10-30 秒）"
