#!/usr/bin/env bash
# 一键部署：硬同步到远程最新代码并重建容器
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 同步代码到远程最新"
git fetch origin
git reset --hard origin/main

if [ ! -f .env ] || ! grep -q "^SITE_IP=" .env; then
  echo "!! 错误：.env 缺失或未设置 SITE_IP（参考 .env.example），Caddy 无法启动"
  exit 1
fi
if [ ! -d data ]; then
  echo "!! 提示：data/ 不存在（数据库 + fernet.key）——首次部署可忽略，会自动生成；迁移老库需手动上传"
fi

echo "==> 构建并启动容器"
docker compose up -d --build

echo "==> 容器状态"
docker compose ps
echo "==> Caddy 最近日志"
docker compose logs caddy --tail 15
echo "==> 完成：https://$(grep '^SITE_IP=' .env | cut -d= -f2):8200"
