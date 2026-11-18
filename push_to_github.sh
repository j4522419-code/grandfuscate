#!/usr/bin/env bash
# Helper to push this workspace to a fresh GitHub repository.
# Usage: ./push_to_github.sh https://github.com/<you>/grandfuscate.git
set -euo pipefail

REMOTE="${1:-}"
if [ -z "$REMOTE" ]; then
  echo "Usage: $0 https://github.com/<you>/grandfuscate.git" >&2
  exit 2
fi

cd "$(dirname "$0")"

if [ ! -d .git ]; then
  git init
fi

# Repo-local identity is enough for the initial commit; it does not touch your
# global git configuration.
if ! git config user.name >/dev/null 2>&1; then
  git config user.name "Arena Agent"
fi
if ! git config user.email >/dev/null 2>&1; then
  git config user.email "agent@arena.ai"
fi

if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  git add .
  git commit -m "Grandfuscate: single VM runtime with light/medium/heavy presets"
  git branch -M main
elif ! git diff --quiet || ! git diff --cached --quiet; then
  git add .
  git commit -m "Update Grandfuscate deployment files"
  git branch -M main
else
  git branch -M main 2>/dev/null || true
fi

if git remote get-url origin >/dev/null 2>&1; then
  echo "origin is already set to $(git remote get-url origin)" >&2
  echo "Push manually with: git push -u origin main" >&2
  exit 1
fi

git remote add origin "$REMOTE"
git push -u origin main

echo
echo "Pushed. Now go to https://dashboard.render.com -> New -> Blueprint -> select this repo."
echo "Full notes: DEPLOY.md"
