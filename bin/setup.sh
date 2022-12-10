#!/bin/bash

git_root=$(git rev-parse --show-toplevel)

ln -sf $git_root/hooks/pre-commit $git_root/.git/hooks/pre-commit

cd $git_root/server/static
yarn install

