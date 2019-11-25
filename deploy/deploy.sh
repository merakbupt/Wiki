#!/bin/bash

git clone --depth=1 --branch=master "https://github.com/merakbupt/merakbupt.github.io.git" deploy
cd deploy
git rm -rf .
cd ..
mv site/* deploy
cd deploy
git add --all
git config user.name "Travis CI"
git config user.email "travis@travis-ci.org"
git commit --message "Auto deploy from Travis CI"
git remote add deploy "https://$GITHUB_TOKEN@github.com/merakbupt/merakbupt.github.io.git" &>/dev/null
git push deploy master &>/dev/null