#!/bin/sh
# クラスタ初回作成時にプライマリで1度だけ実行される: アプリ用ロール・DB を作る
set -e
psql -h /tmp -U postgres -v ON_ERROR_STOP=1 <<SQL
create role sruru login password '${SRURU_DB_PASSWORD:-sruru}';
create database sruru owner sruru;
SQL
