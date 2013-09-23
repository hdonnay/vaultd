#!/bin/sh
cat << EOF | psql
DROP TABLE users CASCADE;
DROP TABLE groups CASCADE;
DROP TABLE secrets CASCADE;
DROP TABLE user_group;
DROP TABLE group_secret;
EOF
