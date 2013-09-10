#!/bin/sh
cat << EOF | psql
DROP TABLE users CASCADE;
DROP TABLE groups CASCADE;
DROP TABLE secret CASCADE;
DROP TABLE secretMap;
EOF
