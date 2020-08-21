#!/bin/sh

for i in `seq 20`
 do
 ab -n 800 -c 50 "https://172.26.5.99:8380/api/v1/quotas/search?component=hdfs1&pageSize=500"
 done
