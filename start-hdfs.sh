#!/bin/bash
if [ ! -d /opt/hadoop/data/nameNode/current ]; then
  $HADOOP_HOME/bin/hdfs namenode -format -force
fi
$HADOOP_HOME/bin/hdfs --daemon start namenode
sleep 5
tail -f /opt/hadoop/logs/hadoop-root-namenode-*.log || sleep infinity