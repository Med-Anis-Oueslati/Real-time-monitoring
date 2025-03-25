#!/bin/bash
rm -rf /opt/hadoop/data/dataNode/*
chown -R hadoop:hadoop /opt/hadoop/data/dataNode
chmod 755 /opt/hadoop/data/dataNode
$HADOOP_HOME/bin/hdfs --daemon start datanode
sleep 5
HOSTNAME=$(hostname)
tail -f /opt/hadoop/logs/hadoop-root-datanode-${HOSTNAME}.log || sleep infinity