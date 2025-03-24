#!/bin/bash
if [ ! -d /opt/hadoop/data/nameNode/current ]; then
  $HADOOP_HOME/bin/hdfs namenode -format -force
fi
$HADOOP_HOME/bin/hdfs namenode