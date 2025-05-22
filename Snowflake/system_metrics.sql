CREATE OR REPLACE TABLE SYSTEM_METRICS (
    year INTEGER,
    month INTEGER,
    day INTEGER,
    hour INTEGER,
    minute INTEGER,
    second INTEGER,
    timestamp TIMESTAMP,
    cpu_user FLOAT,
    cpu_system FLOAT,
    cpu_iowait FLOAT,
    cpu_idle FLOAT,
    disk_read_kbs FLOAT,
    disk_write_kbs FLOAT,
    mem_used FLOAT,
    mem_total FLOAT,
    hostname STRING,
    vm_id STRING
);