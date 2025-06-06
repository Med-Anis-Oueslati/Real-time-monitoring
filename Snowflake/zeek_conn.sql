CREATE OR REPLACE TABLE ZEEK_CONN (
    YEAR INTEGER,
    MONTH INTEGER,
    DAY INTEGER,
    HOUR INTEGER,
    MINUTE INTEGER,
    SECOND INTEGER,
    TIMESTAMP TIMESTAMP_NTZ,
    ID_ORIG_H STRING,
    ID_ORIG_P INTEGER,
    ID_RESP_H STRING,
    ID_RESP_P INTEGER,
    PROTO STRING,
    SERVICE STRING,
    DURATION FLOAT,
    ORIG_BYTES BIGINT,
    RESP_BYTES BIGINT,
    CONN_STATE STRING,
    ORIG_PKTS BIGINT,
    ORIG_IP_BYTES BIGINT,
    RESP_PKTS BIGINT,
    RESP_IP_BYTES BIGINT,
    HOSTNAME STRING,
    VM_ID STRING
)
CLUSTER BY (YEAR, MONTH, DAY);