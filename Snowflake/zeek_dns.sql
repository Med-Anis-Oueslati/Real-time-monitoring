CREATE OR REPLACE TABLE ZEEK_DNS (
    YEAR INTEGER,
    MONTH INTEGER,
    DAY INTEGER,
    HOUR INTEGER,
    MINUTE INTEGER,
    SECOND INTEGER,
    TIMESTAMP TIMESTAMP_NTZ,
    UID STRING,
    ID_ORIG_H STRING,
    ID_ORIG_P INTEGER,
    ID_RESP_H STRING,
    ID_RESP_P INTEGER,
    PROTO STRING,
    TRANS_ID INTEGER,
    RTT FLOAT,
    QUERY STRING,
    QCLASS INTEGER,
    QCLASS_NAME STRING,
    QTYPE INTEGER,
    QTYPE_NAME STRING,
    RCODE INTEGER,
    RCODE_NAME STRING,
    AA BOOLEAN,
    TC BOOLEAN,
    RD BOOLEAN,
    RA BOOLEAN,
    Z INTEGER,
    ANSWERS ARRAY,
    TTLS ARRAY,
    REJECTED BOOLEAN,
    HOSTNAME STRING,
    VM_ID STRING
)
CLUSTER BY (YEAR, MONTH, DAY);