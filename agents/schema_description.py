# schema_description.py
# Schema description for the Snowflake database tables in SPARK_DB.SPARK_SCHEMA

SCHEMA_DESCRIPTION = """
The Snowflake database contains the following tables in SPARK_DB.SPARK_SCHEMA:

1. ZEEK_CAPTURE_LOSS
   - YEAR (INTEGER): Year of the log entry
   - MONTH (INTEGER): Month of the log entry
   - DAY (INTEGER): Day of the log entry
   - HOUR (INTEGER): Hour of the log entry
   - MINUTE (INTEGER): Minute of the log entry
   - SECOND (INTEGER): Second of the log entry
   - TIMESTAMP (TIMESTAMP_NTZ): Timestamp of the log entry
   - TS_DELTA (FLOAT): Time delta between events
   - PEER (STRING): Peer identifier
   - GAPS (INTEGER): Number of gaps in capture
   - ACKS (INTEGER): Number of acknowledgments
   - PERCENT_LOST (FLOAT): Percentage of lost packets
   - LOSS_SEVERITY (STRING): Severity level of packet loss
   - HOSTNAME (STRING): Hostname of the system
   - VM_ID (STRING): Virtual machine identifier
   - Clustering: YEAR, MONTH, DAY

2. ZEEK_CONN
   - YEAR (INTEGER): Year of the log entry
   - MONTH (INTEGER): Month of the log entry
   - DAY (INTEGER): Day of the log entry
   - HOUR (INTEGER): Hour of the log entry
   - MINUTE (INTEGER): Minute of the log entry
   - SECOND (INTEGER): Second of the log entry
   - TIMESTAMP (TIMESTAMP_NTZ): Timestamp of the log entry
   - ID_ORIG_H (STRING): Source IP address
   - ID_ORIG_P (INTEGER): Source port
   - ID_RESP_H (STRING): Destination IP address
   - ID_RESP_P (INTEGER): Destination port
   - PROTO (STRING): Protocol used (e.g., TCP, UDP)
   - SERVICE (STRING): Service type
   - DURATION (FLOAT): Connection duration
   - ORIG_BYTES (BIGINT): Bytes sent by source
   - RESP_BYTES (BIGINT): Bytes sent by destination
   - CONN_STATE (STRING): Connection state
   - ORIG_PKTS (BIGINT): Packets sent by source
   - ORIG_IP_BYTES (BIGINT): IP bytes sent by source
   - RESP_PKTS (BIGINT): Packets sent by destination
   - RESP_IP_BYTES (BIGINT): IP bytes sent by destination
   - HOSTNAME (STRING): Hostname of the system
   - VM_ID (STRING): Virtual machine identifier
   - Clustering: YEAR, MONTH, DAY

3. ZEEK_DNS
   - YEAR (INTEGER): Year of the log entry
   - MONTH (INTEGER): Month of the log entry
   - DAY (INTEGER): Day of the log entry
   - HOUR (INTEGER): Hour of the log entry
   - MINUTE (INTEGER): Minute of the log entry
   - SECOND (INTEGER): Second of the log entry
   - TIMESTAMP (TIMESTAMP_NTZ): Timestamp of the log entry
   - UID (STRING): Unique identifier
   - ID_ORIG_H (STRING): Source IP address
   - ID_ORIG_P (INTEGER): Source port
   - ID_RESP_H (STRING): Destination IP address
   - ID_RESP_P (INTEGER): Destination port
   - PROTO (STRING): Protocol used
   - TRANS_ID (INTEGER): Transaction ID
   - RTT (FLOAT): Round-trip time
   - QUERY (STRING): DNS query string
   - QCLASS (INTEGER): Query class
   - QCLASS_NAME (STRING): Query class name
   - QTYPE (INTEGER): Query type
   - QTYPE_NAME (STRING): Query type name
   - RCODE (INTEGER): Response code
   - RCODE_NAME (STRING): Response code name
   - AA (BOOLEAN): Authoritative answer flag
   - TC (BOOLEAN): Truncation flag
   - RD (BOOLEAN): Recursion desired flag
   - RA (BOOLEAN): Recursion available flag
   - Z (INTEGER): Reserved field
   - ANSWERS (ARRAY): DNS answers
   - TTLS (ARRAY): Time-to-live values
   - REJECTED (BOOLEAN): Query rejection flag
   - HOSTNAME (STRING): Hostname of the system
   - VM_ID (STRING): Virtual machine identifier
   - Clustering: YEAR, MONTH, DAY

4. ZEEK_HTTP
   - YEAR (INTEGER): Year of the log entry
   - MONTH (INTEGER): Month of the log entry
   - DAY (INTEGER): Day of the log entry
   - HOUR (INTEGER): Hour of the log entry
   - MINUTE (INTEGER): Minute of the log entry
   - SECOND (INTEGER): Second of the log entry
   - TIMESTAMP (TIMESTAMP_NTZ): Timestamp of the log entry
   - UID (STRING): Unique identifier
   - ID_ORIG_H (STRING): Source IP address
   - ID_ORIG_P (INTEGER): Source port
   - ID_RESP_H (STRING): Destination IP address
   - ID_RESP_P (INTEGER): Destination port
   - TRANS_DEPTH (INTEGER): Transaction depth
   - METHOD (STRING): HTTP method
   - HOST (STRING): Host header
   - URI (STRING): Request URI
   - VERSION (STRING): HTTP version
   - USER_AGENT (STRING): User agent string
   - REQUEST_BODY_LEN (INTEGER): Request body length
   - RESPONSE_BODY_LEN (INTEGER): Response body length
   - STATUS_CODE (INTEGER): HTTP status code
   - STATUS_MSG (STRING): Status message
   - TAGS (ARRAY): Tags associated with the request
   - RESP_FUIDS (ARRAY): Response file UIDs
   - ORIG_FUIDS (ARRAY): Original file UIDs
   - ORIG_MIME_TYPES (ARRAY): Original MIME types
   - RESP_MIME_TYPES (ARRAY): Response MIME types
   - HOSTNAME (STRING): Hostname of the system
   - VM_ID (STRING): Virtual machine identifier
   - Clustering: YEAR, MONTH, DAY

5. ZEEK_NOTICE
   - YEAR (INTEGER): Year of the log entry
   - MONTH (INTEGER): Month of the log entry
   - DAY (INTEGER): Day of the log entry
   - HOUR (INTEGER): Hour of the log entry
   - MINUTE (INTEGER): Minute of the log entry
   - SECOND (INTEGER): Second of the log entry
   - TIMESTAMP (TIMESTAMP_NTZ): Timestamp of the log entry
   - UID (STRING): Unique identifier
   - ID_ORIG_H (STRING): Source IP address
   - ID_ORIG_P (INTEGER): Source port
   - ID_RESP_H (STRING): Destination IP address
   - ID_RESP_P (INTEGER): Destination port
   - PROTO (STRING): Protocol used
   - NOTE (STRING): Notice type
   - MSG (STRING): Notice message
   - SRC (STRING): Source address
   - DST (STRING): Destination address
   - P (INTEGER): Port
   - ACTIONS (ARRAY): Actions taken
   - EMAIL_DEST (ARRAY): Email destinations
   - SUPPRESS_FOR (FLOAT): Suppression duration
   - HOSTNAME (STRING): Hostname of the system
   - VM_ID (STRING): Virtual machine identifier
   - Clustering: YEAR, MONTH, DAY

6. ZEEK_SSL
   - YEAR (INTEGER): Year of the log entry
   - MONTH (INTEGER): Month of the log entry
   - DAY (INTEGER): Day of the log entry
   - HOUR (INTEGER): Hour of the log entry
   - MINUTE (INTEGER): Minute of the log entry
   - SECOND (INTEGER): Second of the log entry
   - TIMESTAMP (TIMESTAMP_NTZ): Timestamp of the log entry
   - UID (STRING): Unique identifier
   - ID_ORIG_H (STRING): Source IP address
   - ID_ORIG_P (INTEGER): Source port
   - ID_RESP_H (STRING): Destination IP address
   - ID_RESP_P (INTEGER): Destination port
   - VERSION (STRING): SSL/TLS version
   - CIPHER (STRING): Cipher suite
   - CURVE (STRING): Elliptic curve
   - SERVER_NAME (STRING): Server name
   - RESUMED (BOOLEAN): Session resumption flag
   - ESTABLISHED (BOOLEAN): Connection established flag
   - SSL_HISTORY (STRING): SSL history
   - HOSTNAME (STRING): Hostname of the system
   - VM_ID (STRING): Virtual machine identifier
   - Clustering: YEAR, MONTH, DAY
7. ANOMALIES
   -TIMESTAMP (STRING) : Timestamp of the anomaly
   -ATTACK_TYPE (STRING) : Attack type
   -DESCIPTION (STRING) : Description of the cyberattack where the ptotocol was used
   -SRC_IP (STRING) : Source IP address
   -DST_IP (STRING) : Destination IP address
   -INSERTED_AT (TIMESTAMP_NTZ) : Timestamp when the anomaly was inserted into the database
"""