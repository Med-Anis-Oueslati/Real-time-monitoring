from pyspark.sql.types import (
    StructType, StructField, StringType, DoubleType, IntegerType,
    LongType, BooleanType, ArrayType, FloatType
)

# Schema for zeek_capture_loss
capture_loss_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("ts_delta", DoubleType(), True),
    StructField("peer", StringType(), True),
    StructField("gaps", IntegerType(), True),
    StructField("acks", IntegerType(), True),
    StructField("percent_lost", DoubleType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Schema for zeek_conn
conn_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("proto", StringType(), True),
    StructField("service", StringType(), True),
    StructField("duration", DoubleType(), True),
    StructField("orig_bytes", LongType(), True),
    StructField("resp_bytes", LongType(), True),
    StructField("conn_state", StringType(), True),
    StructField("local_orig", BooleanType(), True),
    StructField("local_resp", BooleanType(), True),
    StructField("missed_bytes", LongType(), True),
    StructField("history", StringType(), True),
    StructField("orig_pkts", LongType(), True),
    StructField("orig_ip_bytes", LongType(), True),
    StructField("resp_pkts", LongType(), True),
    StructField("resp_ip_bytes", LongType(), True),
    StructField("ip_proto", IntegerType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Schema for zeek_dns
dns_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("proto", StringType(), True),
    StructField("trans_id", IntegerType(), True),
    StructField("rtt", DoubleType(), True),
    StructField("query", StringType(), True),
    StructField("qclass", IntegerType(), True),
    StructField("qclass_name", StringType(), True),
    StructField("qtype", IntegerType(), True),
    StructField("qtype_name", StringType(), True),
    StructField("rcode", IntegerType(), True),
    StructField("rcode_name", StringType(), True),
    StructField("AA", BooleanType(), True),
    StructField("TC", BooleanType(), True),
    StructField("RD", BooleanType(), True),
    StructField("RA", BooleanType(), True),
    StructField("Z", IntegerType(), True),
    StructField("answers", ArrayType(StringType()), True),
    StructField("TTLs", ArrayType(DoubleType()), True),
    StructField("rejected", BooleanType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Schema for zeek_http
http_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("trans_depth", IntegerType(), True),
    StructField("method", StringType(), True),
    StructField("host", StringType(), True),
    StructField("uri", StringType(), True),
    StructField("version", StringType(), True),
    StructField("user_agent", StringType(), True),
    StructField("request_body_len", IntegerType(), True),
    StructField("response_body_len", IntegerType(), True),
    StructField("status_code", IntegerType(), True),
    StructField("status_msg", StringType(), True),
    StructField("tags", ArrayType(StringType()), True),
    StructField("resp_fuids", ArrayType(StringType()), True),
    StructField("orig_fuids", ArrayType(StringType()), True),
    StructField("orig_mime_types", ArrayType(StringType()), True),
    StructField("resp_mime_types", ArrayType(StringType()), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Schema for zeek_notice
notice_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("proto", StringType(), True),
    StructField("note", StringType(), True),
    StructField("msg", StringType(), True),
    StructField("src", StringType(), True),
    StructField("dst", StringType(), True),
    StructField("p", IntegerType(), True),
    StructField("actions", ArrayType(StringType()), True),
    StructField("email_dest", ArrayType(StringType()), True),
    StructField("suppress_for", FloatType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Schema for zeek_ssl
ssl_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("version", StringType(), True),
    StructField("cipher", StringType(), True),
    StructField("curve", StringType(), True),
    StructField("server_name", StringType(), True),
    StructField("resumed", BooleanType(), True),
    StructField("established", BooleanType(), True),
    StructField("ssl_history", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])