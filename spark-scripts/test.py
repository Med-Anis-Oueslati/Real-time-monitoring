from pyspark.sql import SparkSession

# Initialize Spark session
spark = SparkSession.builder \
    .appName("TestJob") \
    .getOrCreate()

# Create a simple RDD
data = ["hello world", "spark is awesome"]
rdd = spark.sparkContext.parallelize(data)

# Perform a word count
word_count = rdd.flatMap(lambda line: line.split(" ")) \
    .map(lambda word: (word, 1)) \
    .reduceByKey(lambda a, b: a + b)

# Print the result
print(word_count.collect())