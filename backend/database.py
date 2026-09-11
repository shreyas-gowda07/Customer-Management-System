print("Python file is running")
import psycopg2
print("psycopg2 imported successfully")
conn=psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="luffy",
    port="5432"
)
print("Database connected successfully")
cursor=conn.cursor()
cursor.execute("SELECT * FROM products;")
rows=cursor.fetchall()
print("number of rows:",len(rows))
for row in rows:
    print(row)
cursor.close()
conn.close()
print("connection closed")