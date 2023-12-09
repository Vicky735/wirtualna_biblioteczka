import psycopg2
import json

db_params = {
    'host': 'localhost',
    'database': 'virtual_library',
    'user': 'postgres',
    'password': 'passwd',
    'port': '5432'
}

try:
    connection = psycopg2.connect(**db_params)
    cursor = connection.cursor()

    with open('trigger.sql', 'r', encoding='utf8') as trigger_file:
        trigger_sql = trigger_file.read()
        cursor.execute(trigger_sql)


    connection.commit()
    cursor.close()
    connection.close()

    print("Trigger succefully added.")

except Exception as e:
    print(f"Error: {e}")