import subprocess
from django.conf import settings
import mysql.connector
from mysql.connector import Error

def backup_database():
    db_name = settings.DATABASES['default']['NAME']
    db_user = settings.DATABASES['default']['USER']
    db_password = settings.DATABASES['default']['PASSWORD']
    db_host = settings.DATABASES['default']['HOST']
    db_port = settings.DATABASES['default']['PORT']
    
    backup_file = f"{db_name}_backup.sql"

    if settings.DATABASES['default']['ENGINE'] == 'django.db.backends.mysql':
        command = f"mysqldump -u {db_user} -p{db_password} -h {db_host} -P {db_port} {db_name} > {backup_file}"
    else:
        raise ValueError("Unsupported database backend")

    try:
        subprocess.check_call(command, shell=True)
        return backup_file
    except subprocess.CalledProcessError as e:
        print(f"Error backing up database: {e}")
        return None

def get_database_size():
    db_name = settings.DATABASES['default']['NAME']
    db_user = settings.DATABASES['default']['USER']
    db_password = settings.DATABASES['default']['PASSWORD']
    db_host = settings.DATABASES['default']['HOST']
    db_port = settings.DATABASES['default']['PORT']
    
    if settings.DATABASES['default']['ENGINE'] == 'django.db.backends.mysql':
        try:
            connection = mysql.connector.connect(
                host=db_host,
                database=db_name,
                user=db_user,
                password=db_password,
                port=db_port
            )

            query = f"SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS 'DB Size in MB' FROM information_schema.tables WHERE table_schema = '{db_name}';"
            cursor = connection.cursor()
            cursor.execute(query)
            result = cursor.fetchone()
            size_in_mb = float(result[0])

            cursor.close()
            connection.close()
            
            return size_in_mb
        except Error as e:
            print(f"Error getting database size: {e}")
            return None
    else:
        raise ValueError("Unsupported database backend")