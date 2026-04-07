import mysql.connector


class Db_Tools:
    def __init__(self):
        pass

    def init(self):
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Lavi1234!",
            autocommit=True
        )
        return mydb

    def init_with_db(self, dbName):
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Lavi1234!",
            database=dbName,
            autocommit=True
        )
        return mydb

    def delete_all_rows(self, mydb, tableName):
        mycursor = mydb.cursor()
        try:
            tables = self.show_tables(mydb)
            if tableName in tables:
                sql = f"DELETE FROM {tableName}"
                print(sql)
                mycursor.execute(sql)
                mydb.commit()
                print(f"[+] All rows deleted from table '{tableName}'.")
            else:
                print(f"[x] No table named '{tableName}' found.")
        finally:
            mycursor.close()

    def update_ddos_status_by_ip(self, mydb, ip, is_blocked):
        cursor = mydb.cursor()
        try:
            val = 1 if is_blocked else 0
            sql = "UPDATE clients SET clients_ddos_status = %s WHERE clients_ip = %s"
            cursor.execute(sql, (val, ip))
            mydb.commit()
        finally:
            cursor.close()

    def is_ip_blocked(self, mydb, ip):
        cursor = mydb.cursor()
        try:
            sql = "SELECT clients_ddos_status FROM clients WHERE clients_ip = %s LIMIT 1"
            cursor.execute(sql, (ip,))
            result = cursor.fetchone()
            return result is not None and bool(result[0])
        except Exception as e:
            print(f"[!] DB Error in is_ip_blocked: {e}")
            return False
        finally:
            cursor.close()

    def show_databases(self, mydb):
        mycursor = mydb.cursor()
        try:
            mycursor.execute("SHOW DATABASES")
            return [i[0] for i in mycursor]
        finally:
            mycursor.close()

    def create_database(self, mydb, dbName):
        mycursor = mydb.cursor()
        try:
            if dbName not in self.show_databases(mydb):
                mycursor.execute("CREATE DATABASE " + dbName)
        finally:
            mycursor.close()

    def is_db_in_table(self, mydb, table_name, user_id, password_hash):
        rows = self.get_rows_from_table_with_value(mydb, table_name, "clients_hostname", user_id)

        if not rows:
            return False

        for row in rows:
            db_hashed_password = row[1]
            if db_hashed_password == password_hash:
                return True

        return False

    def insert_client_info(self, mydb, password_hashed, hostname, ip, last_seen, created_at):
        column_names = "(clients_password_hashed, clients_hostname, clients_ip, clients_last_seen, clients_status, clients_ddos_status, clients_created_at)"
        placeholders = "(%s, %s, %s, %s, %s, %s, %s)"
        values = (password_hashed, hostname, ip, last_seen, "CLEAN", False, created_at)
        self.insert_row(mydb, "clients", column_names, placeholders, values)

    def insert_event(
        self,
        mydb,
        events_client_id,
        events_interface,
        events_victim_ip,
        events_old_mac,
        events_new_mac,
        events_action,
        events_method,
        events_status,
        events_ddos_status
    ):
        column_names = """(
            events_client_id,
            events_interface,
            events_victim_ip,
            events_old_mac,
            events_new_mac,
            events_action,
            events_method,
            events_status,
            events_ddos_status
        )"""

        placeholders = "(%s, %s, %s, %s, %s, %s, %s, %s, %s)"

        values = (
            events_client_id,
            events_interface,
            events_victim_ip,
            events_old_mac,
            events_new_mac,
            events_action,
            events_method,
            events_status,
            events_ddos_status
        )

        self.insert_row(mydb, "events", column_names, placeholders, values)

    def update_client_entry(self, db, hostname, ip, last_seen, password_hashed):
        mycursor = db.cursor()
        sql = """
            UPDATE clients
            SET clients_password_hashed = %s,
                clients_ip = %s,
                clients_last_seen = %s
            WHERE clients_hostname = %s
        """
        values = (password_hashed, ip, last_seen, hostname)

        try:
            mycursor.execute(sql, values)
            db.commit()
        except mysql.connector.Error as err:
            print(f"[!] Error updating client: {err}")
        finally:
            mycursor.close()

    def delete_row(self, mydb, tableName, columnName, columnValue):
        mycursor = mydb.cursor()
        try:
            tables = self.show_tables(mydb)
            if tableName in tables:
                sql = f"DELETE FROM {tableName} WHERE {columnName} = %s"
                print(sql, (columnValue,))
                mycursor.execute(sql, (columnValue,))
                mydb.commit()
            else:
                print("No column name with name " + tableName)
        finally:
            mycursor.close()

    def get_all_rows(self, mydb, tableName):
        mycursor = mydb.cursor()
        try:
            tables = self.show_tables(mydb)
            if tableName in tables:
                sql = "SELECT * FROM " + tableName
                print(sql)
                mycursor.execute(sql)
                myresult = mycursor.fetchall()
                return myresult
            else:
                print(f"No table exists with name {tableName}")
                return []
        finally:
            mycursor.close()

    def get_rows_from_table_with_value(self, mydb, tableName, columnName, columnValue):
        mycursor = mydb.cursor()
        try:
            tables = self.show_tables(mydb)
            if tableName in tables:
                sql = f"SELECT * FROM {tableName} WHERE {columnName} = %s"
                print(sql, (columnValue,))
                mycursor.execute(sql, (columnValue,))
                myresult = mycursor.fetchall()
                return myresult
            else:
                print("No column name with name " + tableName)
                return []
        finally:
            mycursor.close()

    def insert_row(self, mydb, tableName, columnNames, columnTypes, columnValues):
        mycursor = mydb.cursor()
        try:
            sql = f"INSERT INTO {tableName} {columnNames} VALUES {columnTypes}"
            mycursor.execute(sql, columnValues)
            mydb.commit()
        except Exception as e:
            print(f"[!] Database Insert Error in {tableName}: {e}")
        finally:
            mycursor.close()

    def update_client_status(self, mydb, hostname, status):
        cursor = mydb.cursor()
        try:
            sql = "UPDATE clients SET clients_status = %s WHERE clients_hostname = %s"
            cursor.execute(sql, (status, hostname))
            mydb.commit()
        except Exception as e:
            print(f"[!] Error updating client status: {e}")
        finally:
            cursor.close()

    def initialize_database(self):
        temp_conn = self.init()
        self.create_database(temp_conn, "arp_project")
        temp_conn.close()
        return self.init_with_db("arp_project")

    def show_tables(self, mydb):
        mycursor = mydb.cursor()
        try:
            mycursor.execute("SHOW TABLES")
            return [i[0] for i in mycursor]
        finally:
            mycursor.close()

    def create_table(self, mydb, tableName, params):
        mycursor = mydb.cursor()
        try:
            tables = self.show_tables(mydb)
            if tableName not in tables:
                query = f"CREATE TABLE {tableName} {params}"
                mycursor.execute(query)
                print(f"[+] Table '{tableName}' created.")
            else:
                print(f"[=] Table '{tableName}' already exists.")
        finally:
            mycursor.close()

    def delete_table(self, mydb, tableName):
        mycursor = mydb.cursor()
        try:
            tables = self.show_tables(mydb)
            if tableName in tables:
                mycursor.execute(f"DROP TABLE {tableName}")
                print(f"[-] Table '{tableName}' deleted.")
            else:
                print(f"[x] No table named '{tableName}' found.")
        finally:
            mycursor.close()

    def get_client_id_by_hostname(self, db, hostname):
        cursor = db.cursor()
        try:
            cursor.execute(
                "SELECT clients_id FROM clients WHERE clients_hostname = %s",
                (hostname,)
            )
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            cursor.close()


if __name__ == "__main__":
    dbt = Db_Tools()
    root_conn = dbt.init()
    db_name = "arp_project"
    dbt.create_database(root_conn, db_name)

    mydb = dbt.init_with_db(db_name)

    dbt.create_table(
        mydb,
        "clients",
        "(clients_id INT AUTO_INCREMENT PRIMARY KEY, "
        "clients_password_hashed VARCHAR(255), "
        "clients_hostname VARCHAR(255), "
        "clients_ip VARCHAR(45), "
        "clients_last_seen DATETIME, "
        "clients_status VARCHAR(50) DEFAULT 'CLEAN', "
        "clients_ddos_status BOOLEAN DEFAULT FALSE, "
        "clients_created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
    )

    dbt.create_table(
        mydb,
        "events",
        "(events_id INT AUTO_INCREMENT PRIMARY KEY, "
        "events_client_id INT NOT NULL, "
        "events_interface VARCHAR(100), "
        "events_victim_ip VARCHAR(45), "
        "events_old_mac VARCHAR(20), "
        "events_new_mac VARCHAR(20), "
        "events_action VARCHAR(50), "
        "events_method VARCHAR(50), "
        "events_status VARCHAR(50), "
        "events_ddos_status VARCHAR(50) DEFAULT 'normal', "
        "events_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "FOREIGN KEY (events_client_id) REFERENCES clients(clients_id))"
    )
    print("\nDatabase and tables created successfully!")