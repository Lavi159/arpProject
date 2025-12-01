import mysql.connector

class Db_Tools:
    def __init__(self):
        pass
    def init(self):
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Lavi1234!"
        )
        return mydb

    def init_with_db(self, dbName):
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Lavi1234!",
            database=dbName
        )
        return mydb
    def delete_all_rows(self, mydb, tableName):
        mycursor = mydb.cursor()
        tables = self.show_tables(mydb)
        if tableName in tables:
            sql = f"DELETE FROM {tableName}"
            print(sql)
            mycursor.execute(sql)
            mydb.commit()
            print(f"[+] All rows deleted from table '{tableName}'.")
        else:
            print(f"[x] No table named '{tableName}' found.")

    def show_databases(self, mydb):
        mycursor = mydb.cursor()
        mycursor.execute("SHOW DATABASES")
        return [i[0] for i in mycursor]

    def create_database(self, mydb, dbName):
        mycursor = mydb.cursor()
        if dbName not in self.show_databases(mydb):
            mycursor.execute("CREATE DATABASE " + dbName)
            print(f"[+] Database '{dbName}' created.")
        else:
            print(f"[=] Database '{dbName}' already exists.")
            
    def is_db_in_table(self, mydb, table_name, user_id, password_hash):
        
        rows = self.get_rows_from_table_with_value(mydb, table_name, "clients_hostname", user_id)
        
        if not rows:
            return False
            
        for row in rows:
            db_hashed_password = row[1] 
            if db_hashed_password == password_hash:
                return True
            
        return False
    
    #FOR THE DATABASE
    def insert_client_info(self, mydb, clients_passsword_hashed, clients_hostname, clients_ip, clients_last_seen, clients_ddos_status, clients_created_at):
        column_names = "(clients_password_hashed,clients_hostname, clients_ip, clients_last_seen, clients_ddos_status, clients_created_at)"
        
        placeholders = "(%s, %s, %s, %s, %s, %s)"
        
        values = (clients_passsword_hashed, clients_hostname, clients_ip, clients_last_seen, clients_ddos_status, clients_created_at)

        self.insert_row(mydb, "clients", column_names, placeholders, values)
        
    def update_client_entry(self, db, client_hostname, clients_ip, clients_last_seen, clients_ddos_status, clients_password_hashed):
        mycursor = db.cursor()
        
        sql = """
            UPDATE clients 
            SET 
                clients_password_hashed = %s,
                clients_ip = %s,
                clients_last_seen = %s,
                clients_ddos_status = %s
            WHERE clients_hostname = %s
        """
        
        values = (
            clients_password_hashed,
            clients_ip, 
            clients_last_seen, 
            clients_ddos_status,
            client_hostname 
        )
        
        try:
            print("UPDATE SQL:", sql)
            mycursor.execute(sql, values)
            db.commit()
            print(f"[+] Client '{client_hostname}' updated successfully.")
        except mysql.connector.Error as err:
            print(f"[!] Error updating client: {err}")
        
    def delete_row(self, mydb, tableName, columnName, columnValue):
        mycursor = mydb.cursor()
        tables = self.show_tables(mydb)
        if tableName in tables:
            sql = "DELETE FROM " + tableName + " WHERE "+ columnName + " =  '" + columnValue + "'"
            print(sql)
            mycursor.execute(sql)
            mydb.commit()
        else:
            print("No column name with name "+ tableName)

    def get_all_rows(self, mydb, tableName):
        mycursor = mydb.cursor()
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
           
    def get_rows_from_table_with_value(self, mydb, tableName, columnName, columnValue):
        mycursor = mydb.cursor()
        tables = self.show_tables(mydb)
        if tableName in tables:
            sql = "SELECT * FROM " + tableName + " WHERE "+ columnName + " =  '" + columnValue + "'"
            print(sql)
            mycursor.execute(sql)
            myresult = mycursor.fetchall()
            return myresult
        else:
            print("No column name with name "+ tableName)

    def insert_row(self,mydb, tableName, columnNames, columnTypes, columnValues):
        mycursor = mydb.cursor()
        tables = self.show_tables(mydb)
        if tableName in tables:
            sql = "INSERT INTO " + tableName + " "+ columnNames +" VALUES " + columnTypes
            print(sql)
            mycursor.execute(sql, columnValues)
            mydb.commit()
        else:
            print("No table exists with name "+ tableName)
            
    # Create and connect to MySQL database
    def initialize_database(self):
        mydb = self.init()
        self.create_database(mydb, "arp_project")
        return self.init_with_db("arp_project")
            
    def show_tables(self, mydb):
        mycursor = mydb.cursor()
        mycursor.execute("SHOW TABLES")
        return [i[0] for i in mycursor]

    def create_table(self, mydb, tableName, params):
        mycursor = mydb.cursor()
        tables = self.show_tables(mydb)
        if tableName not in tables:
            query = f"CREATE TABLE {tableName} {params}"
            mycursor.execute(query)
            print(f"[+] Table '{tableName}' created.")
        else:
            print(f"[=] Table '{tableName}' already exists.")

    def delete_table(self, mydb, tableName):
        mycursor = mydb.cursor()
        tables = self.show_tables(mydb)
        if tableName in tables:
            mycursor.execute(f"DROP TABLE {tableName}")
            print(f"[-] Table '{tableName}' deleted.")
        else:
            print(f"[x] No table named '{tableName}' found.")


if __name__ == "__main__":
    dbt = Db_Tools()
    root_conn = dbt.init()
    db_name = "arp_project"
    dbt.create_database(root_conn, db_name)

    mydb = dbt.init_with_db(db_name)

    #dbt.delete_table(mydb, "artifacts")
    #dbt.delete_table(mydb, "events")
    #dbt.delete_table(mydb, "clients")
    
    # --- clients ---
    dbt.create_table(mydb, "clients",
        "(clients_id INT AUTO_INCREMENT PRIMARY KEY, "
        "clients_password_hashed VARCHAR(255), "
        "clients_hostname VARCHAR(255), "
        "clients_ip VARCHAR(45), "
        "clients_last_seen DATETIME, "
        "clients_ddos_status ENUM('normal','suspicious','under_attack','blocked') DEFAULT 'normal', "
        "clients_created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
    )

    # --- events ---
    dbt.create_table(mydb, "events",
        "(events_id INT AUTO_INCREMENT PRIMARY KEY, "
        "events_client_id INT NOT NULL, "
        "events_interface VARCHAR(32) NOT NULL, "
        "events_victim_ip VARCHAR(45) NOT NULL, "
        "events_old_mac CHAR(17), "
        "events_new_mac CHAR(17) NOT NULL, "
        "events_action ENUM('blocked','allowed','ignored') NOT NULL, "
        "events_method ENUM('arptables','arpon','manual') NOT NULL, "
        "events_status ENUM('detected','enforced','failed') NOT NULL, "
        "events_ddos_status ENUM('normal','suspicious','under_attack','blocked') DEFAULT 'normal', "
        "events_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "FOREIGN KEY (events_client_id) REFERENCES clients(clients_id))"
    )

    # --- artifacts ---
    dbt.create_table(mydb, "artifacts",
        "(artifacts_id INT AUTO_INCREMENT PRIMARY KEY, "
        "artifacts_event_id INT NOT NULL, "
        "artifacts_type ENUM('pcap','log','image') NOT NULL, "
        "artifacts_path VARCHAR(512) NOT NULL, "
        "artifacts_size BIGINT, "
        "artifacts_hash CHAR(64), "
        "artifacts_ddos_status ENUM('normal','suspicious','under_attack','blocked') DEFAULT 'normal', "
        "artifacts_created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "FOREIGN KEY (artifacts_event_id) REFERENCES events(events_id))"
    )

    print("\nDatabase and tables created successfully!")
