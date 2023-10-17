import os


if __name__ == "__main__":
    if "MOE_BOT_SERV_SQLALCHEMY_DATABASE_URI" in os.environ:
        # check if mysql or postgresql database is existing
        # if not, create it
        if "mysql" in os.environ["MOE_BOT_SERV_SQLALCHEMY_DATABASE_URI"]:
            # mysql
            import pymysql

            sqlalchemy_database_uri = os.environ["MOE_BOT_SERV_SQLALCHEMY_DATABASE_URI"]
            # MOE_BOT_SERV_SQLALCHEMY_DATABASE_URI=mariadb+pymysql://root:budaC0k_corunakliS1fre@mariadb:3306/moe_bot_auth_server?charset=utf8mb4
            connection_info = {
                "host": sqlalchemy_database_uri.split("@")[-1].split(":")[0],
                "port": int(
                    sqlalchemy_database_uri.split("@")[-1].split(":")[1].split("/")[0]
                ),
                "user": sqlalchemy_database_uri.split("//")[-1].split(":")[0],
                "password": sqlalchemy_database_uri.split("//")[-1]
                .split(":")[1]
                .split("@")[0],
                "charset": sqlalchemy_database_uri.split("?")[-1].split("=")[1],
            }
            table_name = sqlalchemy_database_uri.split("/")[-1].split("?")[0]
            print("detect mysql")
            print(connection_info)
            conn = pymysql.connect(**connection_info)
            conn.cursor().execute(
                "CREATE DATABASE IF NOT EXISTS " + table_name + " CHARACTER SET utf8mb4"
            )
            conn.cursor().close()
            conn.close()
            print("OK: finish creating database")
            exit(0)
        elif "postgresql" in os.environ["MOE_BOT_SERV_SQLALCHEMY_DATABASE_URI"]:
            # postgresql
            raise NotImplementedError("postgresql is not supported yet")
            import psycopg2

            uri = os.environ["MOE_BOT_SERV_SQLALCHEMY_DATABASE_URI"]
            connection_info = {}
            print("detect postgresql")
            print(connection_info)
            table_name = uri.split("/")[-1]
            conn = psycopg2.connect(**connection_info)
            conn.cursor().execute("CREATE DATABASE IF NOT EXISTS " + table_name)
            conn.cursor().close()
            conn.close()
            print("OK: finish creating database")
            exit(0)
        else:
            # other database
            pass
