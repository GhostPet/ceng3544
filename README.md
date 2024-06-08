<h1 align="center">
  <a href="https://github.com/GhostPet/ImageWebsite">
    CENG 3544 Computer and Network Security Project Demo
  </a>
</h1>

<div align="center">
  You can see the study report named "Teamreport_CENG3544.pdf".
</div>

---

<details open="open">
<summary style="font-size:1.4rem;"><b style="font-size:1.5rem;margin-left:0.5rem">Table of Contents</b></summary>

- [About](#about)
- [Getting Started](#getting-started)
  - [Quick Start](#quick-start)
  - [DB Connections](#db-connections)
- [Roadmap](#roadmap)
- [License](#license)

</details>

---

## About

This project demonstrates secure user authentication methods (QR Code, Email Verification, and One Time Password (OTP)) scenarios.

## Getting Started

### Quick Start
The recommended method to install **CENG 3544 Project** is by using [Git](https://git-scm.com/download)'s bash terminal.

To install them, you can copy and paste the code below line by line:
```sh
python -m venv virtenv 
source virtenv/Scripts/activate

pip install -r requirements.txt
```

Then make sure you can connect the Db of your choice with filling the information in .env file.

ENV File Format:

```
# Development settings
SQLALCHEMY_DATABASE_URI=
SECRET_KEY=
UPLOAD_FOLDER=uploads
```

### DB Connections
- **For SqLite connection:**
  You can change url inside the .env file.

- **For MySQL connection:**
  You can change url inside the .env file. Afterwards, you may need to install these additional libraries.
  - **PyMySQL** 1.1.0 - [PyMySQL lastest Docs](https://pymysql.readthedocs.io/en/latest/) - For connecting the db with Flask-SQLAlchemy
    ```sh
    pip install PyMySQL
    ```
  - **mysql-connector-python** 8.3.0 - [mysql-connector-python Docs](https://dev.mysql.com/doc/connector-python/en/) - For creating a db without using additional tool
    ```sh
    pip install mysql-connector-python
    ```

  > **Note:** In MySQL servers, you need to start your connection url with: "mysql+pymysql://".

  And to create a new db without using a tool like MySQL Workbench, you should create a new file, paste the code below inside, fill it with your db information, and execute the file. Then you can delete the file.
  ```py #2 create_db.py
  import mysql.connector
  mydb = mysql.connector.connect(host="", user="", passwd="") #Fill here
  mycursor = mydb.cursor()
  mycursor.execute("CREATE DATABASE your_db_name")
  mycursor.close()
  mydb.close()
  ```

- **For PostgreSQL connection:**
  You can change the \_\_init\_\_.py. Afterwards, you may need to install these additional libraries.
  - **psycopg2** 2.9.9 - [psycopg2 Docs](https://www.psycopg.org/docs/) - For connecting the db with Flask-SQLAlchemy
    ```sh
      pip install psycopg2
    ```
  > **Note:** PostgreSQL is not support the db.Text length.


For Db migrations, after the changes you may use the command below:
```sh
flask db migrate -m 'Comments'
flask db upgrade
```

## Roadmap

See the [open issues](https://github.com/GhostPet/ImageWebsite/issues) for a list of proposed features (and known issues).

## License

This project is licensed under the **MIT license**. Feel free to edit and distribute this website as you like.

See [LICENSE](LICENSE) for more information.