
#!/usr/bin/env python3

#=========================================================
# Authslime
# SlimeDB  
# Actions for loading/querying with the SlimeDB
#=========================================================

import sqlite3
"""

SlimeDB

+-------------------+        +-------------------+		  
|       Slime       |        |       Keys	     |
+-------------------+        +-------------------+		 
| Slime ID (PK)     |        |                   |        
| KeyID (FK)        | -----> | KeyID (PK)        | 
| Version           |        | WrappedPrivateKey |       
| Name              |        | PublicKey         |        
| Color             |        | Certificate       |		  
| Template          |        | WrappedSymKey     |
| AuthslimeImage    |	     | IV				 |
+-------------------+		 | AAD	             |
        					 | Tag		         |
         ^					 +-------------------+
         |
+-------------------+  
|    Accessories    |
+-------------------+  
| SlimeID (FK)      | 
| AccessoryName     |
+-------------------+ 



"""

#------------------Read------------------#

def check_tables():
	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()
	tablecheck = cursor.execute("SELECT name FROM sqlite_master").fetchall()
	
	if tablecheck == []:
		found = False
	else:
		found = True

	return found

def read_all_slime():
	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()

	cursor.execute("SELECT * FROM Slime")

	slimes = cursor.fetchall()

	# Print the column names
	columns = [description[0] for description in cursor.description]
	print("|".join(columns))

	# Print a separator line
	print("-" * (len("|".join(columns)) + len(columns) - 1))

	# Print each row
	for slime in slimes:
		print("|".join(map(str, slime)))

	slimedb_connection.close()

def read_keys():
	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()

	cursor.execute("SELECT * FROM Keys")

	keys = cursor.fetchall()

	# Print the column names
	column_names = [description[0] for description in cursor.description]
	print("Column Names:", column_names)
	
	# Print each row
	for key in keys:
		print("   ".join(map(str, key)))

	slimedb_connection.close()

#------------------Write------------------#

def create_tables():

	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()
	
	#Create Slime Table
	cursor.execute('''
	CREATE TABLE Slime (
        SlimeID TEXT PRIMARY KEY,
        KeyID TEXT,
        Version INTEGER,
        Name TEXT,
        Color TEXT,
        Template INTEGER,
        AuthslimeImage BLOB,
        FOREIGN KEY (KeyID) REFERENCES Keys(KeyID)
        )
		''')

	#Create Keys Table
	cursor.execute('''
    CREATE TABLE Keys (
        KeyID TEXT PRIMARY KEY,
        WrappedPrivateKey BLOB,
        PublicKey TEXT,
        Certificate TEXT,
        WrappedSymKey BLOB,
        IV BLOB,
        AAD TEXT,
        Tag BLOB
    	)
	''')

	#Create Accessories Table
	cursor.execute('''
    CREATE TABLE Accessories (
        SlimeID TEXT,
        AccessoryName TEXT,
        FOREIGN KEY (SlimeID) REFERENCES Slime(SlimeID)
    	)
	''')

	slimedb_connection.commit()
	slimedb_connection.close()


def insert_into_slime_table(slime_dict):
	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()

	cursor.execute('''
    INSERT INTO Slime (SlimeID, KeyID, Version, Name, Color, Template, AuthslimeImage)
    VALUES (?, ?, ?, ?, ?, ?, ?)
	''', slime_dict)


	slimedb_connection.commit()
	slimedb_connection.close()

def insert_into_keys_table(key_dict):
	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()

	cursor.execute('''
	INSERT INTO Keys (KeyID, WrappedPrivateKey, PublicKey, Certificate, WrappedSymKey, IV, AAD, Tag)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		''',key_dict)

	slimedb_connection.commit()
	slimedb_connection.close()


def insert_into_accessories_table(accessory_dict):
	slimedb_connection = sqlite3.connect("authslime.db")
	cursor = slimedb_connection.cursor()

	cursor.execute('''
	INSERT INTO Accessories (SlimeID, AccessoryName)
	VALUES (?, ?)
		''',accessory_dict)

	slimedb_connection.commit()
	slimedb_connection.close()
