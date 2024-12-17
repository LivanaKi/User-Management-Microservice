package db

import(
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func InitDB()(*sql.DB, error){
	database, err := sql.Open("sqlite3", "./user.db")
	if err != nil{
		log.Fatal(err)
		return nil, err
	}

	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
		"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
		"name" TEXT, 
		"email" TEXT UNIQUE, 
		"password" TEXT, 
		"created_at" DATETIME
	);`

	_, err = database.Exec(createTableSQL)
	if err != nil{
		return nil, fmt.Errorf("could not create TABLE: %v", err)
	}

	return database, nil
}