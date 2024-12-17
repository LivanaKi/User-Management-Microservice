package main

import(
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/Users/natza/userServer/handler"
)

func main(){

	r := mux.NewRouter()

	r.HandleFunc("/users", handler.CreateUserHandler).Methods("POST")
	r.HandleFunc("/login", handler.LoginHandler).Methods("POST")

	r.HandleFunc("/users/{id}", handler.GetUserHandler).Methods("GET")
	r.HandleFunc("/users/{id}", handler.UpdateUserHandler).Methods("PUT")
	r.HandleFunc("/users/{id}", handler.DeleteUserHandler).Methods("DELETE")

	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", r)
}