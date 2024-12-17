package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Users/natza/userServer/auth"
	"github.com/Users/natza/userServer/db"
	"github.com/Users/natza/userServer/model"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var database, _ = db.InitDB()
var ErrUserNotFound = errors.New("user not found")

func hashPassword(password string) string {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        panic("Failed to hash password") // Или обработайте ошибку безопасно
    }
    return string(hashedPassword)
}


func CreateUserHandler(w http.ResponseWriter, r *http.Request){
	var user model.User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil{
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	hashedPassword := hashPassword(user.Password)
	user.Password = string(hashedPassword)
	user.CreatedAt = time.Now()

	insertSQL := `INSERT INTO users (name, email, password, created_at) VALUES(?,?,?,?)`
	_, err = database.Exec(insertSQL, user.Name, user.Email, user.Password, user.CreatedAt)
	if err != nil{
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&loginData)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var user model.User
	err = database.QueryRow("SELECT id, name, email, password FROM users WHERE email = ?", loginData.Email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Перевірка пароля
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерація токена
	token, err := auth.GenerateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Повернення токена
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Отримання користувача за ID
func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var user model.User
	err := database.QueryRow("SELECT id, name, email, created_at FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}
func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
    // Отримуємо ID користувача з URL
    vars := mux.Vars(r)
    userID, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }

    var updatedUser model.User
    // Декодуємо JSON із запиту
    err = json.NewDecoder(r.Body).Decode(&updatedUser)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    // Якщо пароль оновлюється, шифруємо його
    if updatedUser.Password != "" {
        updatedUser.Password = hashPassword(updatedUser.Password)
    }

    // Оновлюємо дані користувача
    updatedUser.ID = userID
    err = UpdateUser(database, updatedUser)
    if err != nil {
        if errors.Is(err, ErrUserNotFound) {
            http.Error(w, "User not found", http.StatusNotFound)
        } else {
            http.Error(w, "Failed to update user", http.StatusInternalServerError)
        }
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(updatedUser)
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
    // Отримуємо ID користувача з URL
    vars := mux.Vars(r)
    userID, err := strconv.Atoi(vars["id"])
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }

    // Видаляємо користувача
    err = DeleteUser(database, userID)
    if err != nil {
        if errors.Is(err, ErrUserNotFound) {
            http.Error(w, "User not found", http.StatusNotFound)
        } else {
            http.Error(w, "Failed to delete user", http.StatusInternalServerError)
        }
        return
    }

    w.WriteHeader(http.StatusNoContent) // 204 No Content
}
func UpdateUser(database *sql.DB, user model.User) error {
	query := `
    UPDATE users 
    SET name = COALESCE(NULLIF(?, ''), name), 
        email = COALESCE(NULLIF(?, ''), email),
        password = COALESCE(NULLIF(?, ''), password)
    WHERE id = ?`
    result, err := database.Exec(query, user.Name, user.Email, user.Password, user.ID)
    if err != nil {
        return err
    }
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return err
    }
    if rowsAffected == 0 {
        return ErrUserNotFound
    }
    return nil
}
func DeleteUser(db *sql.DB, userID int) error {
    query := `DELETE FROM users WHERE id = $1`
    result, err := db.Exec(query, userID)
    if err != nil {
        return err
    }
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return err
    }
    if rowsAffected == 0 {
        return ErrUserNotFound
    }
    return nil
}
