package mysql

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ============================================
// 用户管理模块
// 说明: 处理用户的增删改查、认证、权限等操作
// ============================================

// ValidateUser 验证用户登录
func ValidateUser(username, password string) (bool, string, error) {
	var hashedPassword string
	var role string
	err := DB.QueryRow("SELECT password, role FROM user WHERE username = ?", username).Scan(&hashedPassword, &role)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, "", nil
	}

	return true, role, nil
}

// GetUserRole 获取用户角色
func GetUserRole(username string) (string, error) {
	var role string
	err := DB.QueryRow("SELECT role FROM user WHERE username = ?", username).Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

// GetUserID 获取用户ID
func GetUserID(username string) (int, error) {
	var id int
	err := DB.QueryRow("SELECT id FROM user WHERE username = ?", username).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// CreateUser 创建新用户
func CreateUser(username, password string) error {
	// 检查用户是否已存在
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM user WHERE username = ?", username).Scan(&count)
	if err != nil {
		return fmt.Errorf("检查用户失败: %v", err)
	}
	if count > 0 {
		return fmt.Errorf("用户名已存在")
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败: %v", err)
	}

	// 插入新用户
	_, err = DB.Exec(
		"INSERT INTO user (username, password, role, created_at) VALUES (?, ?, ?, NOW())",
		username,
		string(hashedPassword),
		"user", // 默认角色为普通用户
	)
	if err != nil {
		return fmt.Errorf("创建用户失败: %v", err)
	}

	return nil
}

// UpdatePassword 更新用户密码
func UpdatePassword(username, oldPassword, newPassword string) error {
	// 先验证旧密码是否正确
	var hashedPassword string
	err := DB.QueryRow("SELECT password FROM user WHERE username = ?", username).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		return fmt.Errorf("用户不存在")
	}
	if err != nil {
		return err
	}

	// 验证旧密码
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(oldPassword))
	if err != nil {
		return fmt.Errorf("旧密码错误")
	}

	// 加密新密码
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 更新密码
	_, err = DB.Exec("UPDATE user SET password = ? WHERE username = ?", string(newHashedPassword), username)
	return err
}

// GetUserAvatar 获取用户头像
func GetUserAvatar(username string) (string, error) {
	var avatar string
	err := DB.QueryRow("SELECT avatar FROM user WHERE username = ?", username).Scan(&avatar)
	if err != nil {
		return "", err
	}
	return avatar, nil
}

// UpdateUserAvatar 更新用户头像
func UpdateUserAvatar(username, avatarURL string) error {
	_, err := DB.Exec("UPDATE user SET avatar = ? WHERE username = ?", avatarURL, username)
	return err
}
