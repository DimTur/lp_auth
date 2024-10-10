package crypto

import "golang.org/x/crypto/bcrypt"

type PasswordHasher struct {
}

func NewPasswordHasher() PasswordHasher {
	return PasswordHasher{}
}

func (ph PasswordHasher) HashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashedPassword, nil
}

func (ph PasswordHasher) ComparePassword(fromDB []byte, fromUser string) bool {
	if err := bcrypt.CompareHashAndPassword(fromDB, []byte(fromUser)); err != nil {
		return false
	}
	return true
}
