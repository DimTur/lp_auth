package validator

import (
	"regexp"

	ssov1 "github.com/DimTur/lp_protos/gen/go/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Regular expressions for checking
var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	passwordRegex = map[string]*regexp.Regexp{
		"number":  regexp.MustCompile(`[0-9]`),
		"upper":   regexp.MustCompile(`[A-Z]`),
		"special": regexp.MustCompile(`[!@#$%^&*]`),
	}
)

// ValidateLogin validates login request
func ValidateLogin(req *ssov1.LoginUserRequest) error {
	if err := validateEmail(req.GetEmail()); err != nil {
		return err
	}

	if err := validatePassword(req.GetPassword()); err != nil {
		return err
	}

	return nil
}

// ValidateRegister validates register request
func ValidateRegister(req *ssov1.RegisterUserRequest) error {
	if err := validateEmail(req.GetEmail()); err != nil {
		return err
	}

	if err := validatePassword(req.GetPassword()); err != nil {
		return err
	}

	return nil
}

// ValidateRefreshToken validates RefreshTokenRequest request
func ValidateRefreshToken(req *ssov1.RefreshTokenRequest) error {
	if err := validateRefreshToken(req.GetRefreshToken()); err != nil {
		return err
	}

	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if !emailRegex.MatchString(email) {
		return status.Error(codes.InvalidArgument, "invalid email")
	}
	return nil
}

func validatePassword(password string) error {
	if password == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	if len(password) < 8 {
		return status.Error(codes.InvalidArgument, "password must be at least 8 characters long")
	}
	if !passwordRegex["number"].MatchString(password) ||
		!passwordRegex["upper"].MatchString(password) ||
		!passwordRegex["special"].MatchString(password) {
		return status.Error(codes.InvalidArgument, "weak password")
	}
	return nil
}

func validateRefreshToken(refreshToken string) error {
	if refreshToken == "" {
		return status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	return nil
}
