package validator

import (
	"regexp"

	ssov1 "github.com/DimTur/learning_platform/auth/pkg/server/grpc/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ValidateLogin(req *ssov1.LoginUserRequest) error {
	email := req.GetEmail()
	if email == "" || !validEmail(email) {
		var errMsg string
		if email == "" {
			errMsg = "email is required"
		} else {
			errMsg = "invalid email"
		}
		return status.Error(codes.InvalidArgument, errMsg)
	}

	psw := req.GetPassword()
	if psw == "" || !validPsw(psw) {
		var errMsg string
		if psw == "" {
			errMsg = "password is required"
		} else {
			errMsg = "weak password"
		}
		return status.Error(codes.InvalidArgument, errMsg)
	}

	appID := req.GetAppId()
	if appID == "" || !validAppID(appID) {
		var errMsg string
		if appID == "" {
			errMsg = "app_id is required"
		} else {
			errMsg = "invalid app_id"
		}
		return status.Error(codes.InvalidArgument, errMsg)
	}

	return nil
}

// validEmail checks that email is correct
func validEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// Password checking:
// - min 8 symbols
// - at least one digit
// - at least one uppercase letter
// - at least one special character from list !@#$%^&*
func validPsw(password string) bool {
	if len(password) < 8 {
		return false
	}

	reNumber := regexp.MustCompile(`[0-9]`)
	reUpper := regexp.MustCompile(`[A-Z]`)
	reSpecial := regexp.MustCompile(`[!@#$%^&*]`)

	return reNumber.MatchString(password) && reUpper.MatchString(password) && reSpecial.MatchString(password)
}

// validAppID checks that appID is uuid
func validAppID(appID string) bool {
	re := regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
	return re.MatchString(appID)
}
