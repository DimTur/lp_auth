package otp

import (
	mr "math/rand"
	"strconv"
	"time"
)

func RandOTP() string {
	r := mr.New(mr.NewSource(time.Now().UnixNano()))
	randomNumber := r.Intn(9000) + 1000
	rd := strconv.Itoa(randomNumber)

	return rd
}
