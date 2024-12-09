package config

type Redis struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	TokenDB  int    `yaml:"token_db"`
	OtpDB    int    `yaml:"otp_db"`
	Password string `yaml:"password"`
}
