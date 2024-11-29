package config

type OTP struct {
	OTPExchange   OTPExchange `yaml:"otp_exchange"`
	OTPQueue      QueueConfig `yaml:"otp_queue"`
	OTPRoutingKey string      `yaml:"otp_routing_key"`
}

type OTPExchange struct {
	Name        string       `yaml:"name"`
	Kind        string       `yaml:"kind"`
	Durable     bool         `yaml:"durable"`
	AutoDeleted bool         `yaml:"auto_deleted"`
	Internal    bool         `yaml:"internal"`
	NoWait      bool         `yaml:"no_wait"`
	Args        ExchangeArgs `yaml:"args"`
}
