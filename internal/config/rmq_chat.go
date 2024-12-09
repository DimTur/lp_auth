package config

type Chat struct {
	ChatIDQueue  QueueConfig  `yaml:"chat_id_queue"`
	ChatConsumer ChatConsumer `yaml:"chat_consumer"`
}

type ChatConsumer struct {
	Queue        string       `yaml:"queue"`
	Consumer     string       `yaml:"consumer"`
	AutoAck      bool         `yaml:"autoAck"`
	Exclusive    bool         `yaml:"exclusive"`
	NoLocal      bool         `yaml:"noLocal"`
	NoWait       bool         `yaml:"noWait"`
	ConsumerArgs ConsumerArgs `yaml:"args"`
}
