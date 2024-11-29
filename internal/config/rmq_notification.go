package config

type Notification struct {
	NotificationQueue      QueueConfig          `yaml:"notification_queue"`
	NotificationExchange   NotificationExchange `yaml:"notification_exchange"`
	NotificationRoutingKey string               `yaml:"notification_routing_key"`
	NotificationConsumer   NotificationConsumer `yaml:"notification_consumer"`
}

type NotificationConsumer struct {
	Queue        string       `yaml:"queue"`
	Consumer     string       `yaml:"consumer"`
	AutoAck      bool         `yaml:"autoAck"`
	Exclusive    bool         `yaml:"exclusive"`
	NoLocal      bool         `yaml:"noLocal"`
	NoWait       bool         `yaml:"noWait"`
	ConsumerArgs ConsumerArgs `yaml:"args"`
}

type NotificationExchange struct {
	Name string `yaml:"name"`
}
