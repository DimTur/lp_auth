package config

type Spfu struct {
	SpfuExchange   SpfuExchange `yaml:"spfu_exchange"`
	SpfuQueue      QueueConfig  `yaml:"spfu_queue"`
	SpfuRoutingKey string       `yaml:"spfu_routing_key"`
}

type SpfuExchange struct {
	Name string `yaml:"name"`
}
