package rabbitmq

import (
	"log"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RMQClient struct {
	Conn      *amqp.Connection
	adminCH   *amqp.Channel
	publishCH *amqp.Channel
}

// NewClient create conn with RabbitMQ
func NewClient(url string) (*RMQClient, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}

	// Create client
	client := &RMQClient{Conn: conn}

	// Create admin channel
	client.adminCH, err = client.Conn.Channel()
	if err != nil {
		client.Close()
		return nil, err
	}

	// Create publish channel
	client.publishCH, err = client.Conn.Channel()
	if err != nil {
		client.Close()
		return nil, err
	}

	return client, nil
}

// Close close conn and channels
func (c *RMQClient) Close() {
	if c.publishCH != nil {
		if err := c.publishCH.Close(); err != nil {
			log.Printf("error closing publish channel: %v", err)
		}
	}
	if c.adminCH != nil {
		if err := c.adminCH.Close(); err != nil {
			log.Printf("error closing admin channel: %v", err)
		}
	}
	if c.Conn != nil {
		if err := c.Conn.Close(); err != nil {
			log.Printf("error closing connection: %v", err)
		}
	}
}
