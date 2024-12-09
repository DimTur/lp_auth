package rabbitmq

import (
	"context"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

func (c *RMQClient) Consume(
	ctx context.Context,
	queueName, consumer string,
	autoAck, exclusive, noLocal, noWait bool,
	args map[string]interface{},
	handle func(ctx context.Context, msg interface{}) error,
) error {
	ch, err := c.Conn.Channel()
	if err != nil {
		log.Printf("Failed to open channel: %v", err)
		time.Sleep(1 * time.Second)
		return err
	}
	defer func() {
		if err := ch.Close(); err != nil {
			log.Printf("Failed to close channel: %v", err)
		}
	}()

	// Change args to amqp.Table
	tableArgs := amqp.Table(args)

	msgs, err := ch.Consume(
		queueName,
		consumer,
		autoAck,
		exclusive,
		noLocal,
		noWait,
		tableArgs,
	)
	if err != nil {
		return err
	}

	for {

		for {
			select {
			case msg, ok := <-msgs:
				if !ok {
					log.Println("Message channel closed, reconnecting...")
					return err
				}

				if err := handle(ctx, msg); err != nil {
					if nackErr := msg.Nack(false, false); nackErr != nil {
						log.Printf("Failed to Nack message: %v", nackErr)
					}
				} else {
					if ackErr := msg.Ack(false); ackErr != nil {
						log.Printf("Failed to acknowledge message: %v", ackErr)
					}
				}
			case <-ctx.Done():
				log.Println("Context cancelled, stopping message consumption")
				return nil
			}
		}
	}
}
