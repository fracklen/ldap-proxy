package logger

import (
    "github.com/Shopify/sarama"
    "time"
    "encoding/json"
    "fmt"
    "math/rand"
)

type JsonLogger struct {
    Config *sarama.Config
    Producer sarama.AsyncProducer
    Topic string
    input chan []byte
}

func NewLogger(brokers []string, topic string) *JsonLogger {
    config := sarama.NewConfig()
    config.Producer.Return.Successes = true
    producer, err := sarama.NewAsyncProducer(brokers, config)
    if err != nil {
        panic(err)
    }
    input := make(chan []byte, 1000)
    this := &JsonLogger{
        Config: config,
        Producer: producer,
        Topic: topic,
        input: input,
    }
    return this
}

func (c *JsonLogger) Printf(format string, args ... interface{}) {
    msg := fmt.Sprintf(format, args ...)
    data := make(map[string]interface{})
    data["message"] = msg
    data["@timestamp"] = time.Now().UTC()
    json_message, err := json.Marshal(data)
    if err == nil {
        c.input <- json_message
    }
}

func (c *JsonLogger) PrintData(severity string, data map[string]interface{}) {
    data["@timestamp"] = time.Now().UTC()
    data["severity"] = severity
    json_message, err := json.Marshal(data)
    if err == nil {
        c.input <- json_message
    }
}

func (c *JsonLogger) Error(data map[string]interface{}) {
    c.PrintData("error", data)
}

func (c *JsonLogger) Info(data map[string]interface{}) {
    c.PrintData("info", data)
}

func (c *JsonLogger) Debug(data map[string]interface{}) {
    c.PrintData("debug", data)
}

func (c *JsonLogger) Warn(data map[string]interface{}) {
    c.PrintData("warn", data)
}

func (c *JsonLogger) Run() {
    go c.ConsumeErrors()
    go c.ConsumeSuccesses()
    for msg := range c.input {
        key := rand.Int31n(15)
        c.Producer.Input() <- &sarama.ProducerMessage{
            Topic: c.Topic,
            Key:   sarama.StringEncoder(string(key)),
            Value: sarama.StringEncoder(string(msg)),
        }
    }
    defer c.Producer.AsyncClose()
}

func (c *JsonLogger) ConsumeErrors() {
    for err := range c.Producer.Errors() {
        fmt.Println("Logging Error:", err)
    }
}

func (c *JsonLogger) ConsumeSuccesses() {
    for _ = range c.Producer.Successes() {
    }
}

