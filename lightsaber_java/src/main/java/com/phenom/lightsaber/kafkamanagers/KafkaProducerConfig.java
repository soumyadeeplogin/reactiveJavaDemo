package com.phenom.lightsaber.kafkamanagers;

import com.phenom.lightsaber.partitionmanagers.LightSaberPartitioner;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaProducerConfig {

    @Autowired
    Environment env;

    @Bean
    public ProducerFactory<String, String> producerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, env.getProperty("kafka.bootstrapAddress"));
        configProps.put(ProducerConfig.CLIENT_ID_CONFIG, env.getProperty("client.id"));
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.ACKS_CONFIG, env.getProperty("acks"));
        configProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, env.getProperty("compression.type"));
        configProps.put(ProducerConfig.RETRIES_CONFIG, env.getProperty("retries"));
        configProps.put(ProducerConfig.BATCH_SIZE_CONFIG, env.getProperty("batch.size"));
        configProps.put(ProducerConfig.LINGER_MS_CONFIG, env.getProperty("linger.ms"));
        configProps.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, env.getProperty("max.block.ms"));
        configProps.put(ProducerConfig.BUFFER_MEMORY_CONFIG, env.getProperty("buffer.memory"));
        configProps.put(ProducerConfig.PARTITIONER_CLASS_CONFIG, LightSaberPartitioner.class);
        return new DefaultKafkaProducerFactory<>(configProps);
    }

    @Bean
    public ProducerFactory<String, String> batchProducerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, env.getProperty("batch.kafka.bootstrapAddress"));
        configProps.put(ProducerConfig.CLIENT_ID_CONFIG, env.getProperty("client.id"));
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.ACKS_CONFIG, env.getProperty("acks"));
//        configProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, env.getProperty("compression.type"));
        configProps.put(ProducerConfig.RETRIES_CONFIG, env.getProperty("retries"));
        configProps.put(ProducerConfig.BATCH_SIZE_CONFIG, env.getProperty("batch.size"));
        configProps.put(ProducerConfig.LINGER_MS_CONFIG, env.getProperty("linger.ms"));
        configProps.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, env.getProperty("max.block.ms"));
        configProps.put(ProducerConfig.BUFFER_MEMORY_CONFIG, env.getProperty("buffer.memory"));
        configProps.put(ProducerConfig.PARTITIONER_CLASS_CONFIG, LightSaberPartitioner.class);
        return new DefaultKafkaProducerFactory<>(configProps);
    }

    @Bean
    public KafkaTemplate<String, String> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    @Bean
    public KafkaTemplate<String, String> batchKafkaTemplate() {
        return new KafkaTemplate<>(batchProducerFactory());
    }
}