package com.phenom.lightsaber.kafkamanagers;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.util.concurrent.ListenableFutureCallback;
import reactor.core.publisher.Mono;

@Component
public class KafkaEventProducer {

    @Autowired
    private KafkaTemplate<String, String> kafkaTemplate;

    @Autowired
    private KafkaTemplate<String, String> batchKafkaTemplate;



    public Mono<JSONObject> sendMessage(String message, String topicName, boolean batch) {

        ListenableFuture<SendResult<String, String>> future = batch ? batchKafkaTemplate.send(topicName, message) : kafkaTemplate.send(topicName, message);
        return Mono.create(sink -> future.addCallback(new ListenableFutureCallback<SendResult<String, String>>() {
            @Override
            public void onSuccess(SendResult<String, String> result) {
                JSONObject ackedBy = new JSONObject();
                ackedBy.put("checksum", result.getRecordMetadata().hashCode());
                ackedBy.put("partition", result.getRecordMetadata().partition());
                ackedBy.put("offset", result.getRecordMetadata().offset());
                ackedBy.put("timestamp", result.getRecordMetadata().timestamp());
                ackedBy.put("topic", result.getRecordMetadata().topic());

                JSONObject statusJson = new JSONObject();
                statusJson.put("Served-by", "unkown")
                        .put("Acked-by", ackedBy);

                JSONObject response = new JSONObject();
                response.put("statusCode", 200)
                        .put("statusMessage", statusJson);

                System.out.println(response);
                System.out.println("Sent message=[" + message +
                        "] with offset=[" + result.getRecordMetadata().offset() + "]");
                sink.success(response);
            }

            @Override
            public void onFailure(Throwable ex) {
                System.out.println("Unable to send message=["
                        + message + "] due to : " + ex.getMessage());
                sink.error(ex);
            }
        }));
//        return Mono.empty();
    }
}
