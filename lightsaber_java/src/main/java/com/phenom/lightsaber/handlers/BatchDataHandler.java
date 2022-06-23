package com.phenom.lightsaber.handlers;

import com.phenom.lightsaber.dataprocessor.ProcessData;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class BatchDataHandler {

    @Autowired
    ProcessData processData;

    public Mono<ServerResponse> batchData(ServerRequest request) {
        Mono<String> json = request.bodyToMono(String.class);
        return  ServerResponse.ok().body(json.map(this::jsonTransform).map(d -> processData.processRawEvent(d,true).block()),JSONObject.class);
    }

    private JSONObject jsonTransform(String d) {
        JSONObject jsonObject = new JSONObject(d);
        return jsonObject;
    }
}
