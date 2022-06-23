package com.phenom.lightsaber.handlers;

import com.phenom.lightsaber.dataprocessor.ProcessData;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Service
public class DataHandler {

    @Autowired
    ProcessData processData;


    public Mono<ServerResponse> data(ServerRequest request) {
        Mono<String> json = request.bodyToMono(String.class);
        return  ServerResponse.ok().body(
                (Object) json.map(this::jsonTransform).map(d -> Mono.just(processData.processRawEvent(d,false)).flatMap(dd -> dd))
                ,JSONObject.class
        );
    }

    private JSONObject jsonTransform(String d) {
        JSONObject jsonObject = new JSONObject(d);
        return jsonObject;
    }
}
