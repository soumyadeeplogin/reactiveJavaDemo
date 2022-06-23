package com.phenom.lightsaber.handlers;

import org.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class StatusHandler {

    public Mono<ServerResponse> status(ServerRequest request) {
        JSONObject statusMessage = new JSONObject();
        statusMessage.put("status", "Ok").put("message", "I am healthy !");
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(statusMessage.toString()));
    }

}
