package com.phenom.lightsaber.routers;

import com.phenom.lightsaber.handlers.BatchDataHandler;
import com.phenom.lightsaber.handlers.DataHandler;
import com.phenom.lightsaber.handlers.StatusHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.*;

@Configuration
public class Router {

    @Bean
    public RouterFunction<ServerResponse> routes(DataHandler dataHandler, BatchDataHandler batchDataHandler, StatusHandler statusHandler) {

        return RouterFunctions
                .route(POST("/data").and(accept(MediaType.APPLICATION_JSON)), dataHandler::data)
                .andRoute(POST("/batch-data").and(accept(MediaType.APPLICATION_JSON)), batchDataHandler::batchData)
                .andRoute(GET("/status").and(accept(MediaType.APPLICATION_JSON)), statusHandler::status);
    }
}
