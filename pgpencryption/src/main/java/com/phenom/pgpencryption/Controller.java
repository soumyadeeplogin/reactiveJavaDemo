package com.phenom.pgpencryption;


import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
@CrossOrigin(origins = "*")
public class Controller {


    @GetMapping(path = "/getPublicKey", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getPublicKey(){
        return ResponseEntity.ok().body("OK");
    }
}
