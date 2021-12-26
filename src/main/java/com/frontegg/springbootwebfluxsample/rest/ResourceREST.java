package com.frontegg.springbootwebfluxsample.rest;

import com.frontegg.springbootwebfluxsample.model.Message;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class ResourceREST {

    @GetMapping("/resource/with_authorization")
    public Mono<ResponseEntity<Message>> withAuthorization(@RequestHeader("Authorization") String header) {
        return Mono.just(ResponseEntity.ok(new Message("Content with authorization")));
    }

    @GetMapping("/resource/with_roles")
    @PreAuthorize("@fronteggSecurityMethod.isAuthorizedWithRoles(#header, {'Admin'})")
    public Mono<ResponseEntity<Message>> withRoles(@RequestHeader("Authorization") String header) {
        return Mono.just(ResponseEntity.ok(new Message("Content with roles")));
    }

    @GetMapping("/resource/with_permissions")
    @PreAuthorize("@fronteggSecurityMethod.isAuthorizedWithPermissions(#header, {'read-slack', 'read-webhooks'})")
    public Mono<ResponseEntity<Message>> withPermissions(@RequestHeader("Authorization") String header) {
        return Mono.just(ResponseEntity.ok(new Message("Content with permissions")));
    }
}
