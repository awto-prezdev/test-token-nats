package com.example.test_token_nats;

import io.nats.client.Connection;
import io.nats.client.ConnectionListener;
import io.nats.client.Nats;
import io.nats.client.Options;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TestTokenNats {

    @PostConstruct
    public void init() {
        String token = "my-token";
        String subject = "test.token";
        String message = "Test Message";
        String serverURL = "nats://localhost:4222";

        Options options = new Options.Builder().
                server(serverURL).
                token(token.toCharArray()).
                connectionListener((conn, type) -> {
                    if (type == ConnectionListener.Events.CONNECTED) {
                        log.info("[TEST-TOKEN-NATS] Connected to NATS");
                    }
                }).
                build();

        try (Connection nc = Nats.connect(options)) {
            nc.publish(subject, message.getBytes());
            log.info("[TEST-TOKEN-NATS] Message publish at {}", subject);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
