package com.g120s.janus.configuration;

import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;

import java.net.InetAddress;

/**
 * Jackson configuration (Spring Boot 4 / Jackson 3 — {@code tools.jackson}).
 *
 * <p>Because {@link java.net.InetAddress} is an abstract type, Jackson could not
 * deserialize it directly; reading the {@code Device.ip} field back from the report
 * JSON produced a "Cannot construct instance of java.net.InetAddress" error.
 * This module writes and reads IPs as plain text (e.g. {@code 192.168.1.10}).
 */
@Configuration
public class JacksonConfig {

    /** Module that (de)serializes IP addresses as plain text. */
    public static SimpleModule inetAddressModule() {
        SimpleModule module = new SimpleModule("janus-inet");

        module.addSerializer(InetAddress.class, new StdSerializer<>(InetAddress.class) {
            @Override
            public void serialize(InetAddress value, JsonGenerator gen, SerializationContext ctxt) {
                gen.writeString(value.getHostAddress());
            }
        });

        module.addDeserializer(InetAddress.class, new StdDeserializer<>(InetAddress.class) {
            @Override
            public InetAddress deserialize(JsonParser p, DeserializationContext ctxt) {
                String text = p.getValueAsString();
                if (text == null || text.isBlank()) return null;
                try {
                    return InetAddress.getByName(text.trim());
                } catch (Exception e) {
                    return (InetAddress) ctxt.handleWeirdStringValue(InetAddress.class, text,
                            "Invalid IP address: %s", text);
                }
            }
        });

        return module;
    }

    /** Adds the module to the ObjectMapper used by Spring MVC. */
    @Bean
    public JsonMapperBuilderCustomizer janusJacksonCustomizer() {
        return builder -> builder.addModule(inetAddressModule());
    }

    /** Ready-made (indented) mapper for CLI reporting. */
    public static JsonMapper cliMapper() {
        return JsonMapper.builder()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .addModule(inetAddressModule())
                .build();
    }
}
