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
 * Jackson yapılandırması (Spring Boot 4 / Jackson 3 — {@code tools.jackson}).
 *
 * <p>{@link java.net.InetAddress} soyut bir tip olduğu için Jackson onu
 * doğrudan deserileştiremiyordu; {@code Device.ip} alanı rapor JSON'undan geri
 * okunurken "Cannot construct instance of java.net.InetAddress" hatası
 * veriyordu. Bu modül IP'leri düz metin (ör. {@code 192.168.1.10}) olarak
 * yazıp okur.
 */
@Configuration
public class JacksonConfig {

    /** IP adreslerini düz metin olarak (seri/deseri) işleyen modül. */
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
                            "Geçersiz IP adresi: %s", text);
                }
            }
        });

        return module;
    }

    /** Spring MVC'nin kullandığı ObjectMapper'a modülü ekler. */
    @Bean
    public JsonMapperBuilderCustomizer janusJacksonCustomizer() {
        return builder -> builder.addModule(inetAddressModule());
    }

    /** CLI raporlaması için hazır (girintili) mapper. */
    public static JsonMapper cliMapper() {
        return JsonMapper.builder()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .addModule(inetAddressModule())
                .build();
    }
}
