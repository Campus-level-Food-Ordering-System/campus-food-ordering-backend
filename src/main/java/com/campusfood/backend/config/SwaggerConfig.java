package com.campusfood.backend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI campusFoodAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Campus Food Ordering System API")
                        .description("API documentation for Campus-level Food Ordering System")
                        .version("1.0"));
    }
}
