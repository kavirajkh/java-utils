package com.kaviraj.application.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@ComponentScan(basePackages = {"com.kaviraj.application"})
@PropertySource("classpath:crypto.properties")
public class AppConfiguration {
}
