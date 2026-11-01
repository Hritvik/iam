package dev.distracted.iam.activation;

import dev.distracted.iam.activation.adapter.jdbc.JdbcAppSubjectRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.app-subject.enabled", havingValue = "true")
public class AppSubjectApplicationConfiguration {
    @Bean AppSubjectRepository appSubjectRepository(JdbcTemplate jdbc) {
        return new JdbcAppSubjectRepository(jdbc);
    }

    @Bean AppSubjectMaterialGenerator appSubjectMaterialGenerator() {
        return new SecureAppSubjectMaterialGenerator();
    }

    @Bean AppSubjectResolver appSubjectResolver(AppSubjectRepository repository,
            AppSubjectMaterialGenerator generator) {
        return new AppSubjectResolver(repository, generator, 3);
    }
}
