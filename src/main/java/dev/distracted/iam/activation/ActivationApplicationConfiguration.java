package dev.distracted.iam.activation;

import dev.distracted.iam.activation.adapter.jdbc.JdbcAppActivationRepository;
import dev.distracted.iam.messaging.OnboardingEventFactory;
import dev.distracted.iam.messaging.OnboardingIntentWriter;
import dev.distracted.iam.messaging.SecureOnboardingEventIdGenerator;
import dev.distracted.iam.platform.persistence.SpringTransactionRunner;
import java.security.SecureRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.activation.enabled", havingValue = "true")
@ConditionalOnProperty(name = "iam.app-subject.enabled", havingValue = "true")
public class ActivationApplicationConfiguration {
    @Bean AppActivationRepository appActivationRepository(JdbcTemplate jdbc) {
        return new JdbcAppActivationRepository(jdbc);
    }

    @Bean AppActivationService appActivationService(AppActivationRepository repository) {
        return new AppActivationService(repository,
                new SecureAppActivationMaterialGenerator(new SecureRandom()),
                new ActivationPrerequisiteEvaluator());
    }

    @Bean FirstActivationTransaction firstActivationTransaction(AppSubjectResolver subjects,
            AppActivationService activations, OnboardingIntentWriter onboardingIntentWriter,
            PlatformTransactionManager transactionManager, @Value("${iam.environment}") String environment) {
        return new FirstActivationTransaction(subjects, activations, new OnboardingEventFactory(),
                onboardingIntentWriter, new SecureOnboardingEventIdGenerator(new SecureRandom()),
                new SpringTransactionRunner(new TransactionTemplate(transactionManager)), environment);
    }
}
