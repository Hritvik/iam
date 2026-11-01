package dev.distracted.iam.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.RestController;

class ModuleBoundaryTest {
    @Test
    void modulesDoNotReachIntoAnotherModulesPersistencePackage() {
        var classes = new ClassFileImporter().importPackages("dev.distracted.iam");

        for (var module : List.of("identity", "registration", "authorization", "activation", "token", "messaging")) {
            noClasses()
                    .that().resideOutsideOfPackage("dev.distracted.iam." + module + "..")
                    .should().dependOnClassesThat()
                    .resideInAnyPackage(
                            "dev.distracted.iam." + module + ".persistence..",
                            "dev.distracted.iam." + module + ".adapter.jdbc..")
                    .allowEmptyShould(true)
                    .check(classes);
        }
    }

    @Test
    void accessTokenCapabilityHasNoLoggingMetricsTracingPersistenceOrMessagingSurface() {
        var classes = new ClassFileImporter().importPackages("dev.distracted.iam");

        noClasses().that().resideInAPackage("..token..").and().resideOutsideOfPackage("..token.adapter.jdbc..")
                .and().haveSimpleNameNotEndingWith("Test")
                .should().dependOnClassesThat().resideInAnyPackage(
                        "org.slf4j..", "io.micrometer..", "io.opentelemetry..", "java.sql..", "javax.sql..",
                        "org.springframework.jdbc..", "..platform.persistence..", "..messaging..")
                .allowEmptyShould(false).check(classes);
    }

    @Test
    void webAndProtocolAdaptersCannotUseJdbcDirectly() {
        var classes = new ClassFileImporter().importPackages("dev.distracted.iam");

        noClasses()
                .that().resideInAnyPackage("..web..", "..protocol..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.sql..", "javax.sql..", "org.springframework.jdbc..")
                .allowEmptyShould(true)
                .check(classes);

        noClasses()
                .that().resideInAnyPackage("..web..", "..protocol..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("..persistence..", "..adapter.jdbc..")
                .allowEmptyShould(true)
                .check(classes);
    }

    @Test
    void platformRestControllersMustOptIntoSafePlatformErrorHandling() {
        var classes = new ClassFileImporter().importPackages("dev.distracted.iam");

        com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes()
                .that().areAnnotatedWith(RestController.class)
                .should().beAnnotatedWith(dev.distracted.iam.platform.http.PlatformEndpoint.class)
                .allowEmptyShould(true)
                .check(classes);

        noClasses()
                .that().resideInAnyPackage("..web..", "..protocol..", "..authorization..", "..activation..")
                .should().dependOnClassesThat().resideInAPackage("..registration.adapter.jdbc..")
                .allowEmptyShould(true)
                .check(classes);
    }

    @Test
    void fixtureCodeUsesIdentityPortsAndNeverPersistenceOrProtocolAdapters() {
        var classes = new ClassFileImporter().importPackages("dev.distracted.iam");

        noClasses()
                .that().resideInAPackage("..identity.fixture..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.sql..", "javax.sql..", "org.springframework.jdbc..",
                        "..platform.persistence..", "..identity.persistence..", "..identity.adapter.jdbc..",
                        "..authorization..", "..activation..")
                .allowEmptyShould(false)
                .check(classes);
    }

    @Test
    void appSubjectCapabilityHasNoLoggingMetricsTracingHttpTokenOrOutboxSurface() {
        var classes = new ClassFileImporter().importPackages("dev.distracted.iam");

        noClasses().that().resideInAPackage("..activation..")
                .should().dependOnClassesThat().resideInAnyPackage(
                        "org.slf4j..", "io.micrometer..", "io.opentelemetry..", "..web..",
                        "..authorization..")
                .allowEmptyShould(false).check(classes);
    }
}

