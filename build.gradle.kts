import groovy.json.JsonOutput
import java.security.MessageDigest
import org.gradle.api.tasks.bundling.Zip

plugins {
    java
    jacoco
    checkstyle
    id("org.springframework.boot") version "4.1.1"
}

group = "dev.distracted"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
    lockMode = LockMode.STRICT
}

val integrationTestSourceSet = sourceSets.create("integrationTest") {
    java.srcDir("src/integrationTest/java")
    resources.srcDir("src/integrationTest/resources")
    compileClasspath += sourceSets.main.get().output + configurations.testRuntimeClasspath.get()
    runtimeClasspath += output + compileClasspath
}

val contractTestSourceSet = sourceSets.create("contractTest") {
    java.srcDir("src/contractTest/java")
    resources.srcDir("src/contractTest/resources")
    compileClasspath += sourceSets.main.get().output + configurations.testRuntimeClasspath.get()
    runtimeClasspath += output + compileClasspath
}

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.1"))
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")
    implementation("io.github.erdtman:java-json-canonicalization:1.1")
    implementation("com.networknt:json-schema-validator:1.5.9")
    implementation("com.ibm.icu:icu4j:78.1")
    runtimeOnly("org.postgresql:postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.5.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    "integrationTestImplementation"(platform("org.testcontainers:testcontainers-bom:2.0.5"))
    add("integrationTestImplementation", "org.springframework.boot:spring-boot-starter-test")
    add("integrationTestImplementation", "org.springframework.boot:spring-boot-testcontainers")
    add("integrationTestImplementation", "org.testcontainers:testcontainers-junit-jupiter")
    add("integrationTestImplementation", "org.testcontainers:testcontainers-postgresql")
    add("integrationTestRuntimeOnly", "org.junit.platform:junit-platform-launcher")

    add("contractTestImplementation", "org.junit.jupiter:junit-jupiter:6.0.3")
    add("contractTestImplementation", "com.networknt:json-schema-validator:1.5.9")
    add("contractTestImplementation", "io.swagger.parser.v3:swagger-parser:2.1.39")
    add("contractTestRuntimeOnly", "org.junit.platform:junit-platform-launcher")
}

configurations.named("integrationTestImplementation") {
    extendsFrom(configurations.testImplementation.get())
}
configurations.named("integrationTestRuntimeOnly") {
    extendsFrom(configurations.testRuntimeOnly.get())
}
configurations.named("contractTestImplementation") {
    extendsFrom(configurations.testImplementation.get())
}
configurations.named("contractTestRuntimeOnly") {
    extendsFrom(configurations.testRuntimeOnly.get())
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.processResources {
    from(layout.projectDirectory.dir("contracts")) {
        into("canonical-contracts")
    }
}

val integrationTest = tasks.register<Test>("integrationTest") {
    description = "Runs PostgreSQL integration tests."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    testClassesDirs = integrationTestSourceSet.output.classesDirs
    classpath = integrationTestSourceSet.runtimeClasspath
    shouldRunAfter(tasks.test)
    doFirst {
        if (System.getenv("DOCKER_HOST").isNullOrBlank()) {
            val activeDockerHost = providers.exec {
                commandLine("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
            }.standardOutput.asText.get().trim()
            environment("DOCKER_HOST", activeDockerHost)
            if (activeDockerHost.startsWith("unix://") && activeDockerHost != "unix:///var/run/docker.sock") {
                environment("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "/var/run/docker.sock")
            }
        }
    }
}

val contractTest = tasks.register<Test>("contractTest") {
    description = "Validates language-neutral IAM contracts and fixtures."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    testClassesDirs = contractTestSourceSet.output.classesDirs
    classpath = contractTestSourceSet.runtimeClasspath
    inputs.dir(layout.projectDirectory.dir("contracts"))
    systemProperty("contracts.dir", layout.projectDirectory.dir("contracts").asFile.absolutePath)
    shouldRunAfter(tasks.test)
}

val contractVersion = file("contracts/catalog.yaml").useLines { lines ->
    lines.first { it.startsWith("version: ") }.removePrefix("version: ").trim()
}.also { parsed ->
    check(Regex("^[0-9]+\\.[0-9]+\\.[0-9]+$").matches(parsed)) { "catalog version must be semantic" }
}
val contractArchive = tasks.register<Zip>("contractArchive") {
    description = "Builds the immutable language-neutral IAM contract bundle."
    group = "distribution"
    dependsOn(contractTest)
    from(layout.projectDirectory.dir("contracts")) {
        into("iam-contracts-$contractVersion")
    }
    archiveFileName = "iam-contracts-$contractVersion.zip"
    destinationDirectory = layout.buildDirectory.dir("distributions")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    includeEmptyDirs = false
}

val contractChecksum = tasks.register("contractChecksum") {
    description = "Writes the SHA-256 digest for the immutable IAM contract bundle."
    group = "distribution"
    dependsOn(contractArchive)
    val archive = contractArchive.flatMap { it.archiveFile }
    val checksum = layout.buildDirectory.file("distributions/iam-contracts-$contractVersion.sha256")
    inputs.file(archive)
    outputs.file(checksum)
    doLast {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(archive.get().asFile.readBytes())
            .joinToString("") { byte -> "%02x".format(byte) }
        checksum.get().asFile.writeText("$digest  ${archive.get().asFile.name}\n")
    }
}

tasks.register("contractBundle") {
    description = "Validates and publishes the local IAM contract ZIP and SHA-256 digest."
    group = "distribution"
    dependsOn(contractChecksum)
}

jacoco {
    toolVersion = "0.8.15"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test, integrationTest)
    executionData(tasks.test.get(), integrationTest.get())
    reports {
        xml.required = true
        html.required = true
    }
}

tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test, integrationTest)
    executionData(tasks.test.get(), integrationTest.get())
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.80".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}

checkstyle {
    toolVersion = "14.3.0"
    maxWarnings = 0
}

val dependencyPolicyCheck = tasks.register("dependencyPolicyCheck") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Rejects dynamic and snapshot production dependencies."
    doLast {
        val forbidden = configurations.getByName("runtimeClasspath").allDependencies.filter {
            val candidate = it.version.orEmpty()
            candidate.contains("+") || candidate.equals("latest.release", ignoreCase = true) ||
                candidate.endsWith("-SNAPSHOT", ignoreCase = true)
        }
        check(forbidden.isEmpty()) { "Unpinned production dependencies: ${forbidden.joinToString()}" }
    }
}

val applicationComponentName = project.name
val applicationComponentVersion = project.version.toString()

val generateSbom = tasks.register("generateSbom") {
    group = "reporting"
    description = "Writes a deterministic CycloneDX-compatible component inventory."
    val outputFile = layout.buildDirectory.file("reports/sbom/iam.cdx.json")
    outputs.file(outputFile)
    doLast {
        val components = configurations.getByName("runtimeClasspath").resolvedConfiguration
            .resolvedArtifacts
            .map { artifact ->
                mapOf(
                    "type" to "library",
                    "group" to artifact.moduleVersion.id.group,
                    "name" to artifact.name,
                    "version" to artifact.moduleVersion.id.version,
                    "purl" to "pkg:maven/${artifact.moduleVersion.id.group}/${artifact.name}@${artifact.moduleVersion.id.version}"
                )
            }
            .distinctBy { it["purl"] }
            .sortedBy { it["purl"] }
        val document = linkedMapOf(
            "bomFormat" to "CycloneDX",
            "specVersion" to "1.6",
            "version" to 1,
            "metadata" to mapOf("component" to mapOf(
                "type" to "application",
                "name" to applicationComponentName,
                "version" to applicationComponentVersion
            )),
            "components" to components
        )
        outputFile.get().asFile.apply {
            parentFile.mkdirs()
            writeText(JsonOutput.prettyPrint(JsonOutput.toJson(document)) + "\n")
        }
    }
}

val secretScan = tasks.register("secretScan") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Rejects common committed secret assignments in owned source and configuration files."
    val candidates = fileTree(projectDir) {
        include(
            "**/*.java", "**/*.kt", "**/*.kts", "**/*.properties", "**/*.yaml", "**/*.yml",
            "**/*.toml", "**/*.json", "**/*.xml", "**/*.sql", "**/*.sh", "**/*.bat", "**/*.md",
            "**/*.conf", "**/*.env", "**/.env.*", "**/*.lockfile", "**/*.pem", "**/*.key",
            "**/Dockerfile", "**/Dockerfile.*", "gradlew"
        )
        exclude(".gradle/**", "build/**", ".git/**")
    }
    inputs.files(candidates)
    doLast {
        val patterns = linkedMapOf(
            "pem-private-key" to Regex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "jwt" to Regex("eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}"),
            "bearer" to Regex("(?i)\\bBearer\\s+[A-Za-z0-9._~+/=-]{20,}"),
            "secret-assignment" to Regex(
                "(?i)\\b(?:password|passwd|secret|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)"
                    + "\\s*[:=]\\s*(?!\\$\\{)(?!env\\()(?!(?:redacted|example|placeholder)\\b)[\\\"']?[^\\s\\\"']{8,}"
            )
        )
        val canaries = mapOf(
            "pem-private-key" to "-----" + "BEGIN PRIVATE KEY-----",
            "jwt" to listOf(
                "eyJhbGciOiJFUzI1NiJ9",
                "eyJzdWIiOiJjYW5hcnkifQ",
                "signature_canary"
            ).joinToString("."),
            "bearer" to "Bearer " + "abcdefghijklmnopqrstuvwxyz012345",
            "secret-assignment" to "client_" + "secret=" + "unquoted-canary-value"
        )
        patterns.forEach { (name, pattern) ->
            check(pattern.containsMatchIn(canaries.getValue(name))) {
                "Secret scanner self-test failed for $name"
            }
        }
        val findings = candidates.files.flatMap { file ->
            file.readLines().flatMapIndexed { index, line ->
                patterns.mapNotNull { (name, pattern) ->
                    if (pattern.containsMatchIn(line)) {
                        "${file.relativeTo(projectDir)}:${index + 1}:$name"
                    } else {
                        null
                    }
                }
            }
        }
        check(findings.isEmpty()) { "Potential hardcoded secrets: ${findings.joinToString()}" }
    }
}

tasks.check {
    dependsOn(contractTest)
    dependsOn(integrationTest)
    dependsOn(tasks.jacocoTestCoverageVerification)
    dependsOn(dependencyPolicyCheck)
    dependsOn(generateSbom)
    dependsOn(secretScan)
}

