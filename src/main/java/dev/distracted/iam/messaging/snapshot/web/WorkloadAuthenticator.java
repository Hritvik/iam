package dev.distracted.iam.messaging.snapshot.web;

import java.util.Optional;

public interface WorkloadAuthenticator {
    Optional<WorkloadPrincipal> authenticate(Object request);
}
