package dev.distracted.iam.registration;

import org.springframework.jdbc.core.JdbcTemplate;

public final class RegistrationReconcilerConnection {
    private final JdbcTemplate jdbc;

    public RegistrationReconcilerConnection(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    JdbcTemplate jdbc() { return jdbc; }

    void verifyAuthority() {
        var valid = jdbc.queryForObject("select pg_has_role(current_user,'iam_registration_reconciler','member') "
                + "and not pg_has_role(current_user,'iam_runtime','member')", Boolean.class);
        if (!Boolean.TRUE.equals(valid)) throw new RegistrationException("registration_reconciler_authority_invalid");
    }
}
