package dev.distracted.iam.activation.adapter.jdbc;

import dev.distracted.iam.activation.AppSubject;
import dev.distracted.iam.activation.AppSubjectRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcAppSubjectRepository implements AppSubjectRepository {
    private final JdbcTemplate jdbc;

    public JdbcAppSubjectRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override public Result resolve(String appId, String identityId, AppSubject candidate,
            String auditId, String correlationId) {
        try {
            return jdbc.queryForObject("select * from resolve_app_subject(?,?,?,?,?)", (row, number) -> {
                var outcome = Outcome.valueOf(row.getString("result"));
                var value = row.getString("app_subject");
                return new Result(outcome, value == null ? null : new AppSubject(value));
            }, appId, identityId, candidate.value(), auditId, correlationId);
        } catch (DataAccessException exception) {
            throw new IllegalStateException("app_subject_resolution_unavailable");
        }
    }
}
