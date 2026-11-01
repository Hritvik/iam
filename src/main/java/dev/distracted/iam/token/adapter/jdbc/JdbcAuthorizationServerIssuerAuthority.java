package dev.distracted.iam.token.adapter.jdbc;

import dev.distracted.iam.token.AuthorizationServerIssuerAuthority;
import dev.distracted.iam.token.HumanAccessTokenIssueException;
import java.util.Objects;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcAuthorizationServerIssuerAuthority implements AuthorizationServerIssuerAuthority {
    private final JdbcTemplate jdbc;

    public JdbcAuthorizationServerIssuerAuthority(JdbcTemplate jdbc) {
        this.jdbc = Objects.requireNonNull(jdbc);
    }

    @Override public String pinnedIssuer() {
        try {
            var values = jdbc.query("select public.read_authorization_server_issuer()",
                    (resultSet, rowNumber) -> resultSet.getString(1));
            if (values.size() != 1 || values.getFirst() == null) {
                throw new HumanAccessTokenIssueException("invalid_context");
            }
            return values.getFirst();
        } catch (HumanAccessTokenIssueException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new HumanAccessTokenIssueException("invalid_context");
        }
    }
}
