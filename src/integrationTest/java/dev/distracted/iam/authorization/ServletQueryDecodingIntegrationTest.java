package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import org.apache.catalina.startup.Tomcat;
import org.junit.jupiter.api.Test;

class ServletQueryDecodingIntegrationTest {
    @Test
    void tomcatDecodesAQueryParameterExactlyOnce() throws Exception {
        var tomcat = new Tomcat();
        tomcat.setBaseDir(Files.createTempDirectory("iam-query-decoding-").toString());
        tomcat.setPort(0);
        var context = tomcat.addContext("", null);
        Tomcat.addServlet(context, "echo", new HttpServlet() {
            @Override protected void doGet(HttpServletRequest request, HttpServletResponse response)
                    throws java.io.IOException {
                response.setContentType("text/plain");
                response.getWriter().write(request.getParameter("redirect_uri"));
            }
        });
        context.addServletMappingDecoded("/decode", "echo");
        try {
            tomcat.getConnector();
            tomcat.start();
            var port = tomcat.getConnector().getLocalPort();
            assertThat(get(port, "dutch%3A%2F%2Foauth%2Fcallback")).isEqualTo("dutch://oauth/callback");
            assertThat(get(port, "dutch%253A%252F%252Foauth%252Fcallback"))
                    .isEqualTo("dutch%3A%2F%2Foauth%2Fcallback");
        } finally {
            tomcat.stop();
            tomcat.destroy();
        }
    }

    private static String get(int port, String rawRedirect) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port
                + "/decode?redirect_uri=" + rawRedirect)).GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
