import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.ServletException;

/**
 * InflightValve -- real application-layer "is the backend still doing work"
 * counter for the HTTP/2 stream-reset DoS lab's mismatch_ratio signal.
 *
 * Increments on every request entering invoke() and decrements ONLY when that
 * call truly returns, i.e. after getNext().invoke() -- which runs the rest of
 * the pipeline down to the servlet and back -- completes. This has no idea
 * the HTTP/2 layer may have reset the stream out from under it; it only knows
 * whether the backend thread processing that request is still running. That
 * is the whole point: MadeYouReset makes the HTTP/2 connector drop a stream
 * from its own bookkeeping while this counter -- tracking real work, not
 * protocol state -- stays elevated, which is exactly the divergence
 * mismatch_ratio(t) is built to catch.
 *
 * Deliberately NOT a JMX MBean: Tomcat 10.1.43 doesn't expose anything
 * equivalent to this over JMX on its own (verified directly against the
 * running JVM -- only connector-level GlobalRequestProcessor stats and
 * per-worker-thread RequestProcessor state exist, neither of which is a
 * request-level inflight count). Serving a tiny plaintext metric on a
 * reserved path keeps this consistent with how every other service in this
 * lab exposes metrics (a small stdlib-style /metrics-style endpoint), and
 * needs no JMX remote connector, no extra port, and no extra library.
 *
 * The metrics path itself is handled directly here and never passed down the
 * pipeline, so polling it never touches the webapp and is never counted.
 */
public class InflightValve extends ValveBase {

    private static final AtomicInteger inflight = new AtomicInteger(0);
    private static final String METRICS_PATH = "/__inflight_metrics";

    public InflightValve() {
        super(true); // asyncSupported=true at the Valve level; the webapp itself is synchronous
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        if (METRICS_PATH.equals(request.getRequestURI())) {
            serveMetrics(response);
            return;
        }
        inflight.incrementAndGet();
        try {
            getNext().invoke(request, response);
        } finally {
            inflight.decrementAndGet();
        }
    }

    private void serveMetrics(Response response) throws IOException {
        String body = "# TYPE victim_inflight_requests_valve gauge\n"
                + "victim_inflight_requests_valve " + inflight.get() + "\n";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        response.setStatus(200);
        response.setContentType("text/plain; charset=utf-8");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
        response.getOutputStream().flush();
        response.finishResponse();
    }
}
