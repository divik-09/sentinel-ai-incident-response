# Local service simulator

Sentinel includes five in-process HTTP service simulators (development/demo only: they require the `operator` role and are **disabled when `SENTINEL_ENABLE_DEMO` is false**, which is the default in staging/production). The order handler demonstrates a connected request path: order creation checks inventory, then authorizes payment. The other handlers model catalog and auth behavior. This keeps the demo easy to run without Kubernetes, cloud credentials, or multiple containers.

These are intentionally small service stubs, not independently deployed microservices. A scenario selected through `POST /api/incidents` also activates the matching service fault in the simulator. The telemetry fixtures are separately inserted into SQLite for reproducible diagnosis and evaluation.

## Endpoints

| Endpoint | Normal behavior | Injected behavior |
|---|---|---|
| `POST /demo/orders` | Checks inventory, authorizes payment, creates an order | Returns the dependency failure or schema error active in the relevant service |
| `GET /demo/inventory/stock/{sku}` | Returns available stock | Returns supplier timeout (`504`) with simulated latency metadata |
| `POST /demo/payments/authorize` | Returns an authorization ID | Returns database pool timeout (`503`) |
| `GET /demo/catalog/products` | Returns demo product data | Returns degraded cache metrics and simulated latency metadata |
| `POST /demo/auth/token` | Issues a demo token | Returns worker OOM error (`503`) |

## Try it

Start Sentinel, then trigger a scenario:

```bash
# If authentication is enabled add:  -H 'Authorization: Bearer <operator-or-approver-key>'
curl -X POST http://127.0.0.1:8000/api/incidents \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id":"payment-pool-exhaustion"}'
```

The response includes an incident ID. Now probe the connected order/payment flow:

```bash
curl -i -X POST http://127.0.0.1:8000/demo/orders \
  -H 'Content-Type: application/json' \
  -d '{"sku":"DEMO-001","quantity":1,"amount":999}'
```

The order handler will propagate the payment service's simulated failure. To inspect fault states:

```bash
curl http://127.0.0.1:8000/api/demo/services
```

Reset all service faults:

```bash
curl -X POST http://127.0.0.1:8000/api/demo/reset
```

The dashboard also provides a **Reset service faults** control.

## Scope and production boundary

The simulator returns deterministic response payloads and simulated latency metadata; it does not sleep for multiple seconds or call real databases, suppliers, caches, identity providers, or payment gateways. Do not enable the demo endpoints on an internet-facing instance.
