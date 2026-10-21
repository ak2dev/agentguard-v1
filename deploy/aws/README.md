# Agent Guard Web on AWS (one EC2 instance)

The site stays on Vercel. This folder runs the server half of Agent Guard Web (`web/`) on one
**t4g.small** instance (2 vCPU, 2 GB, Graviton) in the project's Region, **ap-southeast-2**:
Caddy (TLS) → API → Redis queue → dispatcher → one gVisor scanner container per job, with
reports in Postgres. Vercel sends `/api/*` to it with a rewrite, so the site's CSP stays
`connect-src 'self'`.

| File | Runs where | What it does |
|---|---|---|
| `launch.ps1` | your PC | IAM role + instance profile (Session Manager only), security group (80/443), instance, Elastic IP |
| `bootstrap.sh` | instance, first boot (user data) | Docker, Compose plugin and gVisor (checksum-verified), 2 GB swap, clones this repository |
| `deploy.sh` | instance, via Session Manager | generates `.env` secrets on the instance, builds both images, requires `check-sandbox` to print `NO-EGRESS`, starts the stack, daily prune timer |
| `compose.prod.yaml`, `Caddyfile` | instance | the stack; only Caddy is published, the API/Postgres/Redis have no egress |

## Before you start

- **Plan and cost.** The project is on the free plan ($120 credits, until 18 Apr 2027), and
  t4g.small is free-tier eligible. Roughly $20/month all-in (instance, 20 GB gp3, Elastic IP)
  at Sydney prices; check the AWS Pricing Calculator. Remaining credits:
  `aws freetier get-account-plan-state --profile agentguard`. When the free plan ends the
  instance stops unless you upgrade in AWS Settings.
- **This folder must be on `main`** on GitHub: `bootstrap.sh` clones `main` (change
  `REPO_REF` to test a branch).
- **Signed in:** `aws login --profile agentguard --region ap-southeast-2` (credentials last
  12 hours and renew for up to 90 days).

## Launch

1. From the repository root on your PC:
   ```powershell
   powershell -ExecutionPolicy Bypass -File deploy\aws\launch.ps1
   ```
   It prints the instance ID, the Elastic IP and a default domain `<ip-with-dashes>.sslip.io`.
2. Wait about 5 minutes for `bootstrap.sh`, then open the Session Manager link it printed
   (EC2 console → instance → **Connect** → **Session Manager**). No SSH key or open port 22.
3. On the instance:
   ```bash
   sudo cat /var/log/agentguard-bootstrap.log | tail -5    # "bootstrap done"
   sudo bash /opt/agentguard/deploy/aws/deploy.sh               # or: deploy.sh api.example.com
   ```
   With your own domain, point an `A` record at the Elastic IP first. `deploy.sh` ends by
   printing the URL that answers `/api/health` and the Vercel rewrite destination.
4. Connect the site: add this rewrite to `vercel.json` **before** the catch-all to `site`,
   then deploy the site:
   ```json
   { "source": "/api/:path*", "destination": "https://<domain>/api/:path*" },
   ```
   Until then the site keeps working: GitHub links fall back to the in-browser scanner.

## Operate

| Task | On the instance |
|---|---|
| Update to the latest `main` | `sudo bash /opt/agentguard/deploy/aws/deploy.sh` |
| Logs | `sudo docker compose -f /opt/agentguard/deploy/aws/compose.prod.yaml logs -f api dispatcher` |
| Re-check isolation | `sudo docker compose -f /opt/agentguard/deploy/aws/compose.prod.yaml run --rm -T --no-deps dispatcher check-sandbox` |

**Saving credits:** stop the instance between demos (EC2 console → Instance state → Stop).
Services restart by themselves on start, and the Elastic IP keeps the same address. While
stopped you still pay for the disk and the idle Elastic IP (about $5/month together).

**Tear down** (from your PC, IDs from `launch.ps1`'s output): `aws ec2 terminate-instances
--instance-ids <i-...>`, then `aws ec2 release-address --allocation-id <eipalloc-...>`, then
delete the `agentguard-web` security group and the `agentguard-web-ec2` instance profile and
role. Terminating deletes the disk and all stored reports.

## Security notes

- **Docker socket.** The dispatcher controls the host's Docker daemon (as a member of the
  `docker` group, not root) to start scanner containers, so the instance runs nothing else.
- **gVisor** comes from Google's `latest` release channel, verified against its published
  SHA-512 but not pinned to a version; the Compose plugin is pinned (`v5.6.0`).
- **Client addresses.** Caddy keeps `X-Forwarded-For` from any sender so the per-visitor rate
  limit works behind Vercel. Someone calling the instance directly can forge it to dodge that
  limit; proof-of-work on every scan and the queue cap (50) still apply.
- **Instance metadata** requires IMDSv2 with a hop limit of 1, so no container can reach
  instance credentials (none of them needs any). The instance role only allows Session
  Manager.
- **Secrets** (`AGW_SECRET`, the Postgres password) are generated on the instance into
  `deploy/aws/.env` (mode 600) and are never in user data, the repository or your PC.
