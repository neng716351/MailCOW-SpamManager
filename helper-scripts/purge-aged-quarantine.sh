#!/bin/bash
# Local addition 2026-11-13.
#
# mailcow ships /usr/local/bin/clean_q_aged.sh inside the dovecot container to delete
# quarantine copies older than Q_MAX_AGE, but this deployment's dovecot container runs
# supervisord WITHOUT cron, so that script was never executed. Harmless while only
# acted-on mail was kept; not harmless now that every inbound message is copied.
#
# Run daily from the host crontab. Safe to run repeatedly; it only deletes rows from the
# `quarantine` table, never anything in a user's mailbox.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
exec docker compose exec -T dovecot-mailcow /usr/local/bin/clean_q_aged.sh
