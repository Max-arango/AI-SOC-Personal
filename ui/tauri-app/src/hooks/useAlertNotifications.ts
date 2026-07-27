import { useEffect, useRef } from 'react';
import * as api from '../utils/tauriApi';

interface UseAlertNotificationsOptions {
  pollIntervalMs?: number;
  enabled?: boolean;
}

export function useAlertNotifications({
  pollIntervalMs = 10000,
  enabled = true,
}: UseAlertNotificationsOptions = {}) {
  const lastAlertId = useRef<string | null>(null);
  const notifiedIds = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!enabled) return;

    const checkNewAlerts = async () => {
      try {
        const result = await api.getAlerts({ limit: 5 });
        const newAlerts = result.alerts.filter(
          (a) => !notifiedIds.current.has(a.id),
        );

        for (const alert of newAlerts) {
          const severity = typeof alert.severity === 'string'
            ? alert.severity
            : `Level ${alert.severity}`;
          const title = `[${severity.toUpperCase()}] Sentinel AI Alert`;
          const body = `${alert.rule_id.replace(/_/g, ' ')} — Risk: ${alert.risk_score}`;

          await api.showNotification(title, body);
          notifiedIds.current.add(alert.id);
          lastAlertId.current = alert.id;
        }

        if (notifiedIds.current.size > 100) {
          notifiedIds.current.clear();
        }
      } catch {
        // silent — notifications are best-effort
      }
    };

    checkNewAlerts();
    const interval = setInterval(checkNewAlerts, pollIntervalMs);
    return () => clearInterval(interval);
  }, [pollIntervalMs, enabled]);
}
