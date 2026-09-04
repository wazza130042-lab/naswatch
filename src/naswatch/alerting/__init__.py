"""Alerting package for NASWatch."""

from naswatch.alerting.notifier import (
    AlertNotifier,
    AlertSink,
    ConsoleAlertSink,
    FileAlertSink,
    InMemoryAlertSink,
    SQLiteAlertSink,
    SyslogAlertSink,
    WebhookAlertSink,
)

__all__ = [
    "AlertNotifier",
    "AlertSink",
    "ConsoleAlertSink",
    "FileAlertSink",
    "InMemoryAlertSink",
    "SQLiteAlertSink",
    "SyslogAlertSink",
    "WebhookAlertSink",
]
