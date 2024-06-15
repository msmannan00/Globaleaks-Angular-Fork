# -*- coding: utf-8 -*-

from globaleaks.orm import transact
from globaleaks import models

def serialize_auditlog(log):
    return {
        'date': log.date,
        'type': log.type,
        'user_id': log.user_id,
        'object_id': log.object_id,
        'data': log.data
    }

def serialize_comment_log(log):
    """
    Serialize an audit log entry for external use.
    """
    return {
        'id': log['object_id'],
        'creation_date': log['date'],
        'content': log.get('content', 'Status changed'),
        'author_id': log['user_id'],
        'visibility': 'public'
    }

def get_label(session, label_id, table):
    """
    Fetch the label for a given UUID from the specified table.
    """
    result = session.query(table).filter_by(id=label_id).first()
    return result.label['en'] if result else f"Unknown {table.__tablename__}"

@transact
def get_audit_log(session, object_id):
    """
    Fetch audit logs for a given object_id where the type is 'update_report_status'.
    """
    logs = session.query(models.AuditLog).filter(
        models.AuditLog.object_id == object_id,
        models.AuditLog.type == 'update_report_status'
    )
    return [serialize_auditlog(log) for log in logs]

@transact
def process_logs(session, logs, tip):
    """
    Process a list of logs to append their details to a tip dictionary.
    """
    for log in logs:
        status_change_string = "Status changed"
        status_details = log.get('data', {})

        if isinstance(status_details, dict):
            status = status_details.get('status')
            sub_status = status_details.get('substatus')

            if status:
                status_label = get_label(session, status, models.SubmissionStatus)
                status_change_string = f"Status changed to {status_label}"

                if sub_status:
                    sub_status_label = get_label(session, sub_status, models.SubmissionSubStatus)
                    status_change_string += f" - {sub_status_label}"

        log['content'] = status_change_string
        tip['comments'].append(serialize_comment_log(log))

    return tip
