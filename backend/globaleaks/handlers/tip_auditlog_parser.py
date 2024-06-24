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
        'content': log['content'],
        'author_id': log['user_id'],
        'visibility': 'public',
        'type': 'auditlog'
    }

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
def process_logs(session, tip ,tip_id):
    """
    Process a list of logs to append their details to a tip dictionary.
    """
    logs = get_audit_log(session,tip_id)
    for log in logs:
        status_details = log.get('data', {})

        if isinstance(status_details, dict):
            status = status_details.get('status', None)
            sub_status = status_details.get('substatus', None) 
    
            formatted_content = {
                "status": status,
                "substatus": sub_status
            }
    
            log['content'] = formatted_content
            tip['comments'].append(serialize_comment_log(log))

    return tip
