# -*- coding: utf-8 -*-
#
# Handlers dealing with tip interface for whistleblowers (wbtip)
import base64
import json
import os
from twisted.internet.threads import deferToThread
from twisted.internet.defer import inlineCallbacks, returnValue

from globaleaks import models
from globaleaks.handlers.admin.node import db_admin_serialize_node
from globaleaks.handlers.admin.notification import db_get_notification
from globaleaks.handlers.base import BaseHandler
from globaleaks.handlers.whistleblower.submission import decrypt_tip, \
    db_set_internaltip_answers, db_get_questionnaire, \
    db_archive_questionnaire_schema, db_set_internaltip_data
from globaleaks.handlers.user import user_serialize_user
from globaleaks.models import serializers
from globaleaks.orm import db_get, transact
from globaleaks.rest import errors, requests
from globaleaks.state import State
from globaleaks.utils.crypto import Base64Encoder, GCE
from globaleaks.utils.fs import directory_traversal_check
from globaleaks.utils.log import log
from globaleaks.utils.templating import Templating
from globaleaks.utils.utility import datetime_now, datetime_null


def db_notify_report_update(session, user, rtip, itip):
    """
    :param session: An ORM session
    :param user: An user ORM object
    :param rtip: A rtip ORM object
    :param itip: A itip ORM object
    """
    data = {
      'type': 'tip_update',
      'user': user_serialize_user(session, user, user.language),
      'node': db_admin_serialize_node(session, user.tid, user.language),
      'tip': serializers.serialize_rtip(session, itip, rtip, user.language),
    }

    if data['node']['mode'] == 'default':
        data['notification'] = db_get_notification(session, user.tid, user.language)
    else:
        data['notification'] = db_get_notification(session, 1, user.language)

    subject, body = Templating().get_mail_subject_and_body(data)

    session.add(models.Mail({
        'address': data['user']['mail_address'],
        'subject': subject,
        'body': body,
        'tid': user.tid
    }))

def db_notify_recipients_of_tip_update(session, itip_id):
    for user, rtip, itip in session.query(models.User, models.ReceiverTip, models.InternalTip) \
                                   .filter(models.User.id == models.ReceiverTip.receiver_id,
                                           models.ReceiverTip.internaltip_id == models.InternalTip.id,
                                           models.InternalTip.id == itip_id):
        db_notify_report_update(session, user, rtip, itip)


def db_get_wbtip(session, itip_id, language):
    itip = db_get(session, models.InternalTip, models.InternalTip.id == itip_id)

    itip.last_access = datetime_now()

    return serializers.serialize_wbtip(session, itip, language), base64.b64decode(itip.crypto_tip_prv_key)


@transact
def get_wbtip(session, itip_id, language):
    return db_get_wbtip(session, itip_id, language)


@transact
def create_comment(session, tid, user_id, content):
    itip = db_get(session,
                  models.InternalTip,
                  (models.InternalTip.id == user_id,
                   models.InternalTip.status != 'closed',
                   models.InternalTip.tid == tid))

    itip.update_date = itip.last_access = datetime_now()

    _content = content
    if itip.crypto_tip_pub_key:
        _content = base64.b64encode(GCE.asymmetric_encrypt(itip.crypto_tip_pub_key, content)).decode()

    comment = models.Comment()
    comment.internaltip_id = itip.id
    comment.content = _content
    session.add(comment)
    session.flush()

    ret = serializers.serialize_comment(session, comment)
    ret['content'] = content

    return ret


@transact
def update_identity_information(session, tid, user_id, identity_field_id, wbi, language):
    itip = db_get(session,
                  models.InternalTip,
                  (models.InternalTip.id == user_id,
                   models.InternalTip.status != 'closed',
                   models.InternalTip.tid == tid))

    if itip.crypto_tip_pub_key:
        wbi = base64.b64encode(GCE.asymmetric_encrypt(itip.crypto_tip_pub_key, json.dumps(wbi).encode())).decode()

    db_set_internaltip_data(session, itip.id, 'whistleblower_identity', wbi)

    now = datetime_now()
    itip.update_date = now
    itip.last_access = now

    db_notify_recipients_of_tip_update(session, itip.id)


@transact
def store_additional_questionnaire_answers(session, tid, user_id, answers, language):
    itip, context = session.query(models.InternalTip, models.Context) \
                           .filter(models.InternalTip.id == user_id,
                                   models.InternalTip.status != 'closed',
                                   models.InternalTip.tid == tid,
                                   models.Context.id == models.InternalTip.context_id).one()

    if not context.additional_questionnaire_id:
        return

    steps = db_get_questionnaire(session, tid, context.additional_questionnaire_id, None)['steps']
    questionnaire_hash = db_archive_questionnaire_schema(session, steps)

    if itip.crypto_tip_pub_key:
        answers = base64.b64encode(GCE.asymmetric_encrypt(itip.crypto_tip_pub_key, json.dumps(answers).encode())).decode()

    db_set_internaltip_answers(session, itip.id, questionnaire_hash, answers)

    db_notify_recipients_of_tip_update(session, itip.id)


@transact
def change_receipt(session, itip_id, cc, new_receipt, receipt_change_needed):
    """
    Transaction for updating old receipt to a new one
    """
    itip = session.query(models.InternalTip) \
                  .filter(models.InternalTip.id == itip_id).one_or_none()
    if itip is None:
        return

    tid = itip.tid

    # update receipt
    itip.receipt_hash = GCE.hash_password(new_receipt, State.tenants[tid].cache.receipt_salt)

    if cc is None:
        return

    wb_key = GCE.derive_key(new_receipt.encode(), State.tenants[tid].cache.receipt_salt)

    # update private keys
    itip.crypto_prv_key = Base64Encoder.encode(GCE.symmetric_encrypt(wb_key, cc))

    itip.receipt_change_needed = receipt_change_needed


class Operations(BaseHandler):
    """
    This interface expose some utility methods for the Whistleblower Tip.
    """
    check_roles = "whistleblower"

    def put(self):
        request = self.validate_request(self.request.content.read(), requests.OpsDesc)
        if request["operation"] != "change_receipt":
            raise errors.InputValidationError("Invalid command")

        return change_receipt(self.session.user_id, self.session.cc,
                              self.session.properties["new_receipt"],
                              "operator_session" in self.session.properties)

def serialize_log(log):
    return {
        'date': log.date,
        'type': log.type,
        'user_id': log.user_id,
        'object_id': log.object_id,
        'data': log.data
    }


@transact
def get_audit_log(session, id,tip):
    logs = session.query(models.AuditLog).filter(models.AuditLog.object_id == id)
    return [serialize_log(log) for log in logs]

@transact
def get_status_label(session, status_uuid):
    """
    Fetch the label for the given status UUID from the Submissionstatus table.
    """
    submissionstatus = session.query(models.SubmissionStatus).filter_by(id=status_uuid).first()
    if submissionstatus:
        return submissionstatus.label['en']
    else:
        return "Unknown Status"
    
@transact
def get_substatus_label(session, substatus_uuid):
    """
    Fetch the label for the given substatus UUID from the Submissionsubstatus table.
    """
    submissionsubstatus = session.query(models.SubmissionSubStatus).filter_by(id=substatus_uuid).first()
    if submissionsubstatus:
        return submissionsubstatus.label['en']
    else:
        return "Unknown Substatus"
    
class WBTipInstance(BaseHandler):
    """
    This interface expose the Whistleblower Tip.
    """
    check_roles = 'whistleblower'

    @inlineCallbacks
    def get(self):
        tip, crypto_tip_prv_key = yield get_wbtip(self.session.user_id, self.request.language)

        if crypto_tip_prv_key:
            logs = yield get_audit_log(tip['id'],tip)
            tip = yield deferToThread(decrypt_tip, self.session.cc, crypto_tip_prv_key, tip)
            tip = yield deferToThread(process_logs, logs, tip)
        # Return the modified tip
        returnValue(tip)

def process_logs(logs, tip):
    for log in logs:
        if log['type'] == 'update_report_status':
            status_details = log.get('data', {})
            if not isinstance(status_details, dict):
                status_change_string = "Status changed"
            else:
                status = status_details.get('status')
                substatus = status_details.get('substatus')

                if status:
                    status_label = get_status_label(status)
                    if substatus:
                        substatus_label = get_substatus_label(substatus)
                        status_change_string = f"Status changed to {status_label} - {substatus_label}"
                    else:
                        status_change_string = f"Status changed to {status_label}"
                else:
                    status_change_string = "Status changed"

            log_data = {
                'id': log['object_id'],
                'creation_date': log['date'],
                'content': status_change_string,
                'author_id': log['user_id'],
                'visibility': 'public'
            }
            tip['comments'].append(log_data)
    return tip


class WBTipCommentCollection(BaseHandler):
    """
    This interface expose the Whistleblower Tip Comments
    """
    check_roles = 'whistleblower'

    def post(self):
        request = self.validate_request(self.request.content.read(), requests.CommentDesc)
        return create_comment(self.request.tid, self.session.user_id, request['content'])


class WhistleblowerFileDownload(BaseHandler):
    """
    This handler exposes wbfiles for download.
    """
    check_roles = 'whistleblower'
    handler_exec_time_threshold = 3600

    @transact
    def download_wbfile(self, session, tid, user_id, file_id):
        ifile, itip = db_get(session,
                             (models.InternalFile,
                              models.InternalTip),
                             (models.InternalFile.id == file_id,
                              models.InternalFile.internaltip_id == models.InternalTip.id,
                              models.InternalTip.id == user_id))
        log.debug("Download of file %s by whistleblower %s" % (ifile.id, user_id))

        return ifile.name, ifile.id, itip.crypto_tip_prv_key

    @inlineCallbacks
    def get(self, wbfile_id):
        name, ifile_id, tip_prv_key = yield self.download_wbfile(self.request.tid, self.session.user_id, wbfile_id)

        filelocation = os.path.join(self.state.settings.attachments_path, ifile_id)

        directory_traversal_check(self.state.settings.attachments_path, filelocation)
        self.check_file_presence(filelocation)

        if tip_prv_key:
            tip_prv_key = GCE.asymmetric_decrypt(self.session.cc, base64.b64decode(tip_prv_key))
            name = GCE.asymmetric_decrypt(tip_prv_key, base64.b64decode(name.encode())).decode()

            try:
                # First attempt
                filelocation = GCE.streaming_encryption_open('DECRYPT', tip_prv_key, filelocation)
            except:
                pass

        yield self.write_file_as_download(name, filelocation)


class ReceiverFileDownload(BaseHandler):
    check_roles = 'whistleblower'
    handler_exec_time_threshold = 3600

    @transact
    def download_rfile(self, session, tid, file_id):
        rfile, wbtip = db_get(session,
                               (models.ReceiverFile, models.InternalTip),
                               (models.ReceiverFile.id == file_id,
                                models.ReceiverFile.internaltip_id == models.InternalTip.id,
                                models.InternalTip.id == self.session.user_id))

        if not wbtip:
            raise errors.ResourceNotFound

        if rfile.access_date == datetime_null():
            rfile.access_date = datetime_now()

        log.debug("Download of file %s by whistleblower %s",
                  rfile.id, self.session.user_id)

        return rfile.name, rfile.id, base64.b64decode(wbtip.crypto_tip_prv_key), ''

    @inlineCallbacks
    def get(self, rfile_id):
        name, filelocation, tip_prv_key, pgp_key = yield self.download_rfile(self.request.tid, rfile_id)

        filelocation = os.path.join(self.state.settings.attachments_path, filelocation)
        directory_traversal_check(self.state.settings.attachments_path, filelocation)

        if tip_prv_key:
            tip_prv_key = GCE.asymmetric_decrypt(self.session.cc, tip_prv_key)
            name = GCE.asymmetric_decrypt(tip_prv_key, base64.b64decode(name.encode())).decode()
            filelocation = GCE.streaming_encryption_open('DECRYPT', tip_prv_key, filelocation)

        yield self.write_file_as_download(name, filelocation, pgp_key)


class WBTipIdentityHandler(BaseHandler):
    """
    This is the interface that securely allows the whistleblower to provide his identity
    """
    check_roles = 'whistleblower'

    def post(self):
        request = self.validate_request(self.request.content.read(), requests.WhisleblowerIdentityAnswers)

        return update_identity_information(self.request.tid,
                                           self.session.user_id,
                                           request['identity_field_id'],
                                           request['identity_field_answers'],
                                           self.request.language)


class WBTipAdditionalQuestionnaire(BaseHandler):
    """
    This is the interface that securely allows the whistleblower to fill the additional questionnaire
    """
    check_roles = 'whistleblower'

    def post(self):
        request = self.validate_request(self.request.content.read(), requests.AdditionalQuestionnaireAnswers)
        return store_additional_questionnaire_answers(self.request.tid,
                                                      self.session.user_id,
                                                      request['answers'],
                                                      self.request.language)
