export class notificationResolverModel {
    disable_admin_notification_emails: boolean;
    disable_custodian_notification_emails: boolean;
    disable_receiver_notification_emails: boolean;
    smtp_authentication: boolean;
    smtp_password: string;
    smtp_port: number;
    smtp_security: string;
    smtp_server: string;
    smtp_source_email: string;
    smtp_username: string;
    tip_expiration_threshold: number;
    account_activation_mail_template: string;
    account_activation_mail_title: string;
    account_recovery_key_instructions: string;
    activation_mail_template:string;
    activation_mail_title:string;
    admin_anomaly_activities:string;
    admin_anomaly_disk_high:string;
    admin_anomaly_disk_low:string;
    admin_anomaly_mail_template:string;
    admin_anomaly_mail_title:string;
    admin_pgp_alert_mail_template:string;
    admin_pgp_alert_mail_title:string;
    admin_signup_alert_mail_template:string;
    admin_signup_alert_mail_title:string;
    admin_test_mail_template:string;
    admin_test_mail_title:string;
    email_validation_mail_template:string;
    email_validation_mail_title:string;
    export_message_recipient:string;
    export_message_whistleblower:string;
    export_template:string;
    https_certificate_expiration_mail_template:string;
    https_certificate_expiration_mail_title:string;
    https_certificate_renewal_failure_mail_template:string;
    https_certificate_renewal_failure_mail_title:string;
    identity_access_authorized_mail_template:string;
    identity_access_authorized_mail_title:string;
    identity_access_denied_mail_template:string;
    identity_access_denied_mail_title:string;
    identity_access_request_mail_template:string;
    identity_access_request_mail_title:string;
    identity_provided_mail_template:string;
    identity_provided_mail_title:string;
    password_reset_validation_mail_template:string;
    password_reset_validation_mail_title:string;
    pgp_alert_mail_template:string;
    pgp_alert_mail_title:string;
    receiver_notification_limit_reached_mail_template:string;
    receiver_notification_limit_reached_mail_title:string;
    signup_mail_template:string;
    signup_mail_title:string;
    software_update_available_mail_template:string;
    software_update_available_mail_title:string;
    tip_access_mail_template:string;
    tip_access_mail_title:string;
    tip_expiration_summary_mail_template:string;
    tip_expiration_summary_mail_title:string;
    tip_mail_template:string;
    tip_mail_title:string;
    tip_update_mail_template:string;
    tip_update_mail_title:string;
    unread_tips_mail_template:string;
    unread_tips_mail_title:string;
    user_credentials:string;
    templates: string[];
  }
