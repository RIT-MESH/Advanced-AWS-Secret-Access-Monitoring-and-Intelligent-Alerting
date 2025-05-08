# Advanced-AWS-Secret-Access-Monitoring-and-Intelligent-Alerting


This project implements a comprehensive, secure, and intelligent system for monitoring access to sensitive secrets stored in AWS Secrets Manager. It leverages a suite of AWS services to provide real-time alerting, AI-powered event summarization, historical analysis, automated responses, and visual dashboards.

## Overview

Monitoring who accesses sensitive configuration and credentials is crucial for security and compliance. This project provides a robust solution that goes beyond basic logging by:

*   Detecting specific access patterns (e.g., IAM Role access).
*   Using anomaly detection to flag unusual activity.
*   Leveraging AI (AWS Bedrock) to generate human-readable summaries of technical access events.
*   Sending immediate, informative alerts to Slack or Microsoft Teams.
*   Enabling automated responses like secret rotation upon suspicious access.
*   Providing historical querying and visualization capabilities via Athena and QuickSight.

This setup is designed with security best practices in mind, including least-privilege IAM policies and resource hardening.

![Screenshot 2025-05-01 204211](https://github.com/user-attachments/assets/6617be05-7161-4f8d-b1cf-41271433dd41)

## Key Features

*   ✅ **Secret Access Logging:** Captures `GetSecretValue` API calls via CloudTrail.
*   ✅ **Real-time Monitoring & Filtering:** Uses CloudWatch Logs and Metric Filters for targeted analysis.
*   ✅ **Anomaly Detection Alerting:** Flags unusual access patterns using CloudWatch Alarms.
*   ✅ **IAM Role Access Alerting:** Triggers immediate alerts for role-based access.
*   ✅ **AI-driven Event Summarization:** Generates concise summaries via AWS Bedrock (Claude) and Lambda.
*   ✅ **Automated Secret Rotation:** Optionally rotates secrets upon untrusted IP access (Lambda).
*   ✅ **Slack/Teams Integration:** Delivers real-time alerts and summaries via SNS and Lambda.
*   ✅ **Historical Log Analysis:** Enables SQL querying of logs via Athena.
*   ✅ **Interactive Security Dashboards:** Visualizes trends and details using QuickSight.
*   ✅ **Security Hardening:** Implements least-privilege IAM, resource policies, and cost optimization measures.

## Architecture Flow


1.  **Access:** IAM User/Role attempts `GetSecretValue` on **Secrets Manager**.
2.  **Logging:** **CloudTrail** logs the API call and delivers it to an **S3 Bucket** (`ritesh-secrets-monitoring-logs-...`).
3.  **Real-time Processing:** Logs are forwarded from CloudTrail to a **CloudWatch Log Group** (`ritesh-secretsmanager-loggroup`).
4.  **Metric Extraction:** **CloudWatch Metric Filters** scan the logs and generate custom **CloudWatch Metrics** (`SecretAccessed`, `SecretAccessedByRole`) in the `SecurityMetricsRitesh` namespace.
5.  **Alerting:** **CloudWatch Alarms** monitor these metrics:
    *   Anomaly Detection Alarm on `SecretAccessed`.
    *   Static Threshold Alarm on `SecretAccessedByRole`.
    *   Alarms trigger an **SNS Topic** (`SecretAccessNotificationsRitesh`) when thresholds are breached.
6.  **Notification:** An **AWS Lambda** function (`SecretAccessNotifier-Ritesh`) subscribes to the SNS topic, formats the alarm message, and sends it to a **Slack/Teams Webhook**.
7.  **Summarization:** A separate **AWS Lambda** function (`SecretAccessSummarizer-Ritesh`) is triggered directly by the **CloudWatch Log Group** (`ritesh-secretsmanager-loggroup`) on `GetSecretValue` events. It calls **AWS Bedrock**, sends the summary to **Slack/Teams**, and saves it to the **S3 Bucket**.
8.  **Automated Rotation (Optional Hardening):** A third **AWS Lambda** function (`SecretRotator-Ritesh`) is also triggered by the **CloudWatch Log Group**. It checks the source IP, calls **Secrets Manager** to update the secret if untrusted, and notifies **Slack/Teams**.
9.  **Reporting:** **AWS Glue Data Catalog** stores metadata. **Amazon Athena** queries logs in the **S3 Bucket**. **Amazon QuickSight** connects to Athena and displays interactive dashboards.
10. **Security Integration (Optional):** Findings can optionally be sent to **AWS Security Hub**.

## AWS Services Used

*   AWS Secrets Manager
*   AWS CloudTrail
*   Amazon S3
*   Amazon CloudWatch (Logs, Metrics, Alarms)
*   AWS Lambda
*   Amazon Simple Notification Service (SNS)
*   Amazon Bedrock
*   Amazon Athena
*   AWS Glue Data Catalog (Used implicitly by Athena)
*   Amazon QuickSight
*   AWS IAM (Identity and Access Management)
*   (Optional) AWS Security Hub, AWS Config, AWS KMS, AWS Budgets, VPC Endpoints

## Prerequisites

*   **AWS Account:** Admin access or relevant permissions (see list above).
*   **AWS Bedrock Access:** Access enabled for a suitable Anthropic Claude model (e.g., `anthropic.claude-3-sonnet-20240229-v1:0`) in your target region.
*   **Notification Endpoint:** A Slack Incoming Webhook URL or Microsoft Teams Webhook Connector URL.
*   **Basic Familiarity:** AWS Console, IAM, Python, JSON.
*   **Tools:** AWS Console access or AWS CLI.

## Setup Instructions



**1. Create Secret (Step 1 from detailed guide)**
*   Go to AWS Secrets Manager.
*   Store a new secret:
    *   Type: `Other type of secret`
    *   Key: `TheSecretIs`, Value: `TopSecretInfo123`
    *   Name: `TopSecretInfo`

**2. Enable CloudTrail (Step 2)**
*   Go to CloudTrail -> Trails -> Create trail.
*   Name: `secrets-manager-trail`.
*   Enable Multi-region.
*   Create **New S3 bucket**: `ritesh-secrets-monitoring-logs-<yourinitials>-<region>` (Replace placeholders).
*   Log events: Management Events, Read/Write, **Exclude KMS**, **Exclude RDS Data API**.
*   Create trail.

**3. Forward Logs to CloudWatch (Step 3)**
*   Edit the `secrets-manager-trail`.
*   Enable CloudWatch Logs integration.
*   New Log Group: `ritesh-secretsmanager-loggroup`.
*   New IAM Role: `CloudTrailRoleForCloudWatchLogs_secrets-manager-trail`.
*   Save changes.

**4. Create CloudWatch Metric Filters (Step 4)**
*   Go to CloudWatch -> Log groups -> `ritesh-secretsmanager-loggroup` -> Metric filters tab.
*   **Filter 1 (General Access):**
    *   Click `Create metric filter`.
    *   Filter pattern:
        ```json
        { $.eventName = "GetSecretValue" }
        ```
    *   Assign metric: Namespace=`SecurityMetricsRitesh`, Name=`SecretAccessed`, Value=`1`. Create filter.
*   **Filter 2 (Role Access):**
    *   Click `Create metric filter`.
    *   Filter pattern:
        ```json
        { ($.eventName = "GetSecretValue") && ($.userIdentity.type = "AssumedRole") }
        ```
    *   Assign metric: Namespace=`SecurityMetricsRitesh`, Name=`SecretAccessedByRole`, Value=`1`. Create filter.

**5. Set Up CloudWatch Alarms (Step 5)**
*   Go to CloudWatch -> Alarms -> Create alarm.
*   Create SNS Topic: Name=`SecretAccessNotificationsRitesh`. Add your email for testing (confirm subscription).
*   **Alarm 1 (Anomaly):**
    *   Metric: `SecurityMetricsRitesh` / `SecretAccessed`.
    *   Condition: Anomaly detection, Greater than band, Threshold=3 (adjust later).
    *   Action: Notify `SecretAccessNotificationsRitesh` SNS topic.
    *   Name: `SecretAccessAnomalyAlarm-Ritesh`. Create alarm.
*   **Alarm 2 (Static Role):**
    *   Metric: `SecurityMetricsRitesh` / `SecretAccessedByRole`.
    *   Condition: Static, >= 1.
    *   Action: Notify `SecretAccessNotificationsRitesh` SNS topic.
    *   Name: `SecretAccessedByRoleAlarm-Ritesh`. Create alarm.

**6. Notifier Lambda (Step 6)**
*   Go to Lambda -> Create function. Name: `SecretAccessNotifier-Ritesh`, Runtime: Python 3.9+, Permissions: Create new basic role.
*   **Environment Variable:** Key=`SLACK_TEAMS_WEBHOOK_URL`, Value=`<YOUR_WEBHOOK_URL>` (Replace!).
*   **Code (`lambda_function.py`):**
    ```python
    import json
    import os
    import urllib3
    import logging

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    WEBHOOK_URL = os.environ.get('SLACK_TEAMS_WEBHOOK_URL')
    http = urllib3.PoolManager()

    def format_slack_message(sns_message):
        alarm_name = sns_message.get('AlarmName', 'N/A')
        new_state = sns_message.get('NewStateValue', 'N/A')
        reason = sns_message.get('NewStateReason', 'N/A')
        account_id = sns_message.get('AWSAccountId', 'N/A')
        region = sns_message.get('Region', 'N/A')
        timestamp = sns_message.get('StateChangeTime', 'N/A')
        color = "#FF0000" if new_state == "ALARM" else "#36a64f"
        status_icon = "🚨" if new_state == "ALARM" else "✅"
        message = {
            "attachments": [{
                    "color": color,
                    "title": f"{status_icon} AWS Secret Access Alert: {alarm_name}",
                    "fields": [
                        {"title": "Status", "value": new_state, "short": True},
                        {"title": "Region", "value": region, "short": True},
                        {"title": "Account ID", "value": account_id, "short": False},
                        {"title": "Timestamp", "value": timestamp, "short": False},
                        {"title": "Reason", "value": reason, "short": False},
                    ],"footer": "AWS CloudWatch Alarm Notification",
            }]}
        return message

    def format_teams_message(sns_message):
        # (Include the format_teams_message function from the detailed guide if using Teams)
        # For brevity here, returning a simple text version for Teams
        alarm_name = sns_message.get('AlarmName', 'N/A')
        new_state = sns_message.get('NewStateValue', 'N/A')
        reason = sns_message.get('NewStateReason', 'N/A')
        return {"text": f"**AWS Secret Access Alert:** {alarm_name}\n**Status:** {new_state}\n**Reason:** {reason}"}

    def lambda_handler(event, context):
        logger.info("Received event: %s", json.dumps(event, indent=2))
        if not WEBHOOK_URL:
            logger.error("FATAL: SLACK_TEAMS_WEBHOOK_URL not set.")
            return {'statusCode': 500, 'body': 'Webhook URL not configured'}
        try:
            sns_record = event['Records'][0]['Sns']
            message_raw = sns_record['Message']
            sns_message = json.loads(message_raw)
            logger.info("Parsed SNS message: %s", json.dumps(sns_message, indent=2))

            if "hooks.slack.com" in WEBHOOK_URL:
                 message_payload = format_slack_message(sns_message)
            # Add elif for teams webhook URL if using format_teams_message
            # elif "webhook.office.com" in WEBHOOK_URL:
            #      message_payload = format_teams_message(sns_message)
            else: # Default or Teams simple version
                 message_payload = format_teams_message(sns_message) # Use simple text for others/Teams

            encoded_message = json.dumps(message_payload).encode('utf-8')
            response = http.request('POST', WEBHOOK_URL, body=encoded_message, headers={'Content-Type': 'application/json'})
            logger.info("Webhook response status: %d", response.status)
            if response.status >= 400: return {'statusCode': response.status, 'body': 'Webhook notification failed'}
            return {'statusCode': 200, 'body': json.dumps('Notification sent successfully')}
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {'statusCode': 500, 'body': 'Internal server error'}
    ```
*   **Trigger:** Add SNS trigger for `SecretAccessNotificationsRitesh` topic.
*   **Deploy.**

**7. Summarizer Lambda (Step 7)**
*   Go to Lambda -> Create function. Name: `SecretAccessSummarizer-Ritesh`, Runtime: Python 3.9+, Permissions: Create new basic role.
*   **Modify IAM Role:** Add permissions for `bedrock:InvokeModel` (scoped to model ARN) and `s3:PutObject` (scoped to `s3://<YOUR_BUCKET_NAME>/summaries/*`).
*   **Increase Timeout:** 30 seconds.
*   **Environment Variables:**
    *   `BEDROCK_MODEL_ID`: `<YOUR_CLAUDE_MODEL_ID>` (e.g., `anthropic.claude-3-sonnet-20240229-v1:0`)
    *   `BEDROCK_REGION`: `<YOUR_BEDROCK_REGION>` (e.g., `us-east-1`)
    *   `TARGET_S3_BUCKET`: `<YOUR_LOG_BUCKET_NAME>` (e.g., `ritesh-secrets-monitoring-logs-...`)
    *   `SLACK_TEAMS_WEBHOOK_URL`: `<YOUR_WEBHOOK_URL>`
*   **Code (`lambda_function.py`):**
    ```python
    # (Include the full SecretAccessSummarizer-Ritesh code from the detailed guide)
    # Key parts: imports, config from env vars, clients, decode_cloudwatch_log_event,
    # extract_event_details, call_bedrock_summarizer, save_summary_to_s3,
    # send_notification (simple version ok), lambda_handler
    import json, os, boto3, base64, gzip, logging, urllib3
    from datetime import datetime

    logger = logging.getLogger(); logger.setLevel(logging.INFO)
    BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID')
    BEDROCK_REGION = os.environ.get('BEDROCK_REGION')
    TARGET_S3_BUCKET = os.environ.get('TARGET_S3_BUCKET')
    WEBHOOK_URL = os.environ.get('SLACK_TEAMS_WEBHOOK_URL')
    MAX_TOKENS = 300
    bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name=BEDROCK_REGION)
    s3_client = boto3.client('s3') if TARGET_S3_BUCKET else None
    http = urllib3.PoolManager()

    def decode_cloudwatch_log_event(event):
        try:
            compressed_payload=base64.b64decode(event['awslogs']['data']); uncompressed_payload=gzip.decompress(compressed_payload); log_data=json.loads(uncompressed_payload); return log_data
        except Exception as e: logger.error(f"Error decoding CWL data: {e}"); return None
    def extract_event_details(log_event):
        details = {}; details['eventTime'] = log_event.get('eventTime', 'N/A'); details['eventName'] = log_event.get('eventName', 'N/A'); details['sourceIPAddress'] = log_event.get('sourceIPAddress', 'N/A'); user_identity = log_event.get('userIdentity', {}); details['identityType'] = user_identity.get('type', 'N/A'); details['arn'] = user_identity.get('arn', 'N/A'); request_params = log_event.get('requestParameters', {}); details['secretId'] = request_params.get('secretId', 'N/A') if request_params else 'N/A'; return {k: v for k, v in details.items() if v is not None}
    def call_bedrock_summarizer(event_details_json):
        prompt = f"Human: Please summarize the following AWS CloudTrail event related to Secrets Manager access in 1-2 concise sentences. Focus on who accessed what, from where, and when.\n\nEvent Details:\n```json\n{event_details_json}\n```\n\nAssistant:"; body = json.dumps({"prompt": prompt,"max_tokens_to_sample": MAX_TOKENS,"temperature": 0.5,"stop_sequences": ["\n\nHuman:"]}); response = bedrock_runtime.invoke_model(modelId=BEDROCK_MODEL_ID, body=body, contentType='application/json', accept='application/json'); response_body = json.loads(response['body'].read()); summary = response_body.get('completion', 'Error: Could not extract summary.').strip(); logger.info(f"Bedrock Summary: {summary}"); return summary
    def save_summary_to_s3(summary, log_event):
        if not s3_client: return False; event_time_str = log_event.get('eventTime', datetime.utcnow().isoformat()); timestamp_dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00")); s3_key = f"summaries/{timestamp_dt.strftime('%Y/%m/%d')}/{log_event.get('eventID', 'unknown_eventid')}.txt"; s3_client.put_object(Bucket=TARGET_S3_BUCKET, Key=s3_key, Body=summary.encode('utf-8'), ContentType='text/plain'); logger.info(f"Summary saved to s3://{TARGET_S3_BUCKET}/{s3_key}"); return True
    def send_notification(summary, details):
        if not WEBHOOK_URL: return False; message_payload = {"text": f"📝 **Secret Access Summary (AI)**:\n{summary}\n**Event Time**: {details.get('eventTime', 'N/A')}\n**Actor ARN**: {details.get('arn', 'N/A')}"}; encoded_message = json.dumps(message_payload).encode('utf-8'); response = http.request('POST', WEBHOOK_URL, body=encoded_message, headers={'Content-Type': 'application/json'}); logger.info(f"Webhook notification response status: {response.status}"); return response.status < 400

    def lambda_handler(event, context):
        logger.info("Summarizer invoked."); log_data = decode_cloudwatch_log_event(event);
        if not log_data: return {'statusCode': 400, 'body': 'Failed to decode CWL data'}
        processed = 0; failed = 0;
        for log_event_raw in log_data.get('logEvents', []):
            try:
                 log_event = json.loads(log_event_raw['message']); event_name = log_event.get('eventName');
                 if event_name != "GetSecretValue": continue
                 logger.info(f"Processing event ID: {log_event.get('eventID', 'N/A')}"); details = extract_event_details(log_event); details_json = json.dumps(details, indent=2); summary = call_bedrock_summarizer(details_json); save_summary_to_s3(summary, log_event); send_notification(summary, details); processed += 1
            except Exception as e: logger.error(f"Error processing event: {e}", exc_info=True); failed += 1
        logger.info(f"Processed {processed} event(s), Failed: {failed}."); return {'statusCode': 200, 'body': json.dumps(f"Processed {processed} event(s).")}
    ```
*   **Trigger:** Add CloudWatch Logs trigger for `ritesh-secretsmanager-loggroup`. Optional Filter pattern: `{ $.eventName = "GetSecretValue" }`.
*   **Deploy.**

**8. Athena & QuickSight (Step 8)**
*   **Athena Setup:**
    *   Set query result location (e.g., `s3://<YOUR_LOG_BUCKET_NAME>/athena-results/`).
    *   Create Database `secret_monitoring_ritesh_db`.
    *   Create Table `cloudtrail_logs` using the **working DDL** (with `JsonSerDe` and correct S3 `LOCATION`):
        ```sql
        CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
            eventVersion STRING, userIdentity STRUCT<...>, eventTime STRING, eventSource STRING, eventName STRING, awsRegion STRING, sourceIPAddress STRING, userAgent STRING, errorCode STRING, errorMessage STRING, requestParameters STRING, responseElements STRING, additionalEventData STRING, requestID STRING, eventID STRING, readOnly BOOLEAN, resources ARRAY<STRUCT< ARN: STRING, accountId: STRING, type: STRING >>, eventType STRING, apiVersion STRING, managementEvent BOOLEAN, recipientAccountId STRING, sharedEventID STRING, vpcEndpointId STRING
        )
        COMMENT 'CloudTrail table for monitoring Ritesh secret access logs'
        PARTITIONED BY (region STRING, year STRING, month STRING, day STRING)
        ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
        STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
        OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat'
        LOCATION 's3://<YOUR_LOG_BUCKET_NAME>/AWSLogs/<your-account-id>/CloudTrail/'; -- Replace placeholders
        ```
    *   Run `MSCK REPAIR TABLE cloudtrail_logs;`.
*   **QuickSight Setup:**
    *   **Attach Consolidated IAM Policy:** Ensure the `aws-quicksight-service-role-v0` role has the consolidated policy attached (granting necessary `athena:*`, `glue:*`, `s3:*`, potentially `kms:*` permissions). Detach redundant custom policies.
    *   Create Athena Data Source `AthenaSecretMonitoringRitesh`.
    *   Create Dataset using **Custom SQL**:
        ```sql
        SELECT
            eventtime AS event_time_original,
            from_iso8601_timestamp(eventtime) AS event_timestamp,
            eventname AS event_name, awsregion AS aws_region, sourceipaddress AS source_ip_address,
            useridentity.type AS user_type, useridentity.arn AS user_arn, useridentity.principalid AS principal_id,
            json_extract_scalar(requestparameters, '$.secretId') AS requested_secret_id, errorcode
        FROM "secret_monitoring_ritesh_db"."cloudtrail_logs"
        WHERE eventsource = 'secretsmanager.amazonaws.com' AND eventname = 'GetSecretValue' AND errorcode IS NULL; -- Filter successful
        ```
    *   Import to **SPICE**. Visualize.
    *   Build dashboard visuals (Trend line, User Type pie, User ARN bar, Secret ID table, Source IP table). Publish. Schedule SPICE refresh.

**9. Security Hardening (Step 9)**
*   **Rotator Lambda:** Create `SecretRotator-Ritesh` Lambda (Python runtime). Grant role `secretsmanager:UpdateSecret`/`GetSecretValue`/`DescribeSecret` for `TopSecretInfo` ARN. Set `SECRET_ID_TO_ROTATE`, `TRUSTED_IPS`, `SLACK_TEAMS_WEBHOOK_URL` env vars. Deploy rotator code. Add CWL trigger.
    ```python
    # (Include the full SecretRotator-Ritesh code from the detailed guide)
    # Key parts: imports, config, clients, is_ip_trusted, generate_new_secret_value,
    # send_rotation_notification, lambda_handler, decode_cloudwatch_log_event
    import json, os, boto3, base64, gzip, logging, secrets, ipaddress, urllib3
    logger = logging.getLogger(); logger.setLevel(logging.INFO); SECRET_ID = os.environ.get('SECRET_ID_TO_ROTATE'); TRUSTED_IP_RANGES_STR = os.environ.get('TRUSTED_IPS', ''); WEBHOOK_URL = os.environ.get('SLACK_TEAMS_WEBHOOK_URL'); secretsmanager = boto3.client('secretsmanager'); http = urllib3.PoolManager(); TRUSTED_NETWORKS = [];
    if TRUSTED_IP_RANGES_STR:
        try: TRUSTED_NETWORKS = [ipaddress.ip_network(ip.strip()) for ip in TRUSTED_IP_RANGES_STR.split(',')]; logger.info(f"Loaded trusted networks: {TRUSTED_NETWORKS}")
        except ValueError as e: logger.error(f"FATAL: Invalid IP/CIDR: {e}"); TRUSTED_NETWORKS = []
    def is_ip_trusted(source_ip):
        if not TRUSTED_NETWORKS: return False; ip_addr = ipaddress.ip_address(source_ip);
        for network in TRUSTED_NETWORKS:
            if ip_addr in network: return True
        return False
    def generate_new_secret_value(): new_value = secrets.token_hex(16); return json.dumps({'TheSecretIs': new_value})
    def send_rotation_notification(secret_id, reason, source_ip):
         if not WEBHOOK_URL: return; message = {"text": f"🔐 **Automatic Secret Rotation Triggered**\n**Secret**: `{secret_id}`\n**Reason**: {reason}\n**Triggering Source IP**: `{source_ip}`\n_The secret value changed._"}; encoded_msg = json.dumps(message).encode('utf-8'); http.request('POST', WEBHOOK_URL, body=encoded_msg, headers={'Content-Type': 'application/json'})
    def lambda_handler(event, context):
        logger.info("Rotator invoked."); log_data = decode_cloudwatch_log_event(event);
        if not log_data: return {'statusCode': 400, 'body': 'Failed to decode CWL data'}
        rotated = False
        for log_event_raw in log_data.get('logEvents', []):
            try:
                log_event = json.loads(log_event_raw['message']); event_name = log_event.get('eventName'); request_params = log_event.get('requestParameters'); event_secret_id = request_params.get('secretId') if request_params else None; source_ip = log_event.get('sourceIPAddress');
                if event_name == "GetSecretValue" and event_secret_id == SECRET_ID and source_ip and not is_ip_trusted(source_ip):
                    logger.warning(f"Untrusted access detected for {SECRET_ID} from {source_ip}. Rotating."); new_secret_string = generate_new_secret_value(); secretsmanager.update_secret(SecretId=SECRET_ID, SecretString=new_secret_string); logger.info(f"Rotated secret {SECRET_ID}."); send_rotation_notification(SECRET_ID, "Access from untrusted IP", source_ip); rotated = True; break # Rotate only once per invocation
            except Exception as e: logger.error(f"Error processing rotator event: {e}", exc_info=True)
        status_msg = "Rotation triggered." if rotated else "No untrusted access for rotation."; return {'statusCode': 200, 'body': json.dumps(status_msg)}
    def decode_cloudwatch_log_event(event): # Need decoder here too
        try: compressed_payload=base64.b64decode(event['awslogs']['data']); uncompressed_payload=gzip.decompress(compressed_payload); log_data=json.loads(uncompressed_payload); return log_data
        except Exception as e: logger.error(f"Error decoding CWL data: {e}"); return None
    ```
*   **IAM Policies:** Tighten Secrets Manager resource policy, Lambda role policies (use custom inline policies), and S3 bucket policy (add DenyInsecureTransport).
    *   *Example Secrets Manager Deny Snippet:*
        ```json
        {
           "Sid": "DenyEveryoneElseGetValue", "Effect": "Deny", "Principal": "*",
           "Action": "secretsmanager:GetSecretValue", "Resource": "*",
           "Condition": { "StringNotEquals": { "aws:PrincipalArn": "arn:aws:iam::<YOUR_ACCOUNT_ID>:role/<YOUR_ALLOWED_ROLE_NAME>" }}
         }
        ```
*   **Security Hub:** Enable and integrate findings if desired.
*   **Cost Opt:** Set S3 lifecycle rules, CloudWatch Logs retention. Consider VPC Endpoints. Use AWS Budgets.

## Configuration Summary

*   Replace placeholders: `<your-account-id>`, `<your-region>`, `<your-initials>`, `<YOUR_WEBHOOK_URL>`, `<YOUR_CLAUDE_MODEL_ID>`, `<YOUR_LOG_BUCKET_NAME>`, `<TRUSTED_IPS>`.
*   Verify IAM policies for least privilege (especially QuickSight role).
*   Ensure Bedrock model access is enabled.

## Testing



1.  **Basic Access:** Use admin/root user. Verify logs, metrics, summarizer (Slack/S3). Static alarm OK.
2.  **Role Access:** Assume role. Verify logs (AssumedRole type), *both* metrics increment, static alarm fires, notifier sends Slack alert, summarizer runs.
3.  **Untrusted Access:** Use non-trusted IP. Verify logs (untrusted IP), rotator runs, secret value changes, rotation alert sent.
4.  **Denied Access:** Use user without permission. Verify API error, denied event logged, no alerts/summaries trigger.
5.  **Reporting:** Generate data, wait, run `MSCK REPAIR`, query Athena, refresh SPICE, check QuickSight dashboard updates.

*Troubleshoot using Lambda CloudWatch Logs.*

## Cleanup


1.  QuickSight: Dashboard, Analysis, Dataset, Data Source.
2.  Athena: Table, Database, Query Result Bucket (if separate).
3.  Lambda: Triggers, Functions.
4.  CloudWatch: Alarms, Metric Filters, Log Groups.
5.  SNS: Topic.
6.  CloudTrail: Trail.
7.  S3: **Empty** Log Bucket, Delete Log Bucket.
8.  Secrets Manager: Secret.
9.  IAM: Roles, Policies (custom/inline ones created).

## License

```text
MIT License
...
