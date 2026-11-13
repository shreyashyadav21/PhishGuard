# Google Cloud Pub/Sub Real-Time Mailbox Notifications Guide

This guide describes how to configure Google Cloud Pub/Sub to deliver real-time push notifications to **PhishGuard** whenever an incoming email arrives.

---

## 1. Create a Pub/Sub Topic

1. In the [Google Cloud Console](https://console.cloud.google.com/), navigate to **Pub/Sub** $\to$ **Topics**.
2. Click **Create Topic**.
3. Topic ID: `gmail-notifications`.
4. Click **Create**.
5. Note the full topic path: `projects/YOUR_PROJECT_ID/topics/gmail-notifications`.

---

## 2. Grant Publish Permissions to Gmail API

Gmail's push service must have permission to publish messages to your Pub/Sub topic:

1. Click into your newly created topic (`gmail-notifications`).
2. Go to the **Permissions** tab.
3. Click **Add Principal**.
4. Principal: `gmail-api-push@system.gserviceaccount.com`
5. Role: **Pub/Sub Publisher**.
6. Click **Save**.

---

## 3. Create a Push Subscription (for Webhook Ingestion)

1. Under the topic page, click **Create Subscription** $\to$ **Create Push Subscription**.
2. Subscription ID: `phishguard-gmail-push`.
3. Delivery Type: Select **Push**.
4. Endpoint URL: Your publicly reachable server endpoint:
   ```
   https://your-domain-or-ngrok.io/api/gmail/pubsub
   ```
   *(For local testing, use [ngrok](https://ngrok.com/) to tunnel port 8000: `ngrok http 8000`)*.
5. Acknowledgment deadline: `30 seconds`.
6. Click **Create**.

---

## 4. How PhishGuard Processes Pub/Sub Notifications

```
Incoming Email arrives in Gmail
              |
              v
Gmail publishes notification to Pub/Sub topic
              |
              v
Pub/Sub pushes JSON webhook to /api/gmail/pubsub
              |
              v
PhishGuard identifies connected account by emailAddress
              |
              v
Calls Gmail History API using last_history_id
              |
              v
Fetches only newly added messages (idempotent)
              |
              v
Runs Email Analyzer & Attachment Scanner
              |
              v
Updates Threat Timeline & Dashboard in Real-Time
```

