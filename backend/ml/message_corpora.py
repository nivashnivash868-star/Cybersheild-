"""Hand-written labelled messages.

TRAIN is what the shipped text model learns from (written to app/detection_data/message_training.json).
EVAL is a separate set the model never sees. Both are written by the project team: they are realistic but not a
sample of any real mailbox, so the evaluation report treats them as a regression set, not a field measurement.

Label 1 = phishing / fraud, 0 = legitimate. Hard cases of both kinds are included on purpose.
"""
import json
from pathlib import Path

TRAIN = [
    # phishing / fraud
    ("URGENT: Your Microsoft 365 account will be suspended within 24 hours. Click here to verify credentials.", 1),
    ("Notice from PayPal: Unauthorized login attempt detected. Verify your identity immediately to prevent lock.", 1),
    ("Your parcel could not be delivered due to an unpaid customs fee of $2.50. Update details at the link below.", 1),
    ("Please process the attached invoice immediately per CEO instructions. Keep this confidential.", 1),
    ("Bank Alert: Your debit card has been locked. Click to restore banking access.", 1),
    ("HR Department: Important updates regarding payroll tax refunds. Submit your 2026 tax form here.", 1),
    ("Security Notification: We noticed a suspicious login from Russia. Confirm your password now.", 1),
    ("Netflix payment failed! Update billing information immediately or your subscription will terminate.", 1),
    ("Crypto Wallet: A transaction of 1.45 BTC is pending. Click to cancel or confirm authorization.", 1),
    ("DocuSign: the CEO has sent you an urgent contract to sign. Access the document via the secure portal.", 1),
    ("Your Apple ID has been locked for security reasons. Enter your recovery key to unlock.", 1),
    ("USPS delivery exception. Redeliver your package by confirming your residential address.", 1),
    ("I need you to purchase gift cards for a client today. Send me the codes by email, I am in a meeting and cannot call.", 1),
    ("We changed our bank details. Please send all future invoice payments to the new account below.", 1),
    ("Your mailbox is almost full. Click here to increase your storage quota or your emails will be deleted.", 1),
    ("A document has been shared with you on OneDrive. Sign in with your work email to view the file.", 1),
    ("Your password expires today. Click the link to keep your current password and avoid losing access.", 1),
    ("Congratulations, you have won a $500 Amazon voucher. Claim your prize now before it expires.", 1),
    ("IT Helpdesk: we are upgrading mail servers. Reply with your username and password to avoid deactivation.", 1),
    ("Final notice: your invoice is overdue. Open the attachment and remit payment today to avoid legal action.", 1),
    ("Unusual sign-in activity on your account. Verify now or your access will be restricted.", 1),
    ("Hi, are you available? I need a quick favour, it's urgent. Reply as soon as you get this.", 1),
    ("Your Coinbase account has been temporarily limited. Verify your identity to restore withdrawals.", 1),
    ("Direct deposit update: HR needs employees to re-enter their bank routing number in the payroll portal.", 1),
    ("Dear customer, your tax refund of $1,284.90 is ready. Submit the form to receive the payment.", 1),
    ("Scan the QR code below to re-authenticate your multi-factor settings before the deadline.", 1),
    ("Your Zoom account will be closed. Click to cancel the request and keep your account active.", 1),
    ("Wire transfer needed today for an acquisition. Do not discuss with anyone else. I will send the account details.", 1),
    ("Security team: your VPN certificate has expired. Download the attached file and run it to renew access.", 1),
    ("Job offer: earn $400 a day working from home. Send your ID and bank account number to get started.", 1),
    # legitimate
    ("Hi team, attached is the agenda for Thursday's architecture review. See you in the conference room.", 0),
    ("Your weekly project summary: 14 tickets completed, 3 pull requests merged. Good job everyone.", 0),
    ("Reminder: the company all-hands meeting starts at 3:00 PM EST on Google Meet.", 0),
    ("Thank you for your order! Your receipt #88192 is attached. Estimated delivery is Friday.", 0),
    ("The quarterly financial report is available on the intranet share for your review.", 0),
    ("Please find the updated documentation for the Python backend API deployment.", 0),
    ("Welcome to the cybersecurity newsletter. Today we discuss hardening Linux SSH daemons.", 0),
    ("Lunch order poll is now open. Please submit your preferences by 11:30 AM.", 0),
    ("System maintenance is scheduled for Saturday 2:00 AM UTC. Downtime is expected to be 15 minutes.", 0),
    ("Code review requested for PR #245: added unit tests for database connection pooling.", 0),
    ("The sprint kickoff is set for Monday morning. Please review the backlog items beforehand.", 0),
    ("Your subscription renewal receipt for the annual cloud storage plan is attached.", 0),
    ("Can you send me the slides from yesterday's presentation? I want to share them with the design team.", 0),
    ("Your flight to Berlin on 14 March is confirmed. Check-in opens 24 hours before departure.", 0),
    ("Here are the notes from our call. Action items: Sam to update the roadmap, Priya to book the venue.", 0),
    ("Your password was changed successfully. If this was you, no action is needed.", 0),
    ("Invoice 2217 for consulting services in September is attached. Payment terms are 30 days as agreed in the contract.", 0),
    ("Reminder: please complete the mandatory security awareness training by the end of the month.", 0),
    ("Happy birthday! The team has put together a card for you in the break room.", 0),
    ("We have shipped your order. Track the parcel from your account page on our website.", 0),
    ("The build failed on the main branch. Logs are available in the CI dashboard.", 0),
    ("Our office will be closed on Monday for the public holiday. Normal hours resume Tuesday.", 0),
    ("Thanks for registering for the webinar. A calendar invite with the joining link is attached.", 0),
    ("Your monthly statement is ready to view. Sign in to the app you normally use to see it.", 0),
    ("Could you review the attached contract draft before our legal sync on Wednesday?", 0),
    ("New comment on your pull request: could you rename this variable for clarity?", 0),
    ("Expense report approved. The reimbursement will be included in next month's payroll run.", 0),
    ("Apple receipt: your purchase of a 200 GB iCloud storage plan on 3 October. Manage subscriptions in Settings.", 0),
    ("Two-factor authentication is now enabled on your account. Contact IT if you did not request this.", 0),
    ("Urgent: the staging database is down. Engineering is on it and will post an update within the hour.", 0),
]

EVAL = [
    # phishing / fraud (hard and easy)
    ("Subject: Re: Invoice\nHello, please find our updated banking details attached. Kindly route this month's payment to the new account and confirm once done.", 1),
    ("Dear user, your Outlook mailbox has exceeded its limit. Click http://outlook-quota-update.top/restore to reactivate.", 1),
    ("Hello, this is the CFO. I'm travelling and need you to buy 5 Apple gift cards for clients today. Reply when ready and I'll send details.", 1),
    ("Your Microsoft password expires in 24 hours. Sign in at https://login-microsoftonline.verify-account.xyz/auth to keep it.", 1),
    ("Action required: unusual sign-in detected from Nigeria. Confirm it was you at http://secure-paypa1.com/signin or your account will be limited.", 1),
    ("Payroll notice: we are migrating to a new provider. Please re-enter your direct deposit routing number using the form linked below within 48 hours.", 1),
    ("You have 1 undelivered package. Pay the small redelivery fee at http://dhl-parcel-fee.click/pay to schedule delivery.", 1),
    ("Your DocuSign envelope is waiting. Review and sign: https://docusign-secure.pages.dev/view?id=88213", 1),
    ("Hi, I'm in a client meeting and can't talk. Are you at your desk? I need a favour that can't wait.", 1),
    ("Congratulations! You've been selected for a $1,000 reward. Confirm your delivery address and card number to claim.", 1),
    ("Security alert from IT: your account has been compromised. Reply with your current password so we can secure it immediately.", 1),
    ("Your Netflix membership could not be renewed. Update your payment method at http://netflix-billing-support.xyz to avoid cancellation.", 1),
    ("Please see the attached remittance advice and open the file with your email password to view.", 1),
    ("Re: wire. The acquisition closes today. I need the transfer sent right now to the account below and please keep it between us.", 1),
    ("Scan this QR code to confirm your identity and keep your company mailbox active.", 1),
    ("Final warning: your account will be terminated unless you verify your identity within 12 hours: http://192.0.2.44/verify", 1),
    ("A new voicemail from +1 415 555 0112 is waiting. Click to listen: https://voice-msg-portal.vercel.app/play", 1),
    ("Your Binance withdrawal of 0.8 BTC is pending approval. If you did not request it, click here to cancel and secure your wallet.", 1),
    ("Dear employee, benefits enrollment closes tonight. Log in with your corporate credentials at the portal below to avoid losing coverage.", 1),
    ("Tax authority notice: you are owed a refund. Provide your bank account and national ID number to receive it.", 1),
    ("Your Chase account is locked after multiple failed attempts. Verify now at https://chase-secure-login.top/unlock", 1),
    ("The shared document 'Q4 Salary Review' needs your Microsoft sign-in before it can be opened.", 1),
    ("Helpdesk: your VPN token has expired. Run the attached installer to restore remote access today.", 1),
    ("I am out of the office and need you to handle a confidential payment. Please send your mobile number so I can give instructions.", 1),
    ("Spotify: your payment was declined. Update your card at http://spotify-account-update.icu or your plan will be cancelled.", 1),
    # legitimate (including look-alike-prone and urgent ones)
    ("Hi all, attached are the minutes from today's planning meeting. Please flag any corrections by Friday.", 0),
    ("Your GitHub password was changed from a new device. If this was not you, visit https://github.com/settings/security.", 0),
    ("Your invoice from Acme Cloud for October is available at https://billing.acmecloud.com/invoices. Payment is due in 30 days.", 0),
    ("Heads up: the VPN will be down for maintenance tonight 22:00-23:00. Please save your work.", 0),
    ("Reminder: complete your annual compliance training at the learning portal on the intranet by 30 November.", 0),
    ("Can you approve my time off request for 15-19 December? The details are in the HR system.", 0),
    ("Welcome to the team! Your laptop will be ready at the IT desk on your first day. Ask for Maria.", 0),
    ("Thanks for contacting support. Your ticket #44021 has been created and an engineer will reply within one business day.", 0),
    ("Your Google Workspace storage is 85% full. Admins can review usage in the admin console.", 0),
    ("Q3 results: revenue grew 12% year on year. The full deck is on the shared drive.", 0),
    ("Urgent: production deploy rollback needed. Please join the incident bridge at https://meet.google.com/abc-defg-hij.", 0),
    ("Receipt for your payment of $49.00 to Dropbox. View your account at https://www.dropbox.com/account.", 0),
    ("Dinner on Friday? I booked a table for six at 7:30. Let me know about dietary requirements.", 0),
    ("Security bulletin: please install the latest operating system update from the company software centre by Friday.", 0),
    ("Your LinkedIn weekly digest: 3 people viewed your profile. See who at https://www.linkedin.com/me/profile-views.", 0),
    ("The wire transfer for the Henderson contract was approved by finance on Tuesday per the signed purchase order.", 0),
    ("We've updated our privacy policy. You can read the changes at https://www.example.com/privacy; no action needed.", 0),
    ("Please reset your password using the self-service page on the intranet. IT will never ask for your password by email.", 0),
    ("Your Amazon order has shipped and will arrive Thursday. Track it in the Your Orders page of the Amazon app.", 0),
    ("Interview scheduled with the candidate for Tuesday 10:00. The CV and feedback form are attached.", 0),
    ("Slack: you have 4 unread messages in #engineering.", 0),
    ("Meeting notes: we agreed to move the release to the 20th and to add the payment gateway tests to the checklist.", 0),
    ("Final reminder: expense reports for Q3 are due tomorrow at noon. Submit them through the finance system.", 0),
    ("Your DHL shipment 4471920 left the Frankfurt hub. Track it at https://www.dhl.com/track.", 0),
    ("As discussed, I've paid the invoice via our usual bank transfer. The remittance advice is attached for your records.", 0),
]


def write_training_json(out: Path) -> None:
    out.write_text(json.dumps(TRAIN, ensure_ascii=False, indent=0))


if __name__ == "__main__":
    write_training_json(Path(__file__).resolve().parent.parent / "app" / "detection_data" / "message_training.json")
    print(f"wrote {len(TRAIN)} training messages ({sum(l for _, l in TRAIN)} phishing); eval set: {len(EVAL)}")


# Written after the rules were tuned against EVAL and never used to tune anything: a small blind check.
BLIND = [
    ("Hello, I noticed an issue with your Adobe subscription. Re-enter your card number at http://adobe-billing-center.cfd/update to avoid suspension.", 1),
    ("Hi, it's your manager. I'm stuck in a board meeting and can't take calls. Please buy two $200 Google Play gift cards and send me the codes.", 1),
    ("Your corporate email will be deactivated tonight. Sign in with your credentials at https://mail-upgrade.workers.dev/login to keep it.", 1),
    ("Attached is the signed contract. You must enable macros to view the content of the document.", 1),
    ("Vendor update: our bank account has changed. Please send all outstanding invoice payments to the new IBAN in the attachment today.", 1),
    ("We detected a login to your account from an unrecognised device. Confirm your password here: http://account-check.icu/s", 1),
    ("Thanks for your presentation yesterday. Could you share the final numbers so I can put them in the board pack?", 0),
    ("Your new corporate card has been dispatched and will arrive within 5 working days. Activate it in the finance app when it arrives.", 0),
    ("IT notice: we're rolling out new laptops next month. You'll receive an email with your slot. We will never ask for your password.", 0),
    ("The invoice from our supplier was paid on the 3rd. Here is the transfer confirmation for your records.", 0),
    ("Reminder: your annual performance review is on Thursday. Please complete the self-assessment form in Workday before then.", 0),
    ("Security tip of the week: use a password manager and enable two-factor authentication on personal accounts too.", 0),
]
