import socket
import logging
import logging.handlers
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase 
from email.mime.multipart import MIMEMultipart
from email import encoders
from datetime import date
import os
import config as cfg

def send_report(report_list):
	fromaddr = cfg.SMTP_SENDER
	toaddr = cfg.SMTP_LIST
	password = cfg.SMTP_PASSWORD

	msg = MIMEMultipart()
	msg["Subject"] = cfg.SMTP_SUBJECT_PREFIX + "DefensePro report  - " + date.today().strftime("%B %d, %Y")
	msg["From"] = fromaddr
	msg["To"] = ', '.join(toaddr)
	body = cfg.SMTP_MSG_BODY
	msg.attach(MIMEText(body, 'plain'))

	for report in report_list:


		if report == 'test':
			#Send this test email if "--test-alarm" argument is set
			logging.info('sending test email alarm')
			msg["Subject"] = cfg.SMTP_SUBJECT_PREFIX + "DefensePro test alert report  - " + date.today().strftime("%B %d, %Y")
			body = "This email is a test email alert"

		else:
			logging.info(f'sending {report} by email')
			dir, filename = os.path.split(report)
			attachment = open(report, "rb")
			p = MIMEBase('application', 'octet-stream')
			p.set_payload((attachment).read())
			encoders.encode_base64(p)
			p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
			msg.attach(p)
			attachment.close()

	mailserver = smtplib.SMTP(host=cfg.SMTP_SERVER,port=cfg.SMTP_SERVER_PORT)
	mailserver.ehlo()
	mailserver.starttls()
	mailserver.ehlo()
	mailserver.login(fromaddr, password)
	mailserver.sendmail(from_addr=fromaddr,to_addrs=toaddr, msg=msg.as_string())
	mailserver.quit()

def log_setup(log_path, syslog_ip, syslog_port):
	log_dir_name = log_path
	log_rotation_size = cfg.LOG_ROTATION_SIZE
	log_rotation_history = cfg.LOG_ROTATION_HISTORY
	

	log_handler = logging.handlers.RotatingFileHandler(log_dir_name + "monitor.log", maxBytes=log_rotation_size, backupCount=log_rotation_history)
	syslog_handler = logging.handlers.SysLogHandler(address=(syslog_ip, syslog_port),
													facility=logging.handlers.SysLogHandler.LOG_USER,
													socktype=socket.SOCK_DGRAM)
	log_formatter = logging.Formatter(
		'%(asctime)s %(message)s',
		'%b %d %H:%M:%S')
	syslog_formatter = logging.Formatter(
		'%(asctime)s %(message)s',
		'%b %d %H:%M:%S')

	log_handler.setFormatter(log_formatter)
	syslog_handler.setFormatter(syslog_formatter)
	logger = logging.getLogger()
	logger.addHandler(log_handler)
	logger.addHandler(syslog_handler)
	logger.setLevel(logging.INFO)