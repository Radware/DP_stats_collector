import config as cfg
import json
from vision import Vision
import traffic_stats_parser
import urllib3
import logging_helper
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not os.path.exists('log'):
	os.makedirs('log')

if not os.path.exists('Raw Data'):
	os.makedirs('Raw Data')

if not os.path.exists('Reports'):
	os.makedirs('Reports')
	

#Arguments variables
getdatafromvision = True
alarm = True
test_email_alarm = False
report = []

reports_path = "./Reports/"
raw_data_path = "./Raw Data/"
requests_path = "./Requests/"


logging_helper.log_setup(cfg.LOG_FILE_PATH, cfg.SYSLOG_SERVER, cfg.SYSLOG_PORT)


for i in sys.argv:
	#Running script with arguments

	if i.lower() == "--use-cache-data":
		#No data collection from vision- running script using previously collected data
		getdatafromvision = False
		logging_helper.logging.info('Running script using cache data only')
		
	if i.lower() == "--no-alarm":
		#Run script without sending email alert.
		alarm = False
		logging_helper.logging.info('Running script without email alarm')

	if i.lower() == "--test-alarm":
		#Run script- test email alert only
		logging_helper.logging.info('Running script to test email alarm only')
		getdatafromvision = False
		test_email_alarm = True
		nobdosreport = True
		nodpconfigparsing = True


def getBDOSReportFromVision():

	bdos_dict = {}

	for dp_ip,dp_attr in full_pol_dic.items():
		bdos_dict[dp_ip] = {}
		bdos_dict[dp_ip]['Name'] = dp_attr['Name']
		bdos_dict[dp_ip]['BDOS Report'] = []

		if not dp_attr['Policies']:
			continue
		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			if pol_attr["rsIDSNewRulesProfileNetflood"] != "" and pol_attr["rsIDSNewRulesName"] != "null":
				bdos_report = v.getBDOSTrafficReport(dp_ip,pol_attr,full_net_dic)
				bdos_dict[dp_ip]['BDOS Report'].append(bdos_report)

	with open(raw_data_path + 'BDOS_traffic_report.json', 'w') as outfile:
		json.dump(bdos_dict,outfile)
	
	return

def getDNSReportFromVision():

	dns_dict = {}

	for dp_ip,dp_attr in full_pol_dic.items():
		dns_dict[dp_ip] = {}
		dns_dict[dp_ip]['Name'] = dp_attr['Name']
		dns_dict[dp_ip]['DNS Report'] = []

		if not dp_attr['Policies']:
			continue
		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			if pol_attr["rsIDSNewRulesProfileDNS"] != "":
				dns_report = v.getDNStrafficReport(dp_ip,pol_attr,full_net_dic)
				dns_dict[dp_ip]['DNS Report'].append(dns_report)

	with open(raw_data_path + 'DNS_traffic_report.json', 'w') as outfile:
		json.dump(dns_dict,outfile)
	
	return


def getTrafficUtilizationStatsFromVision():

	traffic_stats_dict_bps = {}
	traffic_stats_dict_pps = {}
	traffic_stats_dict_cps = {}


	for dp_ip,dp_attr in full_pol_dic.items():

		traffic_stats_dict_bps[dp_ip] = {}
		traffic_stats_dict_bps[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_bps[dp_ip]['Traffic Report BPS'] = []

		traffic_stats_dict_pps[dp_ip] = {}
		traffic_stats_dict_pps[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_pps[dp_ip]['Traffic Report PPS'] = []

		traffic_stats_dict_cps[dp_ip] = {}
		traffic_stats_dict_cps[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_cps[dp_ip]['Traffic Report CPS'] = []

		if not dp_attr['Policies']:
			continue

		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			pol_name = pol_attr["rsIDSNewRulesName"]

			traffic_report_bps = v.getTrafficStatsBPS(dp_ip,pol_name)
			traffic_report_pps = v.getTrafficStatsPPS(dp_ip,pol_name)
			traffic_report_cps = v.getTrafficStatsCPS(dp_ip,pol_name)

			traffic_stats_dict_bps[dp_ip]['Traffic Report BPS'].append(traffic_report_bps)
			traffic_stats_dict_pps[dp_ip]['Traffic Report PPS'].append(traffic_report_pps)
			traffic_stats_dict_cps[dp_ip]['Traffic Report CPS'].append(traffic_report_cps)

	with open(raw_data_path + 'Traffic_report_BPS.json', 'w') as outfile:
		json.dump(traffic_stats_dict_bps,outfile)
	
	with open(raw_data_path + 'Traffic_report_PPS.json', 'w') as outfile:
		json.dump(traffic_stats_dict_pps,outfile)

	with open(raw_data_path + 'Traffic_report_CPS.json', 'w') as outfile:
		json.dump(traffic_stats_dict_cps,outfile)

	getCEC()
	
	return

def getCEC():
	#Get CEC - Concurrent Established Connections per DefensePro

	traffic_stats_dict_cec = {}


	for dp_ip,dp_attr in full_pol_dic.items():

		traffic_stats_dict_cec[dp_ip] = {}
		traffic_stats_dict_cec[dp_ip]['Name'] = dp_attr['Name']
		traffic_stats_dict_cec[dp_ip]['Traffic Report CEC'] = []

		if not dp_attr['Policies']:
			continue

	
		traffic_report_cec = v.getTrafficStatsCEC(dp_ip)

		traffic_stats_dict_cec[dp_ip]['Traffic Report CEC'].append(traffic_report_cec)


	with open(raw_data_path + 'Traffic_report_CEC.json', 'w') as outfile:
		json.dump(traffic_stats_dict_cec,outfile)

	return


if not getdatafromvision:
	#If Script run with argument "--use-cache-data"
	with open(raw_data_path + 'full_pol_dic.json') as full_pol_dic_file:
		full_pol_dic = json.load(full_pol_dic_file)

	with open(raw_data_path + 'full_net_dic.json') as full_net_dic_file:
		full_net_dic = json.load(full_net_dic_file)

if getdatafromvision:
	v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
	
	full_pol_dic = v.getFullPolicyDictionary()
	logging_helper.logging.info('Collecting Full policies data')
	full_net_dic = v.getFullNetClassDictionary()
	logging_helper.logging.info('Collecting Full Network Classes data')

	getBDOSReportFromVision()
	logging_helper.logging.info('Collecting BDOS data')
	getDNSReportFromVision()
	logging_helper.logging.info('Collecting DNS data')
	getTrafficUtilizationStatsFromVision()
	logging_helper.logging.info('Collecting Traffic Utilization data')



report.append(traffic_stats_parser.parse())
logging_helper.logging.info('Parsing traffic/BDOS/DNS data')


if test_email_alarm:
	report = ['test']

if alarm:
	logging_helper.send_report(report)
	logging_helper.logging.info('Sending email')