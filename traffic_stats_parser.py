import json
import csv
import os

reports_path = "./Reports/"
raw_data_path = "./Raw Data/"
requests_path = "./Requests/"


def parseTrafficStatsBPS():
	#Fetches traffic utilization statistics (Bps)

	with open(raw_data_path + 'Traffic_report_BPS.json') as json_file:
		traffic_stats_dict = json.load(json_file)


	for dp_ip,dp_ip_attr in traffic_stats_dict.items(): #dp_ip_attr is {"Name": "ilchic01-borderips-02", "Traffic Report": [{"RCC": [{"row": {"timeStamp": "1626793200000", "excluded": "0", "discards": "0", "trafficValue": "0"}}, {"row":
		dp_name = dp_ip_attr['Name']

		for policy_attr_obj in dp_ip_attr['Traffic Report BPS']: # dp_ip_attr['Traffic Report'] is {'RCC': [{'row': {'timeStamp': '1626793200000', 'excluded': '0', 'discards': '0', 'trafficValue': '0'}}, {'row':...
			for policy, stampslist in policy_attr_obj.items(): #stamplist is [{'row': {'timeStamp': '1626793200000', 'excluded': '0', 'discards': '0', 'trafficValue': '0'}}, {'row':
				currthroughput_list = []

				for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
					row = stamp['row']
					if row['trafficValue'] is None:
						continue
					trafficvalue = int(row['trafficValue'])
					excluded = int(row['excluded'])
					discards = int(row['discards'])


					if excluded !=0:
						print(f'{dp_ip}, {dp_name}, {policy}, Excluded traffic exists')

					# if discards !=0: #blocked traffic
					# 	print(f'{dp_ip}, {dp_name}, {policy}, Discarded traffic exists {discards}')


					currthroughput_list.append(trafficvalue)

				if len(currthroughput_list) and sum(currthroughput_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
					# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))
					top_currthroughput_idx = sorted(range(len(currthroughput_list)), key=lambda i: currthroughput_list[i])[-10:]
					top_currthroughput_list = [currthroughput_list[i] for i in top_currthroughput_idx]
				
					top_currthroughput_avg = ((sum(top_currthroughput_list)) / (len(top_currthroughput_list)))*1.1


					# Traffic Utilization Stats collection - max traffic average per policy
					with open(reports_path + 'traffic_stats_temp1.csv', mode='a', newline="") as traffic_stats:
						traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'All Combined', f'{top_currthroughput_avg / 1000}', f'N/A', f'N/A', f'N/A',f'N/A'])

				if sum(currthroughput_list) == 0:

					with open(reports_path + 'traffic_stats_temp1.csv', mode='a', newline="") as traffic_stats:
						traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'All Combined', f'0', f'N/A', f'N/A', f'N/A',f'N/A'])


def parseTrafficStatsPPS():
	#Fetches traffic utilization statistics (PPS)

	with open(raw_data_path + 'Traffic_report_PPS.json') as json_file:
		traffic_stats_dict = json.load(json_file)


	for dp_ip,dp_ip_attr in traffic_stats_dict.items(): #dp_ip_attr is {"Name": "ilchic01-borderips-02", "Traffic Report": [{"RCC": [{"row": {"timeStamp": "1626793200000", "excluded": "0", "discards": "0", "trafficValue": "0"}}, {"row":
		dp_name = dp_ip_attr['Name']

		for policy_attr_obj in dp_ip_attr['Traffic Report PPS']: # dp_ip_attr['Traffic Report'] is {'RCC': [{'row': {'timeStamp': '1626793200000', 'excluded': '0', 'discards': '0', 'trafficValue': '0'}}, {'row':...
			for policy, stampslist in policy_attr_obj.items(): #stamplist is [{'row': {'timeStamp': '1626793200000', 'excluded': '0', 'discards': '0', 'trafficValue': '0'}}, {'row':
				currthroughput_list = []

				for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
					row = stamp['row']

					if row['trafficValue'] is None:
						continue

					trafficvalue = int(row['trafficValue'])

					currthroughput_list.append(trafficvalue)



				if len(currthroughput_list):
					if sum(currthroughput_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
						# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))
						top_currthroughput_idx = sorted(range(len(currthroughput_list)), key=lambda i: currthroughput_list[i])[-10:]
						top_currthroughput_list = [currthroughput_list[i] for i in top_currthroughput_idx]
					
						top_currthroughput_avg = (sum(top_currthroughput_list)) / (len(top_currthroughput_list))

					# Traffic Utilization Stats collection - max traffic average per policy

					with open(reports_path + 'traffic_stats_temp1.csv', 'r') as read_obj, open(reports_path + 'traffic_stats_temp2.csv', 'a', newline='') as write_obj:
					# Create a csv.reader object from the input file object
						csv_reader = csv.reader(read_obj)

						# Create a csv.writer object from the output file object
						csv_writer = csv.writer(write_obj)

						# Read each row of the input csv file as list
						for row in csv_reader:
							# Append the default text in the row / list
							if row[0] == dp_ip and row[2] == policy:
								if sum(currthroughput_list) !=0:
									row[6] = top_currthroughput_avg
								if sum(currthroughput_list) ==0:
									row[6] = "0"
							# # Add the updated row / list to the output file
								csv_writer.writerow(row)

def parseTrafficStatsCPS():
	#Fetches traffic utilization statistics (CPS)

	with open(raw_data_path + 'Traffic_report_CPS.json') as json_file:
		traffic_stats_dict = json.load(json_file)

	for dp_ip,dp_ip_attr in traffic_stats_dict.items(): #dp_ip_attr is {"Name": "ilchic01-borderips-02", "Traffic Report": [{"RCC": [{"row": {"timeStamp": "1626793200000", "excluded": "0", "discards": "0", "trafficValue": "0"}}, {"row":

		for policy_attr_obj in dp_ip_attr['Traffic Report CPS']: # dp_ip_attr['Traffic Report'] is {'RCC': [{'row': {'timeStamp': '1626793200000', 'excluded': '0', 'discards': '0', 'trafficValue': '0'}}, {'row':...
			for policy, stampslist in policy_attr_obj.items(): #stamplist is [{'row': {'timeStamp': '1626793200000', 'excluded': '0', 'discards': '0', 'trafficValue': '0'}}, {'row':
				currcps_list = []

				for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
					row = stamp['row']
					if row['connectionPerSecond'] is None:
						continue
					
					connectionpersecond = int(row['connectionPerSecond'])

					currcps_list.append(connectionpersecond)

				if len(currcps_list): # if current throughput list per stamplist is not empty, calculate average throughput
					if sum(currcps_list) !=0:
						# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))
						top_currcps_idx = sorted(range(len(currcps_list)), key=lambda i: currcps_list[i])[-10:]
						top_currcps_list = [currcps_list[i] for i in top_currcps_idx]
					
						top_currcps_avg = (sum(top_currcps_list)) / (len(top_currcps_list))


					# Traffic Utilization Stats collection - max traffic average per policy

					with open(reports_path + 'traffic_stats_temp2.csv', 'r') as read_obj, open(reports_path + 'traffic_stats.csv', 'a', newline='') as write_obj:
					# Create a csv.reader object from the input file object
						csv_reader = csv.reader(read_obj)

						# Create a csv.writer object from the output file object
						csv_writer = csv.writer(write_obj)

						# Read each row of the input csv file as list
						for row in csv_reader:
							# Append the default text in the row / list
							if row[0] == dp_ip and row[2] == policy:
								
								if sum(currcps_list) !=0:
									row[7] = top_currcps_avg
								
								if sum(currcps_list) ==0:
									row[7] = "0"
							# # Add the updated row / list to the output file
								csv_writer.writerow(row)


def parseTrafficStatsCEC():
	#Fetches traffic utilization statistics (CEC - Concurrent established Connections)

	with open(raw_data_path + 'Traffic_report_CEC.json') as json_file:
		traffic_stats_dict = json.load(json_file)


	for dp_ip,dp_ip_attr in traffic_stats_dict.items(): #dp_ip_attr is {"Name": "casanj01-borderips-02", "Traffic Report CEC": [[{"row": {"connectionsPerSecond"
		dp_name = dp_ip_attr['Name']
		for stampslist in dp_ip_attr['Traffic Report CEC']: # dp_ip_attr['Traffic Report'] is [[{"row": {"connectionsPerSecond"
			currcec_list = []

			for stamp in stampslist: # every row {"row": {"connectionsPerSecond": "0", "timestamp": "1627318800000"}}
				row = stamp['row']
				if row['connectionsPerSecond'] is None:
					continue
				
				cec = int(row['connectionsPerSecond'])

				currcec_list.append(cec)


			if len(currcec_list) and sum(currcec_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
				# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))
				top_currcec_idx = sorted(range(len(currcec_list)), key=lambda i: currcec_list[i])[-10:]
				top_currcec_list = [currcec_list[i] for i in top_currcec_idx]
			
				top_currcps_avg = (sum(top_currcec_list)) / (len(top_currcec_list))


				# Traffic Utilization Stats collection - max traffic average per policy
				with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
					traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
					traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'All Policies', f'All Combined' , f'N/A','N/A','N/A', 'N/A',f'{top_currcps_avg}'])

				

def parseBDOSStats():
	with open(raw_data_path + 'BDOS_traffic_report.json') as json_file:
		bdos_dict = json.load(json_file)
	
	for dp_ip,dp_ip_attr in bdos_dict.items():
		dp_name = dp_ip_attr['Name']

		
		for policy_attr_obj in dp_ip_attr['BDOS Report']: # policy_attr_obj = {"pol_dmz_prod": [[{"row": {"deviceIp": "10.107.129.209", "normal": "184320.0", "fullExcluded": "-1.0", "policyName": "pol_dmz_prod", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620141600000", "fast": null, "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}
			for policy, pol_attr in policy_attr_obj.items(): #pol_attr is [[{"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620145200000", "fast": "0.0", "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}, {"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isI

				for stampslist in pol_attr: #stampslist = list of 72 checkpoints for the particular protection (udp, tcp-syn etc.) [{'row': {'deviceIp': '10.107.129.206', 'normal': '161.0', 'fullExcluded': '-1.0', 'policyName': 'NIX-NC-EB-dns', 'enrichmentContainer': '{}', 'protection': 'tcp-frag', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620141600000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}, {'row': ....
					currthroughput_list = []
					empty_resp = False


					for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
						row = stamp['row']									
						
						if 'response' in row:
							if row['response'] == 'empty':
								# print(f'{dp_ip},{dp_name},{policy},' , row['protection'] ,' - no BDOS stats ---')
								empty_resp = True
								with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
									traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
									traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', row['protection'] , f'No BDOS stats', f'No BDOS stats' , 'N/A','N/A','N/A'])

								continue

						if row['normal'] is None:
							normal_baseline = row['normal']
							protoc = row['protection']
							continue

						if row['full'] is None:
							normal_baseline = row['normal']
							protoc = row['protection']
							continue

						normal_baseline = row['normal']
						protoc = row['protection']
						currthroughput = float(row['full'])


						currthroughput_list.append(currthroughput)
				

					if len(currthroughput_list) and sum(currthroughput_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
						# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))

						top_10_currthroughput_idx = sorted(range(len(currthroughput_list)), key=lambda i: currthroughput_list[i])[-10:]
						top_10_currthroughput_list = [currthroughput_list[i] for i in top_10_currthroughput_idx]
				
						top10_currthroughput_avg = (sum(top_10_currthroughput_list)) / (len(top_10_currthroughput_list))

						
						# BDOS Stats collection - max traffic average and normal baseline
						if row['normal'] is not None:
							with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
								traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'{protoc}' , f'{top10_currthroughput_avg / 1000}', f'{float(normal_baseline) /1000}' , 'N/A','N/A','N/A'])

						if row['normal'] is None:
							with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
								traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'{protoc}' , f'{top10_currthroughput_avg / 1000}', f'None' , 'N/A','N/A','N/A'])

					if len(currthroughput_list) and sum(currthroughput_list) ==0:
						if row['normal'] is not None:
							with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
								traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'{protoc}' , f'0', f'{float(normal_baseline) /1000}' , 'N/A','N/A','N/A'])



					if len(currthroughput_list) == 0 and not empty_resp:
							with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
								traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', row['protection'] , f'BDOS stats returned None', f'Normal BDOS baseline returned None' , 'N/A','N/A','N/A'])


def parseDNSStats():
	with open(raw_data_path + 'DNS_traffic_report.json') as json_file:
		dns_dict = json.load(json_file)
	
	for dp_ip,dp_ip_attr in dns_dict.items():
		dp_name = dp_ip_attr['Name']

		
		for policy_attr_obj in dp_ip_attr['DNS Report']: # policy_attr_obj = {"pol_dmz_prod": [[{"row": {"deviceIp": "10.107.129.209", "normal": "184320.0", "fullExcluded": "-1.0", "policyName": "pol_dmz_prod", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620141600000", "fast": null, "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}
			for policy, pol_attr in policy_attr_obj.items(): #pol_attr is [[{"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620145200000", "fast": "0.0", "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}, {"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isI

				for stampslist in pol_attr: #stampslist = list of 72 checkpoints for the particular protection (udp, tcp-syn etc.) [{'row': {'deviceIp': '10.107.129.206', 'normal': '161.0', 'fullExcluded': '-1.0', 'policyName': 'NIX-NC-EB-dns', 'enrichmentContainer': '{}', 'protection': 'tcp-frag', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620141600000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}, {'row': ....
					currthroughput_list = []
					empty_resp = False
					for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
						row = stamp['row']
	
						if 'response' in row:
							if row['response'] == 'empty':
								print(f'{dp_ip},{dp_name},{policy},' , row['protection'] ,' - no DNS stats ---')
								empty_resp = True
								with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
									traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
									traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', row['protection'] , f'No DNS stats', f'No DNS stats' , 'N/A','N/A','N/A'])

								continue
						if row['normal'] is None:
							normal_baseline = row['normal']
							protoc = row['protection']
							continue

						if row['full'] is None:
							normal_baseline = row['normal']
							protoc = row['protection']
							continue

						normal_baseline = row['normal']
						protoc = row['protection']
						currthroughput = float(row['full'])

						currthroughput_list.append(currthroughput)


					if len(currthroughput_list) and sum(currthroughput_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
						# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))

						top_10_currthroughput_idx = sorted(range(len(currthroughput_list)), key=lambda i: currthroughput_list[i])[-10:]
						top_10_currthroughput_list = [currthroughput_list[i] for i in top_10_currthroughput_idx]
				
						top10_currthroughput_avg = (sum(top_10_currthroughput_list)) / (len(top_10_currthroughput_list))

						
						# DNS Stats collection - max traffic average and normal baseline
						with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
							traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
							traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'{protoc}' , f'{top10_currthroughput_avg}', f'{float(normal_baseline)}' , 'N/A','N/A','N/A'])


					if len(currthroughput_list) and sum(currthroughput_list) ==0: 
						with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
							traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
							traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', f'{protoc}' , f'0', f'{float(normal_baseline)}' , 'N/A','N/A','N/A'])

					if len(currthroughput_list) == 0 and not empty_resp:
							with open(reports_path + 'traffic_stats.csv', mode='a', newline="") as traffic_stats:
								traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								traffic_stats.writerow([f'{dp_ip}' , f'{dp_name}', f'{policy}', row['protection'] , f'DNS stats returned None', f'Normal DNS baseline returned None' , 'N/A','N/A','N/A'])



def parse():

	with open(reports_path + 'traffic_stats.csv', mode='w', newline="") as traffic_stats:
		traffic_stats = csv.writer(traffic_stats, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		traffic_stats.writerow([f'DefensePro IP' , f'DefensePro Name', f'Policy' , f'Protocol', f'Total traffic Max Throughput Average(Mbps/DNS QPS)', f'BDOS Normal Baseline(Mbps/DNS QPS)', f'Total traffic Max PPS Average', f'Total traffic Max CPS Average' , f'Total traffic Max Concurrent Established Average'])


	parseTrafficStatsBPS()
	parseTrafficStatsPPS()
	parseTrafficStatsCPS()
	parseTrafficStatsCEC()
	parseBDOSStats()
	parseDNSStats()

	if os.path.exists(reports_path + "traffic_stats_temp1.csv"):
		os.remove(reports_path + "traffic_stats_temp1.csv")
	if os.path.exists(reports_path + "traffic_stats_temp2.csv"):
		os.remove(reports_path + "traffic_stats_temp2.csv")


	report = reports_path + "traffic_stats.csv"
	return report