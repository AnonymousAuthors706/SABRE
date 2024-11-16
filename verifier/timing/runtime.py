import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv
from scipy import stats

factor = 1
plt.rcParams["figure.figsize"] = (9*factor,36*factor)
font = {'size' : 16*factor}
matplotlib.rc('font', **font)

# apps = ['libbs', 'fibcall', 'lcdnum', 'jfdctint', 'cover', 'crc_32']
apps = [ 'crc_32', 'libbs', 'fibcall', 'cover', 'lcdnum', 'jfdctint', 'compress']
msp_labels = ['bt', 'se', 'la1', 'la2', 'gp', 'ue', 'rc', 'pc', 'sp']
labels = ['Backwards Trace', 'Symbolic Execution Slice', 'Locate addr_init', 'Generate Patches', 'Update ELF', 'Remap CFLog', 'Build Patched CFG', 'Symbolic Exec. Patch']

app_timings = {}
for app in apps:
	app_timings[app] = {}
	app_timings[app]['msp'] = {}
	app_timings[app]['arm'] = {}
	app_timings[app]['msp-raw'] = {}
	app_timings[app]['arm-raw'] = {}
	for module in labels:
		app_timings[app]['msp-raw'][module] = []
		app_timings[app]['arm-raw'][module] = []

msp_timings = {}
for module in labels:
	msp_timings[module] = {}
	msp_timings[module]['means'] = []
	msp_timings[module]['stdev'] = []

arm_timings = {}
for module in labels:
	arm_timings[module] = {}
	arm_timings[module]['means'] = []
	arm_timings[module]['stdev'] = []

msp_end_to_end = [0]*len(apps)
arm_end_to_end = [0]*len(apps)

app_idx = 0
for app in apps:

	str_data = list(csv.reader(open(f'./msp430/{app}.csv')))
	data = []
	for str_row in str_data:
		float_row = [float(x) for x in str_row]
		float_row = float_row[:2] + [float_row[2]+float_row[3]] + float_row[4:] # combine la1 and la2 for msp430
		data.append(float_row)

	arm_str_data = list(csv.reader(open(f'./arm/{app}.csv')))
	arm_data = []
	for str_row in arm_str_data:
		float_row = [float(x) for x in str_row]
		arm_data.append(float_row)

	data = np.array(data)
	for row in data:
		for i in range(0, len(row)):
			module = labels[i]
			app_timings[app]['msp-raw'][module].append(row[i])


	arm_data = np.array(arm_data)
	for row in arm_data:
		for i in range(0, len(row)):
			module = labels[i]
			app_timings[app]['arm-raw'][module].append(row[i])


	means = np.mean(data, axis=0)
	# stdev = np.std(data, axis=0)
	stdev = stats.sem(data, axis=0)
	for i in range(0, len(labels)):
		module = labels[i]
		msp_timings[module]['means'].append(means[i])
		msp_timings[module]['stdev'].append(stdev[i])
		app_timings[app]['msp'][module] = means[i]
	msp_end_to_end[app_idx] = np.sum(means)

	means = np.mean(arm_data, axis=0)
	stdev = stats.sem(arm_data, axis=0)
	for i in range(0, len(labels)):
		module = labels[i]
		arm_timings[module]['means'].append(means[i])
		arm_timings[module]['stdev'].append(stdev[i])
		app_timings[app]['arm'][module] = means[i]	
	arm_end_to_end[app_idx] = np.sum(means)
	
	app_idx += 1

print('-----------------------------------')
print('--------- MSP430 Timing -----------')
mspFile = open('msp430_means.csv', 'w')
wr = csv.writer(mspFile)
wr.writerow(apps)
for module in msp_timings.keys():
	print(f"{module} : ")
	wr.writerow([round(x, 4) for x in msp_timings[module]['means']])
	for stat in msp_timings[module].keys():
		print(f"\t{stat} : {msp_timings[module][stat]}")
mspFile.close()

print('-----------------------------------')
print('----------- ARM Timing ------------')
armFile = open('arm_means.csv', 'w')
wr = csv.writer(armFile)
wr.writerow(apps)
for module in arm_timings.keys():
	print(f"{module} : ")
	wr.writerow([round(x, 4) for x in arm_timings[module]['means']])
	for stat in arm_timings[module].keys():
		print(f"\t{stat} : {arm_timings[module][stat]}")
armFile.close()
print('-----------------------------------')

# for key in app_timings.keys():
# 	print(f"{key} : ")
# 	for k2 in app_timings[key].keys():
# 		print(f"\t{k2} : ")
# 		for k3 in app_timings[key][k2].keys():
# 			print(f"\t\t{k3} : {app_timings[key][k2][k3]}")

# print('-----------------------------------')


# print(len(slice_addrs_arm))
# print(len(arm_end_to_end))
# plt.scatter(slice_addrs_arm, arm_end_to_end)
# plt.show()

a = input()
#'''
w = 1
bar_width = 0.3
# module = 'BT'
for i in range(0, len(labels)):
	module = labels[i]
	box_data = []
	print(f"{module} : ")
	for app in apps:
		normalized = np.array(app_timings[app]['msp-raw'][module])/np.sum(np.array(app_timings[app]['msp-raw'][module]))
		print(f"\t{app} :  ")
		print(f"\t\tQ1 : {np.quantile(normalized, .25)}")
		print(f"\t\tQ2 : {np.quantile(normalized, .50)}")
		print(f"\t\tQ3 : {np.quantile(normalized, .75)}")
		box_data.append(normalized)
	# print(box_data[0].shape)
	#'''
	# 	# box_data.append(app_timings[app]['arm-raw'][module])
	fig, axes = plt.subplots(len(apps),1,sharex=True)
	print(axes)
	# break

	fig.suptitle(module)
	# counts, bins = np.histogram(box_data, bins=25)
	# print(f"counts {len(counts)}: {counts}\n")
	# print(f"bins {len(bins)}: {bins}\n")
	# plt.bar(bins[:-1], counts)
	# plt.title(module)
	for i in range(0, len(apps)):
		axes[i].set_title(apps[i])
		axes[i].hist(box_data[i], 50, density=True, histtype='bar')
	# plt.legend()
	# plt.boxplot(box_data)
	# plt.xticks(np.arange(len(apps))+1, apps)
	
	# x = np.arange(len(apps))
	# plt.xticks(x, apps)
	# plt.ylabel('Time (ms)')
	
	# print(f"module : {module}")
	# print(f"x : {len(x)}")
	# print(f"means : {len(msp_timings[module]['means'])}")
	# print(f"stdev : {len(msp_timings[module]['stdev'])}")
	# plt.bar(x-0.5*bar_width, msp_timings[module]['means'], yerr=msp_timings[module]['stdev'], width=bar_width, color='white', edgecolor='black')
	# plt.bar(x+0.5*bar_width, arm_timings[module]['means'], yerr=arm_timings[module]['stdev'], width=bar_width, color='grey', edgecolor='black')

	# # Show the plot
	# plt.tight_layout()
	fig.subplots_adjust(hspace=0.5)
	plt.show()
	
	#'''

normal_data = np.random.normal(71, 2, 525)
# print(normal_data)
uniform_data = np.random.uniform(65, 77, 525)
 
fig = plt.figure(figsize =(10, 7))
 
data = [normal_data, uniform_data]

# Creating plot
# plt.boxplot(data)
# plt.xticks(np.arange(2)+1, ['Normal, Uniform'])

# show plot
# plt.show()
