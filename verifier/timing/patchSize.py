import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv
from scipy import stats

factor = 1
plt.rcParams["figure.figsize"] = (9*factor,3*factor)
font = {'size' : 16*factor}
matplotlib.rc('font', **font)

msp_original = np.array([123, 80, 79, 351, 58, 576, 2940])/1000
msp_patched = np.array([147, 105, 103, 376, 82, 600, 3184])/1000

arm_original = np.array([5228,5692,5308,7292,14268,7292,6796])/1000
arm_patched = np.array([5376,5840,5456,7440,14416,7440,6944])/1000

apps = ['libbs', 'fibcall', 'cover', 'lcdnum', 'jfdctint', 'compress', 'crc_32']

bar_width = 0.25

labels = ['Original', 'Patched']

#----------- MSP430 ---------------#
plt.title("MSP430 Binary Size Comparison ")
x = np.arange(len(apps))
# plt.legend(labels)
plt.xticks(x, apps)
plt.ylabel('Size (KB)')
plt.bar(x-0.5*bar_width, msp_original, width=bar_width, color='white', edgecolor='black', label=labels[0])
plt.bar(x+0.5*bar_width, msp_patched, width=bar_width, color='grey', edgecolor='black', label=labels[1])

# # Show the plot
plt.tight_layout()
plt.show()
plt.clf()

#----------- ARM ---------------#
plt.title("ARM Cortex-M33 Binary Size Comparison ")
x = np.arange(len(apps))
plt.xticks(x, apps)
plt.ylabel('Size (KB)')
plt.legend(labels)
plt.bar(x-0.5*bar_width, arm_original, width=bar_width, color='grey', edgecolor='black', label=labels[0])
plt.bar(x+0.5*bar_width, arm_patched, width=bar_width, color='white', edgecolor='black', label=labels[1])
plt.legend(labels)
plt.tight_layout()
plt.show()
plt.clf()

#-------- One plot per app version -------#