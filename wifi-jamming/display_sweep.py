#!/bin/python3

import pandas
import matplotlib.pyplot as plt
import subprocess as sp

try:
	#Fast result = sp.Popen(['hackrf_sweep', '-f', '2401:2483', '-w', '22', '-r' , 'tempfilename.csv'], stdout=sp.PIPE, stderr=sp.PIPE)
	result = sp.Popen(['hackrf_sweep', '-f', '2401:2483', '-a', '1', '-r' , 'tempfilename.csv'], stdout=sp.PIPE, stderr=sp.PIPE)
	print(result)
	result.wait(timeout=20)
except:
	print("20s elapsed")

inputfile = open('tempfilename.csv', 'r')
eofinputfile = True
y = {}
while eofinputfile:
	line = inputfile.readline()
	#print(line)
	if not line:
		eofinputfile = False
	else:
		linelist = line.split(', ')
		#print(linelist)
		if len(linelist) == 11:
			for i in range(0, 5):
				#x.append(int(linelist[2])+(1e6*i))
				#y.append(linelist[6+i])
				if not int(linelist[2])+(1e6*i) in y.keys():
					y[int(linelist[2])+(1e6*i)] = float(linelist[6+i])
				else:
					meany = (y[int(linelist[2])+(1e6*i)] + float(linelist[6+i]))/2
					y[int(linelist[2])+(1e6*i)] = meany
				#print(x[-1], y[-1])
print(len(y.values()))
#print(sorted(y))
ysort = [y[x] for x in sorted(y)]
barx = [2412e6, 2417e6, 2422e6, 2427e6, 2432e6, 2437e6, 2442e6, 2447e6, 2452e6, 2457e6, 2462e6, 2467e6, 2472e6, 2484e6]
channels = {'ch1': ([2401e6, 2423e6], 'g'), 'ch2': ([2406e6, 2428e6], 'y'), 'ch3': ([2411e6, 2433e6], 'b'), 'ch4': ([2416e6, 2438e6], 'm'), 'ch5': ([2421e6, 2443e6], 'c'), 'ch6': ([2426e6, 2448e6], 'k'), 'ch7': ([2431e6, 2453e6], 'g'), 'ch8': ([2436e6, 2458e6], 'y'), 'ch9': ([2441e6, 2463e6], 'b'), 'ch10': ([2446e6, 2468e6], 'm'), 'ch11': ([2451e6, 2473e6], 'c'), 'ch12': ([2456e6, 2478e6], 'k'), 'ch13': ([2461e6, 2483e6], 'g')}
plt.step(sorted(y),ysort,'r-')
#for bar in barx:
#	plt.axvline(x=bar, 'r')
for ch in channels.keys():
	for bar in channels[ch][0]:
		plt.axvline(x=bar, color=channels[ch][1], label=ch)
plt.show()
