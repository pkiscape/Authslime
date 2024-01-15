
#=========================================================
# Authslime
# Slime Stats  
# Information about the slimes and others
#=========================================================

import numpy
import matplotlib.pyplot as plt
from statistics import mean

def slime_creation_graph(create_time, loop_number, slime_time_list):

	loop_count = float(loop_number)
	avg = mean(slime_time_list)
	print("Average Slime creation time: " + str(avg))
	
	x = numpy.arange(0,loop_count)
	y = slime_time_list

	plt.title("Slime Creation Times") 
	plt.xlabel("Number of Slimes") 
	plt.ylabel("Slime Creation Time (seconds)")
	plt.plot(x, y, color ="blue")
	plt.show()	



def slime_rare_detector(slime_list, accessories):

	rare_list = []
	name = slime_list[3]
	color = slime_list[4]
	
	#Rare Color
	rare_color_list = [" #000000","#FFFFFF"]

	if color in rare_color_list:
		rare_list.append(color)
		print(f"Rare color: {color} for {name}!")

	#Rare Accessories
	rare_accessory_list = ["golden sunglasses","robin hood hat", "santa hat", "crown", "golden top hat"]
	
	for accessory in accessories:
		if accessory in rare_accessory_list:
			rare_list.append(accessory)
			print(f"Rare Item: {accessory} for {name}!")
			
	return rare_list





