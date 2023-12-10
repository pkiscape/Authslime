#=========================================================
# Authslime
# Slime Image Creator  
# Actions for creating the Authslime Image
#=========================================================

import io
from PIL import Image, ImageDraw, ImageFont


'''
Slime image details:
768 x 768
'''

def drawslime(slimeid,version,name,color,template,accessories,publickey_digest,images):
	'''
	Creates a slime image based on its attributes
	'''

	slimeid = str(slimeid)

	bigfont = ImageFont.truetype("etc/LiberationMono-Regular.ttf", 34)
	mediumfont = ImageFont.truetype("etc/LiberationMono-Regular.ttf", 16)
	smallfont = ImageFont.truetype("etc/LiberationMono-Regular.ttf", 14)
	tinyfont = ImageFont.truetype("etc/LiberationMono-Regular.ttf", 11)
	#-------------Image-------------
	
	#Choose Template
	if template == 1:
		template_image = Image.open("etc/templates/template1.png")
	if template == 2:
		template_image = Image.open("etc/templates/template2.png")
	if template == 3:
		template_image = Image.open("etc/templates/template3.png")

	#Put Color on the template
	slime_image = Image.new("RGBA", template_image.size, color)
	slime_image.paste(template_image, (0, 0), template_image) 
	text_select = ImageDraw.Draw(slime_image)

	'''
	Choose accessories

	Hat slot: "sunhat","top hat","wizard hat","robin hood hat", "santa hat", "crown", "golden top hat"
	Other slot: "sunglasses","long beard","mustache","golden sunglasses"
	'''
	# Hats
	if "sunhat" in accessories:
		sunhat_image = Image.open("etc/accessories/sunhat.png")
		slime_image.paste(sunhat_image, sunhat_image)

	if "top hat" in accessories:
		tophat_image = Image.open("etc/accessories/tophat.png")
		slime_image.paste(tophat_image, tophat_image)

	if "wizard hat" in accessories:
		wizardhat_image = Image.open("etc/accessories/wizardhat.png")
		slime_image.paste(wizardhat_image, wizardhat_image)
	
	if "robin hood hat" in accessories:
		robinhoodhat_image = Image.open("etc/accessories/robinhoodhat.png")
		slime_image.paste(robinhoodhat_image, robinhoodhat_image)	

	if "santa hat" in accessories:
		santahat_image = Image.open("etc/accessories/santahat.png")
		slime_image.paste(santahat_image, santahat_image)

	if "crown" in accessories:
		crown_image = Image.open("etc/accessories/crown.png")
		slime_image.paste(crown_image, crown_image)	

	if "golden top hat" in accessories:
		goldentophat_image = Image.open("etc/accessories/goldentophat.png")
		slime_image.paste(goldentophat_image, goldentophat_image)

	# Other
	if "sunglasses" in accessories:
		sunglasses_image = Image.open("etc/accessories/sunglasses.png")
		slime_image.paste(sunglasses_image, sunglasses_image)

	if "mustache" in accessories:
		mustache_image = Image.open("etc/accessories/mustache.png")
		slime_image.paste(mustache_image, mustache_image)
			
	if "golden sunglasses" in accessories:
		goldensunglasses_image = Image.open("etc/accessories/goldensunglasses.png")
		slime_image.paste(goldensunglasses_image, goldensunglasses_image)	


	common = ["sunglasses","sunhat"]
	uncommon = ["top hat", "wizard hat","mustache"]
	rare = ["robin hood hat", "santa hat", "crown", "golden top hat", "golden sunglasses"]

	accessory_text_list = []

	for accessory in accessories:
		if accessory in common:
			accessory_text_list.append(f"{accessory.title()} (Common)")

		if accessory in uncommon:
			accessory_text_list.append(f"{accessory.title()} (Uncommon)")

		if accessory in rare:
			accessory_text_list.append(f"{accessory.title()} (Rare)")

	#Write text
	text_select.text((392, 620), name, fill=(0, 0, 0),font=bigfont,anchor="mm")
	text_select.text((392, 648), slimeid, fill=(0, 0, 0),font=mediumfont,anchor="mm")
	text_select.text((392, 668), "SHA256 Digest of Public Key", fill=(0, 0, 0),font=smallfont,anchor="mm")
	text_select.text((392, 682), publickey_digest, fill=(0, 0, 0),font=tinyfont,anchor="mm")
	
	accessory_position_x = 392
	accessory_position_y = 696

	if accessory_text_list:
		text_select.text((accessory_position_x, accessory_position_y), "Items", fill=(0, 0, 0),font=smallfont,anchor="mm")
		for accessory_text in accessory_text_list:
			accessory_position_y = accessory_position_y + 12
			text_select.text((accessory_position_x, accessory_position_y), accessory_text, fill=(0, 0, 0),font=tinyfont,anchor="mm")

	text_select.text((138, 726), "Version: " + str(version), fill=(0, 0, 0),font=smallfont,anchor="mm")
	text_select.text((616, 726), "Color: " + color, fill=(0, 0, 0),font=smallfont,anchor="mm")

	#Save Authslime to JPG
	if images:
		authslime_image	= slime_image.convert('RGB').save("img/"+slimeid+'.jpg', "JPEG") 
	
	#Save Authslime to in-memory Buffer
	buffer = io.BytesIO()
	slime_image = slime_image.convert('RGB') #Cannot write mode RGBA as JPEG
	slime_image.save(buffer, format='JPEG')
	in_memory_authslime_image = buffer.getvalue()

	return in_memory_authslime_image
