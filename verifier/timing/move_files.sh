apps=('lcdnum' 'libbs' 'fibcall' 'cover' 'jfdctint' 'compress' 'crc_32')
mcus=('msp430' 'arm')
# apps=('cover')
# mcus=('arm')

# msp430 headers
#  back trace, symb exec, loc addr_init 1, loc addr_init 2, gen patch, update elf, remap cflog, patch cfg, symb patch

# arm headers:
# back trace, symb exec, loc addr_init, gen patch, update elf, remap cflog, patch cfg, symb patch

# app='lcdnum'
for app in "${apps[@]}"
do
	for mcu in "${mcus[@]}"
	do
		head './combined/'${mcu}'/'${app}'.csv' -n 525 > './0_525/'${mcu}'/'${app}'.csv'
		tail './combined/'${mcu}'/'${app}'.csv' -n 533 > './1_533/'${mcu}'/'${app}'.csv'
	done
done
