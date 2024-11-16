apps=('lcdnum' 'libbs' 'fibcall' 'cover' 'jfdctint' 'aha-compress' 'crc_32')
mcus=('arm')
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
		rm ./logs/timingdata.log
		touch ./logs/timingdata.log
		for (( i = 0; i < $1; i++)); do
			./run.sh $mcu $app
			rm ./objs/*.bin
		done
		# mv './logs/timingdata.log' './timing/'${mcu}'/'${app}'.csv'
		cat './logs/timingdata.log' >> './timing/uaf/'${mcu}'/'${app}'.csv'
	done
done

# cat './timing/msp430/aha-compress.csv' >> './timing/msp430/compress.csv'
# rm  './timing/msp430/aha-compress.csv'

cat './timing/arm/aha-compress.csv' >> './timing/arm/compress.csv'
rm  './timing/arm/aha-compress.csv'
