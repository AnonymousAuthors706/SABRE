# SCRIPT FOR RUNNING TESTS

if [[ $1 == "msp430" ]]; then

	app=$3
	path="../ACFA/beebs/"${app}"/attack/"

	cflog_file=${path}"combined.cflog"
	echo RUNNING beebs/${app}

	input_file=${path}"tcb.lst"
	input_elf=${path}"tcb.elf"
	arch_type="elf32-msp430"
	funcname="main"
	OBJDUMP=msp430-objdump
	stack="__stack"

	sed -i 's/Disassembly of section .empty://g' ${input_file}
	
elif [[ $1 == "arm" ]]; then

	app=$3
	path="../ISC-FLAT/beebs/"${app}"/"

	input_file=${path}"app.list"
	cflog_file=${path}"0.cflog"
	input_elf=${path}"app.elf"

	arch_type="armv8-m33"
	funcname="application"
	OBJDUMP=arm-none-eabi-objdump
	stack="_estack"
	# get data from pmem
	grep "word" ${input_file} > .words.tmp
	awk {'print $1, $2'} .words.tmp > .words.tmp2
	sed 's/:/,/g' .words.tmp2 > ./objs/.words
	rm .words.tmp .words.tmp2
	sed -i '/.word/d' ./objs/.words #remove any mess caused by listing file
	arm-none-eabi-objdump -d ${input_elf} > ${path}beebs.lst
else 
	echo "Use argument 'msp430' or 'arm'"
	exit
fi
echo "Path: " ${path}
echo "Input file: " ${input_file}
echo "Input file: " ${input_elf}

# try to get init stack pointer val 
${OBJDUMP} -dt ${input_elf} | grep ${stack} | awk '{print $1}' > ./objs/.sp

# try to get initial values for data
${OBJDUMP} -t ${input_elf} | grep "O \.data" | sort -k1,1 | awk '{print $1, $5}' > ./objs/.data.objs
${OBJDUMP} -t ${input_elf} | grep "O \.bss" | sort -k1,1 | awk '{print $1, $5}' > ./objs/.bss.objs
${OBJDUMP} -s -j .data ${input_elf} | tail -n +5 | awk '{print $2$3$4$5}' > ./objs/.data
${OBJDUMP} -s -j .rodata ${input_elf} | tail -n +5 | awk '{print $1}' > ./objs/.rodata.start
${OBJDUMP} -s -j .rodata ${input_elf} | tail -n +5 | awk '{print $2$3$4$5}' > ./objs/.rodata

touch ./logs/timingdata.log

echo "Building app CFG..."
echo python3 generate_cfg.py --asmfile ${input_file} --arch ${arch_type} --cfgfile ./objs/cfg.bin
python3 generate_cfg.py --asmfile ${input_file} --arch ${arch_type} --cfgfile ./objs/cfg.bin
echo "Done"

echo "Running SABRE..."
echo  ${input_elf} patched.elf
cp  ${input_elf} patched.elf
python3 sabre.py --cfgfile ./objs/cfg.bin --cflog ${cflog_file} --funcname ${funcname}
echo "Done"
