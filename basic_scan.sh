#!/bin/bash

file="subdomains_alive.txt"
clean="false"
threads=30
while [ $# -gt 0 ] ; do
	opt="$1"
	case $opt in
		-c)
			$clean="true"
			shift
			;;
		-f)
			$file="$2"
			shift
			shift
			;;
		-t)
			$threads=$2 
			shift
			shift
			;;
		*)
			shift
			;;
	esac
done


if [ $clean == "true" ] ; then
	rm nuclei.log awsbuckets.txt s3scan.log subjack.log smuggler.log
fi


echo ">> Running nuclei....."
nuclei -t /opt/nuclei-templates -exclude /opt/nuclei-templates/misc -c $threads -l $file -o nuclei.log


if [ -f nmap.log ] ; then
	grep -s -o "[A-Za-z0-9\-]*\.[A-Za-z0-9\-]*\.amazonaws.com$" nmap.log | sort -u > awsbuckets.txt
	if [ -f awsbuckets.txt ] ; then
		echo ">> Scanning for open AWS buckets....."
		python3 /opt/S3Scanner/s3scanner.py -o s3scan.log -d -l awsbuckets.txt 
	fi
fi


echo ">> Running subjack....."
subjack -w $file -ssl -a -t $threads -o subjack.log -c /opt/subjack/fingerprints.json


echo ">> Scanning for desync vulnerabilities....."
cat $file | python3 /opt/smuggler/smuggler.py -q -l smuggler.log

