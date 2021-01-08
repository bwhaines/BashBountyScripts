#!/bin/bash

altlist=/usr/share/wordlists/altdns_list.txt
dirlilst=/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
reslist=/opt/SecLists/Miscellaneous/dns-resolvers.txt


################################
####### ARGUMENT PARSING #######
################################
asn=""
urllist=""
if [ -f seeds.txt ] ; then
	urllist="seeds.txt"
fi
urlblocklist=""
if [ -f blocklist.txt ] ; then
	urlblocklist="blocklist.txt"
fi
threads=30
scanlevel=1
clean="false"
while [ $# -gt 0 ] ; do
	opt="$1"
	case $opt in
		-a)
			asn=$2
			shift
			shift
			;;
		-b)
			urlblocklist="$2"
			shift
			shift
			;;
		-c)
			clean="true"
			shift
			;;
		-s)
			scanlevel=$2
			shift
			shift
			;;
		-t)
			threads=$2
			shift
			shift
			;;
		-u)
			urllist="$2"
			shift
			shift
			;;
		*)
			shift
			;;
	esac
done

if [ $urllist == "" ] ; then
	echo "Please put URLs in seeds.txt or supply a filename with -u"
	exit
fi

echo "ASN: $asn"
echo "URLLIST: $urllist"
echo "URLBLOCKLIST: $urlblocklist"
echo "THREADS: $threads"
echo "SCAN LEVEL: $scanlevel"
echo "CLEAN RUN: $clean"
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>"


################################
########## CLEAN FILES #########
################################
if [ $clean == "true" ] ; then
	rm subdomains*.* *_urls.txt stats.txt nmap.log
	rm -rf gospider_output eyewitness_output
fi


################################
########### ASN ENUM ###########
################################
if [ $asn ] ; then
	echo ">> Searching ASN....."
	amass intel -asn $asn -active >> $urllist
	sort -u $urllist -o $urllist
fi


################################
######## SUBDOMAIN ENUM ########
################################
echo ">> Running subfinder....."
subfinder -dL $urllist -rL $reslist -nW -silent -max-time 30 -o subdomains.txt
echo "subfinder: `wc -l < subdomains.txt`" >> stats.txt


################################
######### SUBDOMAIN GEN ########
################################
if [ $scanlevel -ge 2 ] ; then
	echo ">> Generating potential subdomains and doing DNS resolution....."
	dnsgen subdomains.txt -w $altlist | massdns -r $reslist -q -o S | sed 's/\. .*//' > subdomains_gen.txt
	if [ -f subdomains_gen.txt ] ; then
		echo "dnsgen: `wc -l < subdomains_gen.txt`" >> stats.txt
		cat subdomains_gen.txt >> subdomains.txt
		sort -u subdomains.txt -o subdomains.txt
	fi
fi


################################
####### BLOCK LIST FILTER ######
################################
if [ -f $urlblocklist ] ; then
	cat $urlblocklist | while read url; do
		sed -i "/$url/d" subdomains.txt
	done
fi


################################
######## LIVE SITE PROBE #######
################################
echo ">> Filtering out unresponsive sites....."
cat subdomains.txt | httpx -silent -threads $threads > subdomains_alive.txt
echo "httpx: `wc -l < subdomains_alive.txt`" >> stats.txt


################################
######### SITE CRAWLING ########
################################
if [ $scanlevel -ge 2 ] ; then
	echo ">> Running GoSpider....."
	gospider -S subdomains_alive.txt -t $threads -q -o gospider_output | sort -u > crawled_urls.txt
	echo "gospider: `wc -l < crawled_urls.txt`" >> stats.txt
	echo ">> Running waybackurls....."
	cat subdomains.txt | waybackurls | sed -E '/.*\.(png|jpg|jpeg|gif|ico|tiff|css)/d' > wayback_urls.txt
	echo "wayback: `wc -l < wayback_urls.txt`" >> stats.txt
fi


################################
######### BRUTE FORCING ########
################################
if [ $scanlevel -ge 3 ] ; then
	echo ">> Running gobuster....."
	cat subdomains_alive.txt | while read url ; do
		gobuster -d -e -q -t $threads -u $url -w $dirlist >> forced_urls.txt
	done
	echo "gobuster: `wc -l < forced_urls.txt`" >> stats.txt
fi


################################
########## SCREENSHOTS #########
################################
#if [ ! -d eyewitness_output/ ] ; then
#	mkdir eyewitness_output/
#fi 
#if [ $scanlevel -ge 3 ] ; then
#	echo ">> Screenshotting crawled and brute-forced pages....."
#	sort -u *_urls.txt -o total_urls.txt
#	/opt/EyeWitness/Python/EyeWitness.py -f total_urls.txt -d eyewitness_output/ --web --no-prompt --threads $threads
#elif [ $scanlevel -eq 2 ] ; then
#	echo ">> Screenshotting subdomain pages....."
#	/opt/EyeWitness/Python/EyeWitness.py -f subdomains_alive.txt -d eyewitness_output/ --web --no-prompt --threads $threads
#fi


################################
######### PORT SCANNING ########
################################
echo ">> Scanning IPs for open ports....."
if [ $scanlevel -eq 1 ] ; then
	nmap -iL subdomains.txt -T4 -A --top-ports 100 --max-parallelism $threads | tee nmap.log
elif [ $scanlevel -eq 2 ] ; then
	nmap -iL subdomains.txt -T4 -A --top-ports 1000 --max-parallelism $threads | tee nmap.log
elif [ $scanlevel -ge 3 ] ; then
	nmap -iL subdomains.txt -T4 -A -p- --max-parallelism $threads | tee nmap.log
fi

