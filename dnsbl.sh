#!/bin/bash
# Check if an IP address is listed on one of the following blacklists
# The format is chosen to make it easy to add or delete
# The shell will strip multiple whitespace

BLISTS="
0spam.fusionzero.com
access.redhawk.org
all.rbl.jp
all.s5h.net
all.spamrats.com
aspews.ext.sorbs.net
backscatter.spameatingmonkey.net
bad.psky.me
b.barracudacentral.org
blacklist.woody.ch
bl.blocklist.de
bl.drmx.org
bl.fmb.la
bl-ip.rbl.scrolloutf1.com
bl.konstant.no
bl.mailspike.net
bl.mav.com.br
bl.nszones.com
bl.scientificspam.net
bl.score.senderscore.com
bl.spamcop.net
bl.spameatingmonkey.net
bl.spamstinks.com
bogons.cymru.com
cbl.abuseat.org
cblplus.anti-spam.org.cn
cidr.bl.mcafee.com
cidr.bl.mcafee.com
db.wpbl.info
dnsbl-1.uceprotect.net
dnsbl.anticaptcha.net
dnsbl.calivent.com.pe
dnsbl.cobion.com
dnsbl.dronebl.org
dnsbl.forefront.microsoft.com
dnsbl.inps.de
dnsbl.justspam.org
dnsbl.kempt.net
dnsbl.madavi.de
dnsbl.net.ua
dnsbl.rv-soft.info
dnsbl.rymsho.ru
dnsbl.sorbs.net
dnsbl.spfbl.net
dnsbl.tornevall.org
dnsbl.zapbl.net
dnsrbl.org
dnsrbl.swinog.ch
dul.pacifier.net
exitnodes.tor.dnsbl.sectoor.de
fnrbl.fast.net
free.v4bl.org
ip.v4bl.org
ix.dnsbl.manitu.net
korea.services.net
list.blogspambl.com
mail-abuse.blacklist.jippg.org
netbl.spameatingmonkey.net
nosolicitado.org
pofon.foobar.hu
psbl.surriel.com
query.senderbase.org
rbl2.triumf.ca
rbl.abuse.ro
rbl.blockedservers.com
rbl.dns-servicios.com
rbl.efnetrbl.org
rbl.interserver.net
rbl.megarbl.net
rbl.realtimeblacklist.com
rbl.talkactive.net
rep.mailspike.net
rf.senderbase.org
rhsbl.zapbl.net
sa.senderbase.org
score.senderscore.com
spam.dnsbl.anonmails.de
spam.dnsbl.sorbs.net
spamguard.leadmon.net
spamlist.or.kr
spam.pedantic.org
spamrbl.imp.ch
spamsources.fabel.dk
srn.surgate.net
stabl.rbl.webiron.net
st.technovision.dk
tor.dnsbl.sectoor.de
torexit.dan.me.uk
truncate.gbudb.net
ubl.unsubscore.com
uribl.abuse.ro
wormrbl.imp.ch
zen.spamhaus.org
"

# simple shell function to show an error message and exit
#  $0  : the name of shell script, $1 is the string passed as argument
# >&2  : redirect/send the message to stderr

ERROR() {
  echo $0 ERROR: $1 >&2
  exit 2
}

# -- Sanity check on parameters
[ $# -ne 1 ] && ERROR 'Please specify a single IP address'

# -- if the address consists of 4 groups of minimal 1, maximal digits, separated by '.'
# -- reverse the order
# -- if the address does not match these criteria the variable 'reverse will be empty'

reverse=$(echo $1 |
  sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")

if [ "x${reverse}" = "x" ] ; then
      ERROR  "IMHO '$1' doesn't look like a valid IP address"
      exit 1
fi

# Assuming an IP address of 11.22.33.44 as parameter or argument

# If the IP address in $0 passes our crude regular expression check,
# the variable  ${reverse} will contain 44.33.22.11
# In this case the test will be:
#   [ "x44.33.22.11" = "x" ]
# This test will fail and the program will continue

# An empty '${reverse}' means that shell argument $1 doesn't pass our simple IP address check
# In that case the test will be:
#   [ "x" = "x" ]
# This evaluates to true, so the script will call the ERROR function and quit

# -- do a reverse ( address -> name) DNS lookup
REVERSE_DNS=$(dig +short -x $1)

# echo IP $1 NAME ${REVERSE_DNS:----}

# # -- cycle through all the blacklists
# for BL in ${BLISTS} ; do
#     # use dig to lookup the name in the blacklist
#     #echo "$(dig +short -t a ${reverse}.${BL}. |  tr '\n' ' ')"
#     LISTED="$(dig +short -t a ${reverse}.${BL}.)"
#     if [[ -n $LISTED ]]; then
#       # show the reversed IP and append the name of the blacklist
#       printf "%-60s" "    ${reverse}.${BL}."
#       echo ${LISTED}
#     fi
# done


# -- cycle through all the blacklists
for BL in ${BLISTS} ; do
    # use dig to lookup the name in the blacklist
    #echo "$(dig +short -t a ${reverse}.${BL}. |  tr '\n' ' ')"
    LISTED="$(dig +short -t a ${reverse}.${BL}.)"
    if [[ -n $LISTED ]]; then
      # checks if it is SenderScore Reputationlist
      # if the score is greater than 50, continue
      if [[ "$BL" = "score.senderscore.com" ]]; then
        SCORE=$(echo "$LISTED" | sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4~p")
        if [[ $SCORE -ge 50 ]]; then
          continue
        fi
      fi
      # checks if the BL is Mailspike reputationlist
      # if the score is lower than 15, it is tagged as spam
      if [[ "$BL" = "rep.mailspike.net" ]]; then
        SCORE=$(echo "$LISTED" | sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4~p")
        if [[ $SCORE -ge 15 ]]; then
          continue
        fi
      fi
      
      # show the reversed IP and append the name of the blacklist
      printf "%-60s" "${reverse}.${BL}."
      echo $LISTED
    fi
done