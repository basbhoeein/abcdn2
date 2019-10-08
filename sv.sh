#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="6.0"

#颜色信息
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

#check root
[ $(id -u) != "0" ] && { echo "${Error}错误: 您必须以root用户运行此脚本"; exit 1; }

clear
#############系统检测组件#############
#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	fi
	#检查版本
	if [[ -s /etc/redhat-release ]]; then
		version=`grep -oE  "[0-9.]+" /etc/redhat-release | cut -d . -f 1`
	else
		version=`grep -oE  "[0-9.]+" /etc/issue | cut -d . -f 1`
	fi
	#检查位数
	bit=`uname -m`
	#检查系统安装格式
	if [ -f "/usr/bin/yum" ] && [ -f "/etc/yum.conf" ]; then
		PM="yum"
	elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
		PM="apt-get"		
	fi
}
#获取IP
get_ip(){
	local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
	[ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
	[ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
	[ ! -z ${IP} ] && echo ${IP} || echo
}
get_char(){
	SAVEDSTTY=`stty -g`
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $SAVEDSTTY
}
#防火墙配置
firewall_restart(){
	if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
		firewall-cmd --reload
	else
		if [[ ${release} == "centos" ]]; then
			service iptables save
			service ip6tables save
		else
			iptables-save > /etc/iptables.up.rules
			ip6tables-save > /etc/ip6tables.up.rules
		fi
	fi
	echo -e "${Info}防火墙设置完成,2秒后进行下一步"
	sleep 2s
}
add_firewall(){
	if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
		firewall-cmd --get-active-zones
		firewall-cmd --permanent --zone=public --add-port=${port}/tcp > /dev/null 2>&1
		firewall-cmd --permanent --zone=public --add-port=${port}/udp > /dev/null 2>&1
	else
		iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
		iptables -I INPUT -p udp --dport ${port} -j ACCEPT
		ip6tables -I INPUT -p tcp --dport ${port} -j ACCEPT
		ip6tables -I INPUT -p udp --dport ${port} -j ACCEPT
	fi
}
delete_firewall(){
	if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
		firewall-cmd --get-active-zones
		firewall-cmd --permanent --zone=public --remove-port=${port}/tcp > /dev/null 2>&1
		firewall-cmd --permanent --zone=public --remove-port=${port}/udp > /dev/null 2>&1
	else
		iptables -I INPUT -p tcp --dport ${port} -j DROP
		iptables -I INPUT -p udp --dport ${port} -j DROP
		ip6tables -I INPUT -p tcp --dport ${port} -j DROP
		ip6tables -I INPUT -p udp --dport ${port} -j DROP
	fi
}
#安装Docker
install_docker(){
	#安装docker
	if [ -x "$(command -v docker)" ]; then
		echo "${Info}您的系统已安装docker"
	else
		echo "${Info}开始安装docker..."
		docker version > /dev/null || curl -fsSL get.docker.com | bash
		service docker restart
		systemctl enable docker 
	fi
	#安装Docker环境
	if [ -x "$(command -v docker-compose)" ]; then
		echo "${Info}系统已存在Docker环境"
	else
		echo "${Info}正在安装Docker环境..."
		curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
		chmod +x /usr/local/bin/docker-compose
	fi
}
	
###########超级VPN一键设置#############
#安装V2ray
install_v2ray(){
	#!/bin/bash
	# Author: Jrohy
	# github: https://github.com/Jrohy/multi-v2ray

	#定时任务北京执行时间(0~23)
	BEIJING_UPDATE_TIME=3

	#记录最开始运行脚本的路径
	BEGIN_PATH=$(pwd)

	#安装方式, 0为全新安装, 1为保留v2ray配置更新
	INSTALL_WAY=0

	#定义操作变量, 0为否, 1为是
	HELP=0
	REMOVE=0
	CHINESE=0
	BASE_SOURCE_PATH="https://raw.githubusercontent.com/Jrohy/multi-v2ray/master"
	CLEAN_IPTABLES_SHELL="$BASE_SOURCE_PATH/v2ray_util/global_setting/clean_iptables.sh"
	BASH_COMPLETION_SHELL="$BASE_SOURCE_PATH/v2ray.bash"
	UTIL_CFG="$BASE_SOURCE_PATH/v2ray_util/util_core/util.cfg"
	UTIL_PATH="/etc/v2ray_util/util.cfg"

	#Centos 临时取消别名
	[[ -f /etc/redhat-release && -z $(echo $SHELL|grep zsh) ]] && unalias -a
	[[ -z $(echo $SHELL|grep zsh) ]] && ENV_FILE=".bashrc" || ENV_FILE=".zshrc"

	#######color code########
	RED="31m"
	GREEN="32m"
	YELLOW="33m"
	BLUE="36m"
	FUCHSIA="35m"

	colorEcho(){
		COLOR=$1
		echo -e "\033[${COLOR}${@:2}\033[0m"
	}

	#######get params#########
	while [[ $# > 0 ]];do
		key="$1"
		case $key in
			--remove)
			REMOVE=1
			;;
			-h|--help)
			HELP=1
			;;
			-k|--keep)
			INSTALL_WAY=1
			colorEcho ${BLUE} "keep v2ray profile to update\n"
			;;
			--zh)
			CHINESE=1
			colorEcho ${BLUE} "安装中文版..\n"
			;;
			*)
					# unknown option
			;;
		esac
		shift # past argument or value
	done
	#############################

	help(){
		echo "bash multi-v2ray.sh [-h|--help] [-k|--keep] [--remove]"
		echo "  -h, --help           Show help"
		echo "  -k, --keep           keep the v2ray config.json to update"
		echo "      --remove         remove v2ray && multi-v2ray"
		echo "                       no params to new install"
		return 0
	}

	removeV2Ray() {
		#卸载V2ray官方脚本
		systemctl stop v2ray  >/dev/null 2>&1
		systemctl disable v2ray  >/dev/null 2>&1
		service v2ray stop  >/dev/null 2>&1
		update-rc.d -f v2ray remove  >/dev/null 2>&1
		rm -rf  /etc/v2ray/  >/dev/null 2>&1
		rm -rf /usr/bin/v2ray  >/dev/null 2>&1
		rm -rf /var/log/v2ray/  >/dev/null 2>&1
		rm -rf /lib/systemd/system/v2ray.service  >/dev/null 2>&1
		rm -rf /etc/init.d/v2ray  >/dev/null 2>&1

		#清理v2ray相关iptable规则
		bash <(curl -L -s $CLEAN_IPTABLES_SHELL)

		#卸载multi-v2ray
		pip uninstall v2ray_util -y
		rm -rf /etc/bash_completion.d/v2ray.bash >/dev/null 2>&1
		rm -rf /usr/local/bin/v2ray >/dev/null 2>&1
		rm -rf /etc/v2ray_util >/dev/null 2>&1

		#删除v2ray定时更新任务
		crontab -l|sed '/SHELL=/d;/v2ray/d' > crontab.txt
		crontab crontab.txt >/dev/null 2>&1
		rm -f crontab.txt >/dev/null 2>&1

		if [[ ${OS} == 'CentOS' || ${OS} == 'Fedora' ]];then
			service crond restart >/dev/null 2>&1
		else
			service cron restart >/dev/null 2>&1
		fi

		#删除multi-v2ray环境变量
		sed -i '/v2ray/d' ~/$ENV_FILE
		source ~/$ENV_FILE

		colorEcho ${GREEN} "uninstall success!"
	}

	closeSELinux() {
		#禁用SELinux
		if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
			sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
			setenforce 0
		fi
	}

	checkSys() {
		#检查是否为Root
		[ $(id -u) != "0" ] && { colorEcho ${RED} "Error: You must be root to run this script"; exit 1; }

		#检查系统信息
		if [[ -e /etc/redhat-release ]];then
			if [[ $(cat /etc/redhat-release | grep Fedora) ]];then
				OS='Fedora'
				PACKAGE_MANAGER='dnf'
			else
				OS='CentOS'
				PACKAGE_MANAGER='yum'
			fi
		elif [[ $(cat /etc/issue | grep Debian) ]];then
			OS='Debian'
			PACKAGE_MANAGER='apt-get'
		elif [[ $(cat /etc/issue | grep Ubuntu) ]];then
			OS='Ubuntu'
			PACKAGE_MANAGER='apt-get'
		elif [[ $(cat /etc/issue | grep Raspbian) ]];then
			OS='Raspbian'
			PACKAGE_MANAGER='apt-get'
		else
			colorEcho ${RED} "Not support OS, Please reinstall OS and retry!"
			exit 1
		fi
	}

	#安装依赖
	installDependent(){
		if [[ ${OS} == 'CentOS' || ${OS} == 'Fedora' ]];then
			${PACKAGE_MANAGER} install ntpdate socat crontabs lsof which -y
		else
			${PACKAGE_MANAGER} update
			${PACKAGE_MANAGER} install ntpdate socat cron lsof -y
		fi

		#install python3 & pip3
		bash <(curl -sL https://git.io/fhqMz)
	}

	#设置定时升级任务
	planUpdate(){
		if [[ $CHINESE == 1 ]];then
			#计算北京时间早上3点时VPS的实际时间
			ORIGIN_TIME_ZONE=$(date -R|awk '{printf"%d",$6}')
			LOCAL_TIME_ZONE=${ORIGIN_TIME_ZONE%00}
			BEIJING_ZONE=8
			DIFF_ZONE=$[$BEIJING_ZONE-$LOCAL_TIME_ZONE]
			LOCAL_TIME=$[$BEIJING_UPDATE_TIME-$DIFF_ZONE]
			if [ $LOCAL_TIME -lt 0 ];then
				LOCAL_TIME=$[24+$LOCAL_TIME]
			elif [ $LOCAL_TIME -ge 24 ];then
				LOCAL_TIME=$[$LOCAL_TIME-24]
			fi
			colorEcho ${BLUE} "beijing time ${BEIJING_UPDATE_TIME}, VPS time: ${LOCAL_TIME}\n"
		else
			LOCAL_TIME=3
		fi
		OLD_CRONTAB=$(crontab -l)
		echo "SHELL=/bin/bash" >> crontab.txt
		echo "${OLD_CRONTAB}" >> crontab.txt
		echo "0 ${LOCAL_TIME} * * * bash <(curl -L -s https://install.direct/go.sh) | tee -a /root/v2rayUpdate.log && service v2ray restart" >> crontab.txt
		crontab crontab.txt
		sleep 1
		if [[ ${OS} == 'CentOS' || ${OS} == 'Fedora' ]];then
			service crond restart
		else
			service cron restart
		fi
		rm -f crontab.txt
		colorEcho ${GREEN} "success open schedule update task: beijing time ${BEIJING_UPDATE_TIME}\n"
	}

	updateProject() {
		local DOMAIN=""

		[[ ! $(type pip3 2>/dev/null) ]] && colorEcho $RED "pip3 no install!" && exit 1

		if [[ -e /usr/local/multi-v2ray/multi-v2ray.conf ]];then
			TEMP_VALUE=$(cat /usr/local/multi-v2ray/multi-v2ray.conf|grep domain|awk 'NR==1')
			DOMAIN=${TEMP_VALUE/*=}
			rm -rf /usr/local/multi-v2ray
		fi

		pip3 install -U v2ray_util

		if [[ -e $UTIL_PATH ]];then
			[[ -z $(cat $UTIL_PATH|grep lang) ]] && echo "lang=en" >> $UTIL_PATH
		else
			mkdir -p /etc/v2ray_util
			curl $UTIL_CFG > $UTIL_PATH
			[[ ! -z $DOMAIN ]] && sed -i "s/^domain.*/domain=${DOMAIN}/g" $UTIL_PATH
		fi

		[[ $CHINESE == 1 ]] && sed -i "s/lang=en/lang=zh/g" $UTIL_PATH

		rm -f /usr/local/bin/v2ray >/dev/null 2>&1
		ln -s $(which v2ray-util) /usr/local/bin/v2ray

		#更新v2ray bash_completion脚本
		curl $BASH_COMPLETION_SHELL > /etc/bash_completion.d/v2ray.bash
		[[ -z $(echo $SHELL|grep zsh) ]] && source /etc/bash_completion.d/v2ray.bash
		
		#安装/更新V2ray主程序
		bash <(curl -L -s https://install.direct/go.sh)
	}

	#时间同步
	timeSync() {
		if [[ ${INSTALL_WAY} == 0 ]];then
			echo -e "${Info} Time Synchronizing.. ${Font}"
			ntpdate pool.ntp.org
			if [[ $? -eq 0 ]];then 
				echo -e "${OK} Time Sync Success ${Font}"
				echo -e "${OK} now: `date -R`${Font}"
				sleep 1
			else
				echo -e "${Error} Time sync fail, please run command to sync:${Font}${Yellow}ntpdate pool.ntp.org${Font}"
			fi
		fi
	}

	profileInit() {

		#清理v2ray模块环境变量
		[[ $(grep v2ray ~/$ENV_FILE) ]] && sed -i '/v2ray/d' ~/$ENV_FILE && source ~/$ENV_FILE

		#解决Python3中文显示问题
		[[ -z $(grep PYTHONIOENCODING=utf-8 ~/$ENV_FILE) ]] && echo "export PYTHONIOENCODING=utf-8" >> ~/$ENV_FILE && source ~/$ENV_FILE

		# 加入v2ray tab补全环境变量
		[[ -z $(echo $SHELL|grep zsh) && -z $(grep v2ray.bash ~/$ENV_FILE) ]] && echo "source /etc/bash_completion.d/v2ray.bash" >> ~/$ENV_FILE && source ~/$ENV_FILE

		#全新安装的新配置
		if [[ ${INSTALL_WAY} == 0 ]];then 
			v2ray new
		else
			v2ray convert
		fi

		bash <(curl -L -s $CLEAN_IPTABLES_SHELL)
		echo ""
	}

	installFinish() {
		#回到原点
		cd ${BEGIN_PATH}
		[[ ${INSTALL_WAY} == 0 ]] && WAY="install" || WAY="update"
		colorEcho  ${GREEN} "multi-v2ray ${WAY} success!\n"
		clear
		v2ray info
		echo -e "\nplease input 'v2ray' command to manage v2ray
——————————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 管理V2Ray
 ${Green_font_prefix}2.${Font_color_suffix} 回到主页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
——————————————————————————————————" && echo

		read -p " 请输入数字 [1-3](默认:3):" num
		[ -z "${num}" ] && num=3
		case "$num" in
			1)
			v2ray
			;;
			2)
			start_menu_main
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-3]:"
			sleep 2s
			installFinish
			;;
		esac
	}

	main() {
		[[ ${HELP} == 1 ]] && help && return
		[[ ${REMOVE} == 1 ]] && removeV2Ray && return
		[[ ${INSTALL_WAY} == 0 ]] && colorEcho ${BLUE} "new install\n"
		
		checkSys
		installDependent
		closeSELinux
		timeSync
		
		#设置定时任务
		[[ -z $(crontab -l|grep v2ray) ]] && planUpdate
		updateProject
		profileInit
		service v2ray restart
		installFinish
	}
	main
}

#安装SSR
install_ssr(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH
	#=================================================================#
	#   System Required:  CentOS 6,7, Debian, Ubuntu                  #
	#   Description: One click Install ShadowsocksR Server            #
	#   Author: Teddysun <i@teddysun.com>                             #
	#   Thanks: @breakwa11 <https://twitter.com/breakwa11>            #
	#   Intro:  https://shadowsocks.be/9.html                         #
	#=================================================================#

	clear
	libsodium_file="libsodium-1.0.17"
	libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"
	shadowsocks_r_file="shadowsocksr-3.2.2"
	shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

	#Current folder
	cur_dir=`pwd`
	
	# Reference URL:
	# https://github.com/shadowsocksr-rm/shadowsocks-rss/blob/master/ssr.md
	# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
	
	# Disable selinux
	disable_selinux(){
		if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
			sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
			setenforce 0
		fi
	}

	#Check system
	check_sys_ssr(){
		local checkType=$1
		local value=$2

		local release=''
		local systemPackage=''

		if [[ -f /etc/redhat-release ]]; then
			release="centos"
			systemPackage="yum"
		elif grep -Eqi "debian|raspbian" /etc/issue; then
			release="debian"
			systemPackage="apt"
		elif grep -Eqi "ubuntu" /etc/issue; then
			release="ubuntu"
			systemPackage="apt"
		elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
			release="centos"
			systemPackage="yum"
		elif grep -Eqi "debian|raspbian" /proc/version; then
			release="debian"
			systemPackage="apt"
		elif grep -Eqi "ubuntu" /proc/version; then
			release="ubuntu"
			systemPackage="apt"
		elif grep -Eqi "centos|red hat|redhat" /proc/version; then
			release="centos"
			systemPackage="yum"
		fi

		if [[ "${checkType}" == "sysRelease" ]]; then
			if [ "${value}" == "${release}" ]; then
				return 0
			else
				return 1
			fi
		elif [[ "${checkType}" == "packageManager" ]]; then
			if [ "${value}" == "${systemPackage}" ]; then
				return 0
			else
				return 1
			fi
		fi
	}
	
	# Get version
	getversion(){
		if [[ -s /etc/redhat-release ]]; then
			grep -oE  "[0-9.]+" /etc/redhat-release
		else
			grep -oE  "[0-9.]+" /etc/issue
		fi
	}

	# CentOS version
	centosversion(){
		if check_sys_ssr sysRelease centos; then
			local code=$1
			local version="$(getversion)"
			local main_ver=${version%%.*}
			if [ "$main_ver" == "$code" ]; then
				return 0
			else
				return 1
			fi
		else
			return 1
		fi
	}

	#选择加密
	set_method(){
		# Stream Ciphers
		ciphers=(
			none
			aes-256-cfb
			aes-192-cfb
			aes-128-cfb
			aes-256-cfb8
			aes-192-cfb8
			aes-128-cfb8
			aes-256-ctr
			aes-192-ctr
			aes-128-ctr
			chacha20-ietf
			chacha20
			salsa20
			xchacha20
			xsalsa20
			rc4-md5
		)
		while true
		do
		echo -e "${Info}请选择ShadowsocksR加密方式:"
		for ((i=1;i<=${#ciphers[@]};i++ )); do
			hint="${ciphers[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which cipher you'd select(默认: ${ciphers[1]}):" pick
		[ -z "$pick" ] && pick=2
		expr ${pick} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Please enter a number"
			continue
		fi
		if [[ "$pick" -lt 1 || "$pick" -gt ${#ciphers[@]} ]]; then
			echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#ciphers[@]}"
			continue
		fi
		method=${ciphers[$pick-1]}
		echo
		echo "---------------------------"
		echo "cipher = ${method}"
		echo "---------------------------"
		echo
		break
		done
	}
	#选择协议
	set_protocol(){
		# Protocol
		protocols=(
			origin
			verify_deflate
			auth_sha1_v4
			auth_sha1_v4_compatible
			auth_aes128_md5
			auth_aes128_sha1
			auth_chain_a
			auth_chain_b
			auth_chain_c
			auth_chain_d
			auth_chain_e
			auth_chain_f
		)
		while true
		do
		echo -e "${Info}请选择ShadowsocksR协议:"
		for ((i=1;i<=${#protocols[@]};i++ )); do
			hint="${protocols[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which protocol you'd select(默认: ${protocols[3]}):" protocol
		[ -z "$protocol" ] && protocol=4
		expr ${protocol} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Input error, please input a number"
			continue
		fi
		if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
			echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#protocols[@]}"
			continue
		fi
		protocol=${protocols[$protocol-1]}
		echo
		echo "---------------------------"
		echo "protocol = ${protocol}"
		echo "---------------------------"
		echo
		break
		done
	}
	#选择混淆
	set_obfs(){
		# obfs
		obfs=(
			plain
			http_simple
			http_simple_compatible
			http_post
			http_post_compatible
			tls1.2_ticket_auth
			tls1.2_ticket_auth_compatible
			tls1.2_ticket_fastauth
			tls1.2_ticket_fastauth_compatible
		)
		while true
		do
		echo -e "${Info}请选择ShadowsocksR混淆方式:"
		for ((i=1;i<=${#obfs[@]};i++ )); do
			hint="${obfs[$i-1]}"
			echo -e "${green}${i}${plain}) ${hint}"
		done
		read -p "Which obfs you'd select(默认: ${obfs[2]}):" r_obfs
		[ -z "$r_obfs" ] && r_obfs=3
		expr ${r_obfs} + 1 &>/dev/null
		if [ $? -ne 0 ]; then
			echo -e "[${red}Error${plain}] Input error, please input a number"
			continue
		fi
		if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
			echo -e "[${red}Error${plain}] Input error, please input a number between 1 and ${#obfs[@]}"
			continue
		fi
		obfs=${obfs[$r_obfs-1]}
		echo
		echo "---------------------------"
		echo "obfs = ${obfs}"
		echo "---------------------------"
		echo
		break
		done
	}
	
	# Pre-installation settings
	pre_install(){
		if check_sys_ssr packageManager yum || check_sys_ssr packageManager apt; then
			# Not support CentOS 5
			if centosversion 5; then
				echo -e "$[{red}Error${plain}] Not supported CentOS 5, please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
				exit 1
			fi
		else
			echo -e "[${red}Error${plain}] Your OS is not supported. please change OS to CentOS/Debian/Ubuntu and try again."
			exit 1
		fi
		# Set ShadowsocksR config password
		echo -e "${Info}请设置ShadowsocksR密码:"
		read -p "(默认密码: pangbobi):" password
		[ -z "${password}" ] && password="pangbobi"
		echo
		echo "---------------------------"
		echo "password = ${password}"
		echo "---------------------------"
		echo
		# Set ShadowsocksR config port
		while true
		do
		dport=$(shuf -i 1000-9999 -n 1)
		echo -e "${Info}请设置ShadowsocksR端口[1-65535]:"
		read -p "(默认随机端口: ${dport}):" port
		[ -z "${port}" ] && port=${dport}
		expr ${port} + 1 &>/dev/null
		if [ $? -eq 0 ]; then
			if [ ${port} -ge 1 ] && [ ${port} -le 65535 ] && [ ${port:0:1} != 0 ]; then
				echo
				echo "---------------------------"
				echo "port = ${port}"
				echo "---------------------------"
				echo
				break
			fi
		fi
		echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
		done

		# Set shadowsocksR config stream ciphers
		set_method

		# Set shadowsocksR config protocol
		set_protocol
		
		# Set shadowsocksR config obfs
		set_obfs

		echo
		echo "Press any key to start...or Press Ctrl+C to cancel"
		char=`get_char`
		cd ${cur_dir}
	}

	# Download files
	download_files(){
		# Download libsodium file
		if ! wget --no-check-certificate -O ${libsodium_file}.tar.gz ${libsodium_url}; then
			echo -e "[${red}Error${plain}] Failed to download ${libsodium_file}.tar.gz!"
			exit 1
		fi
		# Download ShadowsocksR file
		if ! wget --no-check-certificate -O ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_url}; then
			echo -e "[${red}Error${plain}] Failed to download ShadowsocksR file!"
			exit 1
		fi
		# Download ShadowsocksR init script
		if check_sys_ssr packageManager yum; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR -O /etc/init.d/shadowsocks; then
				echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
				exit 1
			fi
		elif check_sys_ssr packageManager apt; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
				echo -e "[${red}Error${plain}] Failed to download ShadowsocksR chkconfig file!"
				exit 1
			fi
		fi
	}

	# Config ShadowsocksR
	config_shadowsocks(){
		cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"[::]",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "port_password":{
                "${port}":"${password}"
        },
    "timeout":300,
    "method":"${method}",
    "protocol":"${protocol}",
    "protocol_param":"3",
    "obfs":"${obfs}",
    "obfs_param":"",
    "redirect":"*:*#127.0.0.1:80",
    "dns_ipv6":false,
    "fast_open":true,
    "workers":1
}
EOF
	}

	# Install ShadowsocksR
	install(){
		# Install libsodium
		if [ ! -f /usr/lib/libsodium.a ]; then
			cd ${cur_dir}
			tar zxf ${libsodium_file}.tar.gz
			cd ${libsodium_file}
			./configure --prefix=/usr && make && make install
			if [ $? -ne 0 ]; then
				echo -e "[${red}Error${plain}] libsodium install failed!"
				install_cleanup
				exit 1
			fi
		fi

		ldconfig
		# Install ShadowsocksR
		cd ${cur_dir}
		tar zxf ${shadowsocks_r_file}.tar.gz
		mv ${shadowsocks_r_file}/shadowsocks /usr/local/
		if [ -f /usr/local/shadowsocks/server.py ]; then
			chmod +x /etc/init.d/shadowsocks
			if check_sys_ssr packageManager yum; then
				chkconfig --add shadowsocks
				chkconfig shadowsocks on
			elif check_sys_ssr packageManager apt; then
				update-rc.d -f shadowsocks defaults
			fi
			/etc/init.d/shadowsocks start
			
			get_info
			set_ssrurl
			echo
			echo -e "Congratulations, ShadowsocksR server install completed!"
			echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
			echo -e "Your Server Port      : \033[41;37m ${port} \033[0m"
			echo -e "Your Password         : \033[41;37m ${password} \033[0m"
			echo -e "Your Protocol         : \033[41;37m ${protocol} \033[0m"
			echo -e "Your obfs             : \033[41;37m ${obfs} \033[0m"
			echo -e "Your Encryption Method: \033[41;37m ${method} \033[0m"
			echo "
	Enjoy it!
	请记录你的SSR信息"
			echo -e "
————————————胖波比————————————
 ${Green_font_prefix}1.${Font_color_suffix} 回到主页
 ${Green_font_prefix}2.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
			read -p " 请输入数字 [1-2](默认:2):" num
			[ -z "${num}" ] && num=2
			case "$num" in
				1)
				start_menu_main
				;;
				2)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-2]"
				sleep 2s
				start_menu_main
				;;
			esac
		else
			echo "ShadowsocksR install failed, please Email to Teddysun <i@teddysun.com> and contact"
			install_cleanup
			exit 1
		fi
	}

	# Install cleanup
	install_cleanup(){
		cd ${cur_dir}
		rm -rf ${shadowsocks_r_file}.tar.gz ${shadowsocks_r_file} ${libsodium_file}.tar.gz ${libsodium_file}
	}

	# Uninstall ShadowsocksR
	uninstall_shadowsocksr(){
		printf "Are you sure uninstall ShadowsocksR? (y/n)"
		printf "\n"
		read -p "(Default: n):" answer
		[ -z ${answer} ] && answer="n"
		if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
			/etc/init.d/shadowsocks status > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				/etc/init.d/shadowsocks stop
			fi
			if check_sys_ssr packageManager yum; then
				chkconfig --del shadowsocks
			elif check_sys_ssr packageManager apt; then
				update-rc.d -f shadowsocks remove
			fi
			rm -f /etc/shadowsocks.json
			rm -f /etc/init.d/shadowsocks
			rm -f /var/log/shadowsocks.log
			rm -rf /usr/local/shadowsocks
			echo "ShadowsocksR uninstall success!"
		else
			echo
			echo "uninstall cancelled, nothing to do..."
			echo
		fi
	}

	# Install ShadowsocksR
	install_shadowsocksr(){
		disable_selinux
		pre_install
		download_files
		config_shadowsocks
		add_firewall
		firewall_restart
		install
		install_cleanup
	}

	#字符转换
	urlsafe_base64(){
		date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
		echo -e "${date}"
	}
	#获取配置信息
	get_info(){
		#获取协议
		protocol=$(jq -r '.protocol' /etc/shadowsocks.json)
		#获取加密方式
		method=$(jq -r '.method' /etc/shadowsocks.json)
		#获取混淆
		obfs=$(jq -r '.obfs' /etc/shadowsocks.json)
		#预处理
		SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
		SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
		Remarksbase64=$(urlsafe_base64 "企鹅号:3450633979有问题随时戳我")
		Groupbase64=$(urlsafe_base64 "我们爱中国")
	}
	#读取端口密码
	get_pp(){
		cat > ppj<<-EOF
$(jq '.port_password' /etc/shadowsocks.json)
EOF
		pp=$(jq -r "to_entries|map(\"\(.key):\(.value|tostring)\")|.[]" ppj)
		cat > ppj<<-EOF
${pp}
EOF
	}
	#生成SSR链接
	set_ssrurl(){
		SSRPWDbase64=$(urlsafe_base64 "${password}")
		SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
		SSRurl="ssr://${SSRbase64}"
		service shadowsocks restart
		clear
		#输出链接
		echo -e "${Info}SSR已重启！2秒后输出链接"
		sleep 2s
		echo -e "${Info}端口：${Red_font_prefix}${port}${Font_color_suffix}   密码：${Red_font_prefix}${password}${Font_color_suffix}"
		echo -e "${Info}SSR链接 : ${Red_font_prefix}${SSRurl}${Font_color_suffix}\n"
	}
	#查看所有链接
	view_ssrurl(){
		clear
		get_pp
		cat ppj | while read line; do
			port=`echo $line|awk -F ':' '{print $1}'`
			password=`echo $line|awk -F ':' '{print $2}'`
			echo -e "端口：${Red_font_prefix}${port}${Font_color_suffix}   密码：${Red_font_prefix}${password}${Font_color_suffix}"
			SSRPWDbase64=$(urlsafe_base64 "${password}")
			SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
			SSRurl="ssr://${SSRbase64}"
			echo -e "SSR链接 : ${Red_font_prefix}${SSRurl}${Font_color_suffix}\n"
		done
		echo -e "服务器IP    ：${Red_font_prefix}$(get_ip)${Font_color_suffix}"
		echo -e "加密方式    ：${Red_font_prefix}${method}${Font_color_suffix}"
		echo -e "协议        ：${Red_font_prefix}${protocol}${Font_color_suffix}"
		echo -e "混淆        ：${Red_font_prefix}${obfs}${Font_color_suffix}"
		echo -e "当前用户总数：${Red_font_prefix}$(jq '.port_password | length' /etc/shadowsocks.json)${Font_color_suffix}\n"
		if [[ "${testmpo}" == "1" ]]; then
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
		fi
		echo -e "${Info}按任意键回到SSR用户管理页..."
		char=`get_char`
		manage_ssr
	}

	#更改密码
	change_pw(){
		#查看文件内容
		clear
		get_pp
		jq '.port_password' /etc/shadowsocks.json
		echo -e "${Info}以上是配置文件的内容\n"
		#判断端口是否已有,清空port内存
		unset port
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && "${port}" -ge "1000" && "${port}" -le "65535" && "${port}" -ne "1080" ]]
		do
			read -p "请输入要改密的端口号：" port
		done
		password1=$(cat ppj | grep "${port}:" | awk -F ':' '{print $2}')
		password=$(openssl rand -base64 6)
		et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
		until [[ "${password1}" == "${password}" ]]
		do
			sed -i "${et}s/${password1}/${password}/g" /etc/shadowsocks.json
			get_pp
			password1=$(cat ppj | grep "${port}:" | awk -F ':' '{print $2}')
		done
		#调用生成链接的函数
		set_ssrurl
		echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续更改用户密码
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————" && echo
		read -p " 请输入数字 [1-3](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			1)
			change_pw
			;;
			2)
			manage_ssr
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-3]:"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	#添加用户
	add_user(){
		#逐个添加
		add_user_single(){
			clear
			jq '.port_password' /etc/shadowsocks.json
			echo -e "${Info}以上是配置文件的内容"
			echo -e "${Info}当前用户总数：${Red_font_prefix}$(jq '.port_password | length' /etc/shadowsocks.json)${Font_color_suffix}\n"
			unset port
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '0' && "${port}" -ge "1000" && "${port}" -le "65535" ]]
			do
				read -p "请输入要添加的端口号[1000-65535]：" port
			done
			add_firewall
			firewall_restart
			password=$(openssl rand -base64 6)
			sed -i "7i\\\t\t\"${port}\":\"${password}\"," /etc/shadowsocks.json
			set_ssrurl
			echo -e "    ————胖波比————
 ——————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续添加用户
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 ——————————————————————" && echo
			read -p " 请输入数字 [1-3](默认:3)：" num
			[ -z "${num}" ] && num=3
			case "$num" in
				1)
				add_user_single
				;;
				2)
				manage_ssr
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]:"
				sleep 2s
				manage_ssr
				;;
			esac
		}
		#批量添加
		add_user_multi(){
			clear
			echo -e "\n${Info}当前用户总数：${Red_font_prefix}$(jq '.port_password | length' /etc/shadowsocks.json)${Font_color_suffix}\n"
			read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			unset port
			for(( i = 0; i < ${num}; i++ ))
			do
				until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '0' ]]
				do
					port=$(shuf -i 1000-9999 -n 1)
				done
				add_firewall
				password=$(openssl rand -base64 6)
				sed -i "7i\\\t\t\"${port}\":\"${password}\"," /etc/shadowsocks.json
				SSRPWDbase64=$(urlsafe_base64 "${password}")
				SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
				SSRurl="ssr://${SSRbase64}"
				echo -e "${Info}端口：${Red_font_prefix}${port}${Font_color_suffix}   密码：${Red_font_prefix}${password}${Font_color_suffix}"
				echo -e "${Info}SSR链接 : ${Red_font_prefix}${SSRurl}${Font_color_suffix}\n"
			done
			firewall_restart
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			echo -e "${Info}当前用户总数：${Red_font_prefix}$(jq '.port_password | length' /etc/shadowsocks.json)${Font_color_suffix}\n"
			echo -e "${Info}按任意键返回SSR用户管理页..."
			char=`get_char`
			manage_ssr
		}
		#添加用户菜单
		add_user_menu(){
			clear
			echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 逐个添加
 ${Green_font_prefix}2.${Font_color_suffix} 批量添加
 ${Green_font_prefix}3.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
 —————————————————————" && echo
			read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				add_user_single
				;;
				2)
				add_user_multi
				;;
				3)
				manage_ssr
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-4]:"
				sleep 2s
				add_user_menu
				;;
			esac
		}
		add_user_menu
	}	
	#删除用户
	delete_user(){
		clear
		jq '.port_password' /etc/shadowsocks.json
		echo -e "${Info}以上是配置文件的内容\n"
		unset port
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && "${port}" -ge "1000" && "${port}" -le "65535" && "${port}" -ne "1080" ]]
		do
			read -p "请输入要删除的端口:" port
		done
		et=$(awk "/${port}/{getline;print}" /etc/shadowsocks.json)
		if [[ `expr index "${et}" '}'` -ne '0' ]]; then
			et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
			((et--))
			sed -i "${et}s/,//g" /etc/shadowsocks.json
		fi
		sed -i "/${port}/d" /etc/shadowsocks.json
		echo -e "${Info}用户已删除..."
		delete_firewall
		firewall_restart
		service shadowsocks restart
		echo -e "${Info}SSR已重启！"
		sleep 2s
		clear
		echo && echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续删除用户
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————"
		read -p " 请输入数字 [1-3](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			1)
			delete_user
			;;
			2)
			manage_ssr
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-3]:"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	#更改端口
	change_port(){
		clear
		jq '.port_password' /etc/shadowsocks.json
		echo -e "${Info}以上是配置文件的内容\n"
		unset port
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && "${port}" -ge "1000" && "${port}" -le "65535" && "${port}" -ne "1080" ]]
		do
			read -p "请输入要修改的端口号：" port
		done
		delete_firewall
		port1=${port}
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '0' && "${port}" -ge "1000" && "${port}" -le "65535" ]]
		do
			read -p "请输入修改后的端口[1000-65535]:" port
		done
		add_firewall
		firewall_restart
		password=$(openssl rand -base64 6)
		sed -i "s/${port1}/${port}/g"  /etc/shadowsocks.json
		set_ssrurl
		echo -e "	————胖波比————
 ———————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续更改端口
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 ———————————————————————————"
		read -p " 请输入数字 [1-3](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			1)
			change_port
			;;
			2)
			manage_ssr
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-3]:"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	#更改加密
	change_method(){
		method1=$(jq -r '.method' /etc/shadowsocks.json)
		set_method
		sed -i "s/${method1}/${method}/g"  /etc/shadowsocks.json
		testmpo=1
		view_ssrurl
	}
	#更改协议
	change_protocol(){
		protocol1=$(jq -r '.protocol' /etc/shadowsocks.json)
		set_protocol
		sed -i "s/${protocol1}/${protocol}/g"  /etc/shadowsocks.json
		SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
		testmpo=1
		view_ssrurl
	}
	#更改混淆
	change_obfs(){
		obfs1=$(jq -r '.obfs' /etc/shadowsocks.json)
		set_obfs
		sed -i "s/${obfs1}/${obfs}/g"  /etc/shadowsocks.json
		SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
		testmpo=1
		view_ssrurl
	}
	
	#管理SSR配置
	manage_ssr(){
		clear
		get_info
		echo && echo -e "   SSR用户管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
手动修改配置文件：vi /etc/shadowsocks.json
		
—————————SSR用户管理——————————
 ${Green_font_prefix}1.${Font_color_suffix} 更改密码
 ${Green_font_prefix}2.${Font_color_suffix} 添加用户
 ${Green_font_prefix}3.${Font_color_suffix} 删除用户
 ${Green_font_prefix}4.${Font_color_suffix} 更改端口
 ${Green_font_prefix}5.${Font_color_suffix} 更改加密
 ${Green_font_prefix}6.${Font_color_suffix} 更改协议
 ${Green_font_prefix}7.${Font_color_suffix} 更改混淆
 ${Green_font_prefix}8.${Font_color_suffix} 查看用户链接
 ${Green_font_prefix}9.${Font_color_suffix} 回到主页
 ${Green_font_prefix}10.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
		read -p " 请输入数字 [1-10](默认:10):" num
		[ -z "${num}" ] && num=10
		case "$num" in
			1)
			change_pw
			;;
			2)
			add_user
			;;
			3)
			delete_user
			;;
			4)
			change_port
			;;
			5)
			change_method
			;;
			6)
			change_protocol
			;;
			7)
			change_obfs
			;;
			8)
			testmpo=2
			view_ssrurl
			;;
			9)
			start_menu_main
			;;
			10)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-10]"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	
	# Initialization step
	start_menu_ssr(){
		echo && echo -e " SSR一键安装脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
    -- 胖波比 --
		
——————————SSR安装——————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装SSR
 ${Green_font_prefix}2.${Font_color_suffix} 管理SSR用户
 ${Green_font_prefix}3.${Font_color_suffix} 卸载SSR
 ${Green_font_prefix}4.${Font_color_suffix} 重启SSR
 ${Green_font_prefix}5.${Font_color_suffix} 关闭SSR
 ${Green_font_prefix}6.${Font_color_suffix} 启动SSR
 ${Green_font_prefix}7.${Font_color_suffix} 查看SSR状态
 ${Green_font_prefix}8.${Font_color_suffix} 回到主页
 ${Green_font_prefix}9.${Font_color_suffix} 退出脚本
———————————————————————————" && echo
		read -p " 请输入数字 [1-9](默认:9):" num
		[ -z "${num}" ] && num=9
		case "$num" in
			1)
			install_shadowsocksr
			;;
			2)
			manage_ssr
			;;
			3)
			uninstall_shadowsocksr
			;;
			4)
			service shadowsocks restart
			;;
			5)
			service shadowsocks stop
			;;
			6)
			service shadowsocks start
			;;
			7)
			service shadowsocks status
			;;
			8)
			start_menu_main
			;;
			9)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-9]"
			sleep 2s
			start_menu_ssr
			;;
		esac
	}
	start_menu_ssr
}

#安装BBR或锐速
install_bbr(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH

	#=================================================
	#	System Required: CentOS 6/7,Debian 8/9,Ubuntu 16+
	#	Description: BBR+BBR魔改版+BBRplus+Lotserver
	#	Version: 1.3.2
	#	Author: 千影,cx9208
	#	Blog: https://www.94ish.me/
	#=================================================

	github="raw.githubusercontent.com/chiakge/Linux-NetSpeed/master"

	#安装BBR内核
	installbbr(){
		kernel_version="4.11.8"
		if [[ "${release}" == "centos" ]]; then
			rpm --import http://${github}/bbr/${release}/RPM-GPG-KEY-elrepo.org
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-${kernel_version}.rpm
			yum remove -y kernel-headers
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-headers-${kernel_version}.rpm
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-devel-${kernel_version}.rpm
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			mkdir bbr && cd bbr
			wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
			wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/linux-headers-${kernel_version}-all.deb
			wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
			wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
		
			dpkg -i libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
			dpkg -i linux-headers-${kernel_version}-all.deb
			dpkg -i linux-headers-${kernel_version}.deb
			dpkg -i linux-image-${kernel_version}.deb
			cd .. && rm -rf bbr
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBR/BBR魔改版${Font_color_suffix}"
		stty erase '^H' && read -p "需要重启VPS后，才能开启BBR/BBR魔改版，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装BBRplus内核
	installbbrplus(){
		kernel_version="4.14.129-bbrplus"
		if [[ "${release}" == "centos" ]]; then
			wget -N --no-check-certificate https://${github}/bbrplus/${release}/${version}/kernel-${kernel_version}.rpm
			yum install -y kernel-${kernel_version}.rpm
			rm -f kernel-${kernel_version}.rpm
			kernel_version="4.14.129_bbrplus" #fix a bug
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			mkdir bbrplus && cd bbrplus
			wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
			wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
			dpkg -i linux-headers-${kernel_version}.deb
			dpkg -i linux-image-${kernel_version}.deb
			cd .. && rm -rf bbrplus
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBRplus${Font_color_suffix}"
		stty erase '^H' && read -p "需要重启VPS后，才能开启BBRplus，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装Lotserver内核
	installlot(){
		if [[ "${release}" == "centos" ]]; then
			rpm --import http://${github}/lotserver/${release}/RPM-GPG-KEY-elrepo.org
			yum remove -y kernel-firmware
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-firmware-${kernel_version}.rpm
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-${kernel_version}.rpm
			yum remove -y kernel-headers
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-headers-${kernel_version}.rpm
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-devel-${kernel_version}.rpm
		elif [[ "${release}" == "ubuntu" ]]; then
			bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
		elif [[ "${release}" == "debian" ]]; then
			bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}Lotserver${Font_color_suffix}"
		stty erase '^H' && read -p "需要重启VPS后，才能开启Lotserver，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#启用BBR
	startbbr(){
		remove_all
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
		sysctl -p
		echo -e "${Info}BBR启动成功！"
	}

	#启用BBRplus
	startbbrplus(){
		remove_all
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=bbrplus" >> /etc/sysctl.conf
		sysctl -p
		echo -e "${Info}BBRplus启动成功！"
	}

	#编译并启用BBR魔改
	startbbrmod(){
		remove_all
		if [[ "${release}" == "centos" ]]; then
			yum install -y make gcc
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate http://${github}/bbr/tcp_tsunami.c
			echo "obj-m:=tcp_tsunami.o" > Makefile
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc
			chmod +x ./tcp_tsunami.ko
			cp -rf ./tcp_tsunami.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			insmod tcp_tsunami.ko
			depmod -a
		else
			apt-get update
			if [[ "${release}" == "ubuntu" && "${version}" = "14" ]]; then
				apt-get -y install build-essential
				apt-get -y install software-properties-common
				add-apt-repository ppa:ubuntu-toolchain-r/test -y
				apt-get update
			fi
			apt-get -y install make gcc
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate http://${github}/bbr/tcp_tsunami.c
			echo "obj-m:=tcp_tsunami.o" > Makefile
			ln -s /usr/bin/gcc /usr/bin/gcc-4.9
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc-4.9
			install tcp_tsunami.ko /lib/modules/$(uname -r)/kernel
			cp -rf ./tcp_tsunami.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			depmod -a
		fi
		

		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=tsunami" >> /etc/sysctl.conf
		sysctl -p
		cd .. && rm -rf bbrmod
		echo -e "${Info}魔改版BBR启动成功！"
	}

	#编译并启用BBR魔改
	startbbrmod_nanqinlang(){
		remove_all
		if [[ "${release}" == "centos" ]]; then
			yum install -y make gcc
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/bbr/centos/tcp_nanqinlang.c
			echo "obj-m := tcp_nanqinlang.o" > Makefile
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc
			chmod +x ./tcp_nanqinlang.ko
			cp -rf ./tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			insmod tcp_nanqinlang.ko
			depmod -a
		else
			apt-get update
			if [[ "${release}" == "ubuntu" && "${version}" = "14" ]]; then
				apt-get -y install build-essential
				apt-get -y install software-properties-common
				add-apt-repository ppa:ubuntu-toolchain-r/test -y
				apt-get update
			fi
			apt-get -y install make gcc-4.9
			mkdir bbrmod && cd bbrmod
			wget -N --no-check-certificate https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/bbr/tcp_nanqinlang.c
			echo "obj-m := tcp_nanqinlang.o" > Makefile
			make -C /lib/modules/$(uname -r)/build M=`pwd` modules CC=/usr/bin/gcc-4.9
			install tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel
			cp -rf ./tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel/net/ipv4
			depmod -a
		fi
		

		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control=nanqinlang" >> /etc/sysctl.conf
		sysctl -p
		echo -e "${Info}魔改版BBR启动成功！"
	}

	#启用Lotserver
	startlotserver(){
		remove_all
		if [[ "${release}" == "centos" ]]; then
			yum install ethtool
		else
			apt-get update
			apt-get install ethtool
		fi
		bash <(wget --no-check-certificate -qO- https://raw.githubusercontent.com/chiakge/lotServer/master/Install.sh) install
		sed -i '/advinacc/d' /appex/etc/config
		sed -i '/maxmode/d' /appex/etc/config
		echo -e "advinacc=\"1\"
	maxmode=\"1\"">>/appex/etc/config
		/appex/bin/lotServer.sh restart
		start_menu_bbr
	}

	#卸载全部加速
	remove_all(){
		rm -rf bbrmod
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/fs.file-max/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
		if [[ -e /appex/bin/lotServer.sh ]]; then
			bash <(wget --no-check-certificate -qO- https://github.com/MoeClub/lotServer/raw/master/Install.sh) uninstall
		fi
		clear
		echo -e "${Info}:清除加速完成。"
		sleep 1s
	}

	#优化系统配置
	optimizing_system(){
		sed -i '/fs.file-max/d' /etc/sysctl.conf
		sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		echo "fs.file-max = 1000000
	fs.inotify.max_user_instances = 8192
	net.ipv4.tcp_syncookies = 1
	net.ipv4.tcp_fin_timeout = 30
	net.ipv4.tcp_tw_reuse = 1
	net.ipv4.ip_local_port_range = 1024 65000
	net.ipv4.tcp_max_syn_backlog = 16384
	net.ipv4.tcp_max_tw_buckets = 6000
	net.ipv4.route.gc_timeout = 100
	net.ipv4.tcp_syn_retries = 1
	net.ipv4.tcp_synack_retries = 1
	net.core.somaxconn = 32768
	net.core.netdev_max_backlog = 32768
	net.ipv4.tcp_timestamps = 0
	net.ipv4.tcp_max_orphans = 32768
	# forward ipv4
	net.ipv4.ip_forward = 1">>/etc/sysctl.conf
		sysctl -p
		echo "*               soft    nofile           1000000
	*               hard    nofile          1000000">/etc/security/limits.conf
		echo "ulimit -SHn 1000000">>/etc/profile
		read -p "需要重启VPS后，才能生效系统优化配置，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#开始菜单
	start_menu_bbr(){
	clear
	echo && echo -e " TCP加速 一键安装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  -- 就是爱生活 | 94ish.me --
  
————————————内核管理————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 BBR/BBR魔改版内核
 ${Green_font_prefix}2.${Font_color_suffix} 安装 BBRplus版内核 
 ${Green_font_prefix}3.${Font_color_suffix} 安装 Lotserver(锐速)内核
————————————加速管理————————————
 ${Green_font_prefix}4.${Font_color_suffix} 使用BBR加速
 ${Green_font_prefix}5.${Font_color_suffix} 使用BBR魔改版加速
 ${Green_font_prefix}6.${Font_color_suffix} 使用暴力BBR魔改版加速(不支持部分系统)
 ${Green_font_prefix}7.${Font_color_suffix} 使用BBRplus版加速
 ${Green_font_prefix}8.${Font_color_suffix} 使用Lotserver(锐速)加速
————————————杂项管理————————————
 ${Green_font_prefix}9.${Font_color_suffix} 卸载全部加速
 ${Green_font_prefix}10.${Font_color_suffix} 系统配置优化
 ${Green_font_prefix}11.${Font_color_suffix} 回到主页
 ${Green_font_prefix}12.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		check_status
		if [[ ${kernel_status} == "noinstall" ]]; then
			echo -e " 当前状态: ${Green_font_prefix}未安装${Font_color_suffix} 加速内核 ${Red_font_prefix}请先安装内核${Font_color_suffix}"
		else
			echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} ${_font_prefix}${kernel_status}${Font_color_suffix} 加速内核 , ${Green_font_prefix}${run_status}${Font_color_suffix}"
			
		fi
	echo
	read -p " 请输入数字 [1-12](默认:12):" num
	[ -z "${num}" ] && num=12
	case "$num" in
		1)
		check_sys_bbr
		;;
		2)
		check_sys_bbrplus
		;;
		3)
		check_sys_Lotsever
		;;
		4)
		startbbr
		;;
		5)
		startbbrmod
		;;
		6)
		startbbrmod_nanqinlang
		;;
		7)
		startbbrplus
		;;
		8)
		startlotserver
		;;
		9)
		remove_all
		;;
		10)
		optimizing_system
		;;
		11)
		start_menu_main
		;;
		12)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-12]"
		sleep 2s
		start_menu_bbr
		;;
	esac
	}
	#############内核管理组件#############

	#删除多余内核
	detele_kernel(){
		if [[ "${release}" == "centos" ]]; then
			rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
			if [ "${rpm_total}" > "1" ]; then
				echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
				for((integer = 1; integer <= ${rpm_total}; integer++)); do
					rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
					echo -e "开始卸载 ${rpm_del} 内核..."
					rpm --nodeps -e ${rpm_del}
					echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
				done
				echo --nodeps -e "内核卸载完毕，继续..."
			else
				echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
			fi
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
			if [ "${deb_total}" > "1" ]; then
				echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
				for((integer = 1; integer <= ${deb_total}; integer++)); do
					deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
					echo -e "开始卸载 ${deb_del} 内核..."
					apt-get purge -y ${deb_del}
					echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
				done
				echo -e "内核卸载完毕，继续..."
			else
				echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
			fi
		fi
	}

	#更新引导
	BBR_grub(){
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} = "6" ]]; then
				if [ ! -f "/boot/grub/grub.conf" ]; then
					echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
					exit 1
				fi
				sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
			elif [[ ${version} = "7" ]]; then
				if [ ! -f "/boot/grub2/grub.cfg" ]; then
					echo -e "${Error} /boot/grub2/grub.cfg 找不到，请检查."
					exit 1
				fi
				grub2-set-default 0
			fi
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			/usr/sbin/update-grub
		fi
	}

	#############内核管理组件#############



	#############系统检测组件#############

	#检查Linux版本
	check_version_bbr(){
		if [[ -s /etc/redhat-release ]]; then
			version=`grep -oE  "[0-9.]+" /etc/redhat-release | cut -d . -f 1`
		else
			version=`grep -oE  "[0-9.]+" /etc/issue | cut -d . -f 1`
		fi
		bit=`uname -m`
		if [[ ${bit} = "x86_64" ]]; then
			bit="x64"
		else
			bit="x32"
		fi
	}

	#检查安装bbr的系统要求
	check_sys_bbr(){
		check_version_bbr
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} -ge "6" ]]; then
				installbbr
			else
				echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "debian" ]]; then
			if [[ ${version} -ge "8" ]]; then
				installbbr
			else
				echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} -ge "14" ]]; then
				installbbr
			else
				echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	}

	check_sys_bbrplus(){
		check_version_bbr
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} -ge "6" ]]; then
				installbbrplus
			else
				echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "debian" ]]; then
			if [[ ${version} -ge "8" ]]; then
				installbbrplus
			else
				echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} -ge "14" ]]; then
				installbbrplus
			else
				echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		else
			echo -e "${Error} BBRplus内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	}


	#检查安装Lotsever的系统要求
	check_sys_Lotsever(){
		check_version_bbr
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} == "6" ]]; then
				kernel_version="2.6.32-504"
				installlot
			elif [[ ${version} == "7" ]]; then
				yum -y install net-tools
				kernel_version="3.10.0-327"
				installlot
			else
				echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "debian" ]]; then
			if [[ ${version} = "7" || ${version} = "8" ]]; then
				if [[ ${bit} == "x64" ]]; then
					kernel_version="3.16.0-4"
					installlot
				elif [[ ${bit} == "x32" ]]; then
					kernel_version="3.2.0-4"
					installlot
				fi
			elif [[ ${version} = "9" ]]; then
				if [[ ${bit} == "x64" ]]; then
					kernel_version="4.9.0-4"
					installlot
				fi
			else
				echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} -ge "12" ]]; then
				if [[ ${bit} == "x64" ]]; then
					kernel_version="4.4.0-47"
					installlot
				elif [[ ${bit} == "x32" ]]; then
					kernel_version="3.13.0-29"
					installlot
				fi
			else
				echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
			fi
		else
			echo -e "${Error} Lotsever不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	}

	check_status(){
		kernel_version=`uname -r | awk -F "-" '{print $1}'`
		kernel_version_full=`uname -r`
		if [[ ${kernel_version_full} = "4.14.129-bbrplus" ]]; then
			kernel_status="BBRplus"
		elif [[ ${kernel_version} = "3.10.0" || ${kernel_version} = "3.16.0" || ${kernel_version} = "3.2.0" || ${kernel_version} = "4.4.0" || ${kernel_version} = "3.13.0"  || ${kernel_version} = "2.6.32" || ${kernel_version} = "4.9.0" ]]; then
			kernel_status="Lotserver"
		elif [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "4" ]] && [[ `echo ${kernel_version} | awk -F'.' '{print $2}'` -ge 9 ]] || [[ `echo ${kernel_version} | awk -F'.' '{print $1}'` == "5" ]]; then
			kernel_status="BBR"
		else 
			kernel_status="noinstall"
		fi

		if [[ ${kernel_status} == "Lotserver" ]]; then
			if [[ -e /appex/bin/lotServer.sh ]]; then
				run_status=`bash /appex/bin/lotServer.sh status | grep "LotServer" | awk  '{print $3}'`
				if [[ ${run_status} = "running!" ]]; then
					run_status="启动成功"
				else 
					run_status="启动失败"
				fi
			else 
				run_status="未安装加速模块"
			fi
		elif [[ ${kernel_status} == "BBR" ]]; then
			run_status=`grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}'`
			if [[ ${run_status} == "bbr" ]]; then
				run_status=`lsmod | grep "bbr" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_bbr" ]]; then
					run_status="BBR启动成功"
				else 
					run_status="BBR启动失败"
				fi
			elif [[ ${run_status} == "tsunami" ]]; then
				run_status=`lsmod | grep "tsunami" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_tsunami" ]]; then
					run_status="BBR魔改版启动成功"
				else 
					run_status="BBR魔改版启动失败"
				fi
			elif [[ ${run_status} == "nanqinlang" ]]; then
				run_status=`lsmod | grep "nanqinlang" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_nanqinlang" ]]; then
					run_status="暴力BBR魔改版启动成功"
				else 
					run_status="暴力BBR魔改版启动失败"
				fi
			else 
				run_status="未安装加速模块"
			fi
		elif [[ ${kernel_status} == "BBRplus" ]]; then
			run_status=`grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}'`
			if [[ ${run_status} == "bbrplus" ]]; then
				run_status=`lsmod | grep "bbrplus" | awk '{print $1}'`
				if [[ ${run_status} == "tcp_bbrplus" ]]; then
					run_status="BBRplus启动成功"
				else 
					run_status="BBRplus启动失败"
				fi
			else 
				run_status="未安装加速模块"
			fi
		fi
	}
	check_version_bbr
	start_menu_bbr
}

#安装SSR控制面板
install_sspanel(){
	#通知信息
	sspanel_message(){
		echo -e "${Info}搭建成功，现在您可以直接访问了\n"
		echo -e "${Info}ss-panel地址：http://$(get_ip):666"   
		echo -e "${Info}phpadmin地址：http://$(get_ip):8080"
		echo -e "${Info}源码路径：/code/code"
		echo -e "${Info}网页源文件路径：/opt/sspanel/code"
		echo -e "${Info}数据库存储路径：/opt/sspanel/mysql"
		echo -e "\n之后执行剩下的相关命令：
docker exec -it sspanel sh	#进入sspanel容器
php xcat createAdmin		#创建管理员账户
php xcat syncusers			#同步用户
php xcat initQQWry			#下载ip解析库
php xcat resetTraffic		#重置流量
php xcat initdownload		#下载客户端安装包
exit						#退出
\n执行 crontab -e 命令, 添加以下四条（定时任务配置）：
30 22 * * * docker exec -t sspanel php xcat sendDiaryMail
0 0 * * * docker exec -t sspanel php -n xcat dailyjob
*/1 * * * * docker exec -t sspanel php xcat checkjob
*/1 * * * * docker exec -t sspanel php xcat syncnode"
		echo -e "${Info}请务必先记录以上信息！"
		echo -e "\n${Info}按任意键返回主页..."
		char=`get_char`
		start_menu_main
	}
	#稳定版
	sspanel_install_a(){
		mkdir -p /opt/sspanel && cd /opt/sspanel
		rm -f docker-compose.yml 
		wget https://raw.githubusercontent.com/Baiyuetribe/ss-panel-v3-mod_Uim/dev/Docker/master/docker-compose.yml
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成"
		docker-compose up -d
		sspanel_message
	}
	#开发版
	sspanel_install_b(){
		mkdir -p /opt/sspanel && cd /opt/sspanel
		rm -f docker-compose.yml
		docker rmi -f baiyuetribe/sspanel:dev
		wget https://raw.githubusercontent.com/Baiyuetribe/ss-panel-v3-mod_Uim/dev/Docker/docker-compose.yml
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成"
		docker-compose up -d
		sspanel_message
	}
	#管理面板
	manage_sspanel(){
		clear
		echo -e "
	SS-PANEL_NODE 一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
		-- 胖波比 --
	  
————————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装SS-PANEL(稳定版-master分支)
 ${Green_font_prefix}2.${Font_color_suffix} 安装SS-PANEL(开发版-dev分支)
 ${Green_font_prefix}3.${Font_color_suffix} 停止SS-PANEL
 ${Green_font_prefix}4.${Font_color_suffix} 重启SS-PANEL
 ${Green_font_prefix}5.${Font_color_suffix} 卸载SS-PANEL
 ${Green_font_prefix}6.${Font_color_suffix} 回到主页
 ${Green_font_prefix}7.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
		echo
		read -p " 请输入数字 [1-7](默认:7):" num
		[ -z "${num}" ] && num=7
		case "$num" in
			1)
			sspanel_install_a
			;;
			2)
			sspanel_install_b
			;;
			3)
			cd /opt/sspanel
			docker-compose kill
			;;
			4)
			cd /opt/sspanel
			docker-compose restart
			;;
			5)
			cd /opt/sspanel
			docker-compose down
			rm -fr /opt/sspanel
			;;
			6)
			start_menu_main
			;;
			7)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-6]:"
			sleep 2s
			manage_sspanel
			;;
		esac
	}
	manage_sspanel
}

#安装Caddy
install_caddy(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH
	#=================================================
	#       System Required: CentOS/Debian/Ubuntu
	#       Description: Caddy Install
	#       Version: 1.0.8
	#       Author: Toyo
	#       Blog: https://doub.io/shell-jc1/
	#=================================================
	file="/usr/local/caddy/"
	caddy_file="/usr/local/caddy/caddy"
	caddy_conf_file="/usr/local/caddy/Caddyfile"
	Info_font_prefix="\033[32m" && Error_font_prefix="\033[31m" && Info_background_prefix="\033[42;37m" && Error_background_prefix="\033[41;37m" && Font_suffix="\033[0m"

	check_installed_status(){
		[[ ! -e ${caddy_file} ]] && echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy 没有安装，请检查 !" && exit 1
	}
	Download_caddy(){
		[[ ! -e ${file} ]] && mkdir "${file}"
		cd "${file}"
		PID=$(ps -ef |grep "caddy" |grep -v "grep" |grep -v "init.d" |grep -v "service" |grep -v "caddy_install" |awk '{print $2}')
		[[ ! -z ${PID} ]] && kill -9 ${PID}
		[[ -e "caddy_linux*.tar.gz" ]] && rm -rf "caddy_linux*.tar.gz"
		
		if [[ ! -z ${extension} ]]; then
			extension_all="?plugins=${extension}&license=personal"
		else
			extension_all="?license=personal"
		fi
		
		if [[ ${bit} == "x86_64" ]]; then
			wget --no-check-certificate -O "caddy_linux.tar.gz" "https://caddyserver.com/download/linux/amd64${extension_all}"
		elif [[ ${bit} == "i386" || ${bit} == "i686" ]]; then
			wget --no-check-certificate -O "caddy_linux.tar.gz" "https://caddyserver.com/download/linux/386${extension_all}"
		elif [[ ${bit} == "armv7l" ]]; then
			wget --no-check-certificate -O "caddy_linux.tar.gz" "https://caddyserver.com/download/linux/arm7${extension_all}"
		else
			echo -e "${Error_font_prefix}[错误]${Font_suffix} 不支持 [${bit}] ! 请向本站反馈[]中的名称，我会看看是否可以添加支持。" && exit 1
		fi
		[[ ! -e "caddy_linux.tar.gz" ]] && echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy 下载失败 !" && exit 1
		tar zxf "caddy_linux.tar.gz"
		rm -rf "caddy_linux.tar.gz"
		[[ ! -e ${caddy_file} ]] && echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy 解压失败或压缩文件错误 !" && exit 1
		rm -rf LICENSES.txt
		rm -rf README.txt 
		rm -rf CHANGES.txt
		rm -rf "init/"
		chmod +x caddy
	}
	Service_caddy(){
		if [[ ${release} = "centos" ]]; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/caddy_centos -O /etc/init.d/caddy; then
				echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy服务 管理脚本下载失败 !" && exit 1
			fi
			chmod +x /etc/init.d/caddy
			chkconfig --add caddy
			chkconfig caddy on
		else
			if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/caddy_debian -O /etc/init.d/caddy; then
				echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy服务 管理脚本下载失败 !" && exit 1
			fi
			chmod +x /etc/init.d/caddy
			update-rc.d -f caddy defaults
		fi
		extension=$2
	}
	set_caddy(){
		#配置Caddy
		set_caddy_http(){
			echo && echo -e " Caddy监听一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --"
			read -p " 请输入你的域名(默认本机IP):" domain
			[ -z "${domain}" ] && domain=$(get_ip)
			read -p "请输入监听端口[1-65535],已默认添加80端口" port
			[ -z "${port}" ] && port=80
			add_firewall
			firewall_restart
			echo "http://$domain {
root /usr/local/caddy/listenport
proxy / 127.0.0.1:$port
timeouts none
gzip
}" > /usr/local/caddy/Caddyfile
			service caddy restart
			echo -e "${Info}Caddy重启成功!"
			sleep 2s
		}
		set_caddy_https(){
			echo && echo -e " Caddy监听一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
    -- 胖波比 --"
			read -p " 请输入你的域名(默认本机IP):" domain
			[ -z "${domain}" ] && domain=$(get_ip)
			read -p "请输入监听端口[1-65535],已默认添加443端口" port
			[ -z "${port}" ] && port=443
			add_firewall
			firewall_restart
			read -p " 请输入你的邮箱:" yemail
			echo "https://$domain {
root /usr/local/caddy/listenport
proxy / 127.0.0.1:$port
timeouts none
tls $yemail
gzip
}" > /usr/local/caddy/Caddyfile
			port=80
			add_firewall
			port=443
			add_firewall
			firewall_restart
			service caddy restart
			echo -e "${Info}Caddy重启成功，请手动配置SSR或V2Ray监听端口"
			sleep 2s
		}
		#Caddy设置菜单
		start_menu_set_caddy(){
			clear
			echo && echo -e " Caddy监听一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
			
————————————伪装方式————————————
 ${Green_font_prefix}1.${Font_color_suffix} HTTP伪装
 ${Green_font_prefix}2.${Font_color_suffix} HTTPS伪装
 ${Green_font_prefix}3.${Font_color_suffix} 回到上级目录
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

			echo
			read -p " 请输入数字 [1-5](默认:5):" num
			[ -z "${num}" ] && num=5
			case "$num" in
				1)
				set_caddy_http
				;;
				2)
				set_caddy_https
				;;
				3)
				start_menu_caddy
				;;
				4)
				start_menu_main
				;;
				5)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-5]"
				sleep 2s
				start_menu_set_caddy
				;;
			esac
		}
		start_menu_set_caddy
	}
	install_caddy(){
		if [[ -e ${caddy_file} ]]; then
			echo && echo -e "${Error_font_prefix}[信息]${Font_suffix} 检测到 Caddy 已安装，是否继续安装(覆盖更新)？[y/N]"
			read -e -p "(默认: n):" yn
			[[ -z ${yn} ]] && yn="n"
			if [[ ${yn} == [Nn] ]]; then
				echo && echo "已取消..."
				sleep 2s
				start_menu_caddy
			fi
		fi
		Download_caddy
		Service_caddy
		#设置Caddy监听地址文件夹
		mkdir /usr/local/caddy/listenport
		echo -e "${Info}正在下载网页。请稍等···"
		svn checkout "https://github.com/AmuyangA/internet/trunk/html" /usr/local/caddy/listenport
		set_caddy
		echo && echo -e " Caddy 使用命令：${caddy_conf_file}
 日志文件：cat /tmp/caddy.log
 使用说明：service caddy start | stop | restart | status
 或者使用：/etc/init.d/caddy start | stop | restart | status
 ${Info}Caddy 安装完成！" && echo
	}
	uninstall_caddy(){
		check_installed_status
		echo && echo "确定要卸载 Caddy ? [y/N]"
		read -e -p "(默认: n):" unyn
		[[ -z ${unyn} ]] && unyn="n"
		if [[ ${unyn} == [Yy] ]]; then
			PID=`ps -ef |grep "caddy" |grep -v "grep" |grep -v "init.d" |grep -v "service" |grep -v "caddy_install" |awk '{print $2}'`
			[[ ! -z ${PID} ]] && kill -9 ${PID}
			if [[ ${release} = "centos" ]]; then
				chkconfig --del caddy
			else
				update-rc.d -f caddy remove
			fi
			[[ -s /tmp/caddy.log ]] && rm -rf /tmp/caddy.log
			rm -rf ${caddy_file}
			rm -rf ${caddy_conf_file}
			rm -rf /etc/init.d/caddy
			#删除Caddy监听地址文件夹
			rm -rf /usr/local/caddy
			[[ ! -e ${caddy_file} ]] && echo && echo -e "${Info_font_prefix}[信息]${Font_suffix} Caddy 卸载完成 !" && echo && exit 1
			echo && echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy 卸载失败 !" && echo
		else
			echo && echo "卸载已取消..."
			sleep 2s
			start_menu_caddy
		fi
	}
	manage_caddy(){
		clear
		echo && echo -e " Caddy一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
		
————————————Caddy管理————————————
 ${Green_font_prefix}1.${Font_color_suffix} 配置Caddy
 ${Green_font_prefix}2.${Font_color_suffix} 启动Caddy
 ${Green_font_prefix}3.${Font_color_suffix} 关闭Caddy
 ${Green_font_prefix}4.${Font_color_suffix} 重启Caddy
 ${Green_font_prefix}5.${Font_color_suffix} 查看Caddy状态
 ${Green_font_prefix}6.${Font_color_suffix} 回到主页
 ${Green_font_prefix}7.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		echo
		read -p " 请输入数字 [1-7](默认:7):" num
		[ -z "${num}" ] && num=7
		case "$num" in
			1)
			set_caddy
			;;
			2)
			service caddy start
			;;
			3)
			service caddy stop
			;;
			4)
			service caddy restart
			;;
			5)
			service caddy status
			;;
			6)
			start_menu_main
			;;
			7)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-7]"
			sleep 2s
			manage_caddy
			;;
		esac
		manage_caddy
	}
	#开始菜单
	start_menu_caddy(){
		clear
		echo && echo -e " Caddy一键安装脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
		
————————————Caddy安装————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装Caddy
 ${Green_font_prefix}2.${Font_color_suffix} 卸载Caddy
 ${Green_font_prefix}3.${Font_color_suffix} 管理Caddy
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		echo
		read -p " 请输入数字 [1-5](默认:5):" num
		[ -z "${num}" ] && num=5
		case "$num" in
			1)
			install_caddy
			;;
			2)
			uninstall_caddy
			;;
			3)
			manage_caddy
			;;
			4)
			start_menu_main
			;;
			5)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-5]"
			sleep 2s
			start_menu_caddy
			;;
		esac
	}
	start_menu_caddy
}

#安装Nginx
install_nginx(){
	nginx_install(){
		#!/usr/bin/env bash
		PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
		export PATH
		
			if [[ "${release}" == "centos" ]]; then
				 setsebool -P httpd_can_network_connect 1
					 touch /etc/yum.repos.d/nginx.repo
cat <<EOF > /etc/yum.repos.d/nginx.repo
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/mainline/centos/7/\$basearch/
gpgcheck=0
enabled=1
EOF
					 yum -y install nginx
			elif [[ "${release}" == "debian" ]]; then
					 echo "deb http://nginx.org/packages/debian/ stretch nginx" >> /etc/apt/sources.list
					 echo "deb-src http://nginx.org/packages/debian/ stretch nginx" >> /etc/apt/sources.list
					 wget http://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
			 apt-key add nginx_signing.key >/dev/null 2>&1
					 apt-get update
					 apt-get -y install nginx
					 rm -rf add nginx_signing.key >/dev/null 2>&1
			elif [[ "${release}" == "ubuntu" ]]; then
					 echo "deb http://nginx.org/packages/mainline/ubuntu/ bionic nginx" >> /etc/apt/sources.list
			 echo "deb http://nginx.org/packages/mainline/ubuntu/ xenial nginx" >> /etc/apt/sources.list
					 echo "deb-src http://nginx.org/packages/mainline/ubuntu/ bionic nginx" >> /etc/apt/sources.list
			 echo "deb-src http://nginx.org/packages/mainline/ubuntu/ xenial nginx" >> /etc/apt/sources.list
					 wget -N --no-check-certificate https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
			 apt-key add nginx_signing.key >/dev/null 2>&1
					 apt-get update
					 apt-get -y install nginx
					 rm -rf add nginx_signing.key >/dev/null 2>&1
			fi
		echo -e "${Info}安装完成！1秒后开启Nginx"
		sleep 1s
		systemctl start nginx.service
		echo -e "${Info}Nginx已开启！1秒后回到管理页"
		sleep 1s
		manage_nginx
	}
	
	#配置Nginx
	set_nginx(){
		#配置结尾
		set_nginx_success(){
			echo -e "${Info}修改Nginx配置成功，2秒后重启Nginx"
			sleep 2s
			systemctl restart nginx.service
			echo -e "${Info}Nginx重启成功，1秒后回到配置管理页"
			sleep 1s
			set_nginx_menu
		}
		#添加监听端口
		add_nginx(){
			cat /etc/nginx/conf.d/default.conf
			read -p "请输入端口[1-65535],不可重复,(默认:8080):" port
			[ -z "${port}" ] && port=8080
			add_firewall
			firewall_restart
			sed -i "2i\\\tlisten ${port};" /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#删除监听端口
		delete_nginx(){
			cat /etc/nginx/conf.d/default.conf
			read -p "请输入端口[1-65535],已有端口,(默认:8080):" port
			[ -z "${port}" ] && port=8080
			port=$(sed -n -e '/${port}/=' /etc/nginx/conf.d/default.conf)
			sed -i '${port} d' /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#配置方式选择
		set_nginx_menu(){
			clear
			echo && echo -e " Nginx配置管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
		
——————————Nginx配置管理—————————
 ${Green_font_prefix}1.${Font_color_suffix} 添加监听端口(不可添加已占用端口)
 ${Green_font_prefix}2.${Font_color_suffix} 删除监听端口
 ${Green_font_prefix}3.${Font_color_suffix} 回到主页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
			read -p " 请输入数字 [1-4](默认:4):" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				add_nginx
				;;
				2)
				delete_nginx
				;;
				3)
				start_menu_main
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-4]"
				sleep 2s
				set_nginx_menu
				;;
			esac
		}
		#默认配置
		test ! -e /root/testng || set_nginx_menu
		#设置Nginx网页
		rm -f /usr/share/nginx/html/index.html
		echo -e "${Info}正在下载网页。请稍等···"
		sleep 2s
		svn checkout "https://github.com/AmuyangA/internet/trunk/html" /usr/share/nginx/html
		#修改Nginx配置文件
		echo "server {
	listen 80;
	listen 443;
	server_name  localhost;
	location / {
		root /usr/share/nginx/html;
		index  index.html index.htm;
	}
	error_page   500 502 503 504  /50x.html;
	location = /50x.html {
		root /usr/share/nginx/html;
	}
}" > /etc/nginx/conf.d/default.conf
		touch /root/testng
		port=80
		add_firewall
		port=443
		add_firewall
		firewall_restart
		echo -e "${Info}已默认添加80,443端口
如需手动配置，请修改：/etc/nginx/conf.d/default.conf"
		set_nginx_success
	}
	
	#Nginx管理
	manage_nginx(){
		clear
		echo && echo -e " Nginx一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
		
————————————Nginx管理————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装Nginx
 ${Green_font_prefix}2.${Font_color_suffix} 配置Nginx
 ${Green_font_prefix}3.${Font_color_suffix} 启动Nginx
 ${Green_font_prefix}4.${Font_color_suffix} 关闭Nginx
 ${Green_font_prefix}5.${Font_color_suffix} 重启Nginx
 ${Green_font_prefix}6.${Font_color_suffix} 查看Nginx状态
 ${Green_font_prefix}7.${Font_color_suffix} 回到主页
 ${Green_font_prefix}8.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
		read -p " 请输入数字 [1-8](默认:8):" num
		[ -z "${num}" ] && num=8
		case "$num" in
			1)
			nginx_install
			;;
			2)
			set_nginx
			;;
			3)
			systemctl start nginx.service
			;;
			4)
			systemctl stop nginx.service
			;;
			5)
			systemctl restart nginx.service
			;;
			6)
			systemctl status nginx.service
			;;
			7)
			start_menu_main
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-8]"
			sleep 2s
			manage_nginx
			;;
		esac
	}
	manage_nginx
 }

#设置SSH端口
set_ssh(){
	# Use default SSH port 22. If you use another SSH port on your server
	if [ -e "/etc/ssh/sshd_config" ];then
		[ -z "`grep ^Port /etc/ssh/sshd_config`" ] && ssh_port=22 || ssh_port=`grep ^Port /etc/ssh/sshd_config | awk '{print $2}'`
		while :; do echo
			read -p "Please input SSH port(Default: $ssh_port): " SSH_PORT
			[ -z "$SSH_PORT" ] && SSH_PORT=$ssh_port
			if [ $SSH_PORT -eq 22 >/dev/null 2>&1 -o $SSH_PORT -gt 1024 >/dev/null 2>&1 -a $SSH_PORT -lt 65535 >/dev/null 2>&1 ];then
				break
			else
				echo "${CWARNING}input error! Input range: 22,1025~65534${CEND}"
			fi
		done
	 
		if [ -z "`grep ^Port /etc/ssh/sshd_config`" -a "$SSH_PORT" != '22' ];then
			sed -i "s@^#Port.*@&\nPort $SSH_PORT@" /etc/ssh/sshd_config
		elif [ -n "`grep ^Port /etc/ssh/sshd_config`" ];then
			sed -i "s@^Port.*@Port $SSH_PORT@" /etc/ssh/sshd_config
		fi
	fi
	#开放端口
	port=$SSH_PORT
	add_firewall
	firewall_restart
	#重启SSH防火墙
	if [[ "${release}" == "centos" ]]; then
		service sshd restart
	elif [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
		service ssh restart
	fi
	echo -e "${Info}SSH防火墙已重启！"
	echo -e "${Info}已将SSH端口修改为：${Red_font_prefix}${port}${Font_color_suffix}"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
	start_menu_main
 }
 
#设置Root密码
set_root(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH

	#=================================================
	#	System Required: CentOS 6+,Debian7+,Ubuntu12+
	#	Description: 设置修改root用户登录密码
	#	Version: 2.0
	#	Author: 胖波比
	#	Project: https://github.com/AmuyangA/
	#=================================================

	github="https://github.com/AmuyangA/internet/"
	
	#一键启用root帐号命令
	if [[ "${release}" == "centos" ]]; then
		# 修改root 密码
		echo "请输入 passwd  命令修改root用户的密码"
		passwd root
		# 启用root密码登陆
		sed -i "s/PermitRootLogin.*/PermitRootLogin yes/g"   /etc/ssh/sshd_config
		sed -i "s/PasswordAuthentication.*/PasswordAuthentication yes/g"   /etc/ssh/sshd_config
		# 重启ssh服务
		service sshd restart	
	elif [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
		# 修改root 密码
		echo "请输入 passwd  命令修改root用户的密码"
		passwd root
		# 启用root密码登陆
		sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/g"   /etc/ssh/sshd_config
		sed -i "s/PasswordAuthentication.*/PasswordAuthentication yes/g"   /etc/ssh/sshd_config
		# 重启ssh服务
		service ssh restart
	fi
	echo -e "${Info}Root密码已更改！2秒后回到主页"
	sleep 2s
	start_menu_main
}

#系统性能测试
test_sys(){
	#千影大佬的脚本
	qybench(){
		clear
		echo && echo -e " 系统性能一键测试综合脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
			
————————————性能测试————————————
 ${Green_font_prefix}1.${Font_color_suffix} 运行（不含UnixBench）
 ${Green_font_prefix}2.${Font_color_suffix} 运行（含UnixBench）
 ${Green_font_prefix}3.${Font_color_suffix} 回到主页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		echo
		wget https://raw.githubusercontent.com/AmuyangA/internet/master/bench/linuxtest.sh && chmod +x linuxtest.sh
		read -p " 请输入数字 [1-4](默认:4):" num
		[ -z "${num}" ] && num=4
		case "$num" in
			1)
			bash linuxtest.sh
			;;
			2)
			bash linuxtest.sh a
			;;
			3)
			start_menu_main
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-4]"
			sleep 2s
			qybench
			;;
		esac
	}
	
	#ipv4与ipv6测试
	ibench(){
		#!/usr/bin/env bash
		#
		# Description: Auto test download & I/O speed script
		#
		# Copyright (C) 2015 - 2019 Teddysun <i@teddysun.com>
		#
		# Thanks: LookBack <admin@dwhd.org>
		#
		# URL: https://teddysun.com/444.html
		#

		if  [ ! -e '/usr/bin/wget' ]; then
			echo "Error: wget command not found. You must be install wget command at first."
			exit 1
		fi

		# Colors
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		BLUE='\033[0;36m'
		PLAIN='\033[0m'

		get_opsy() {
			[ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
			[ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
			[ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
		}

		next() {
			printf "%-70s\n" "-" | sed 's/\s/-/g'
		}

		speed_test_v4() {
			local output=$(LANG=C wget -4O /dev/null -T300 $1 2>&1)
			local speedtest=$(printf '%s' "$output" | awk '/\/dev\/null/ {speed=$3 $4} END {gsub(/\(|\)/,"",speed); print speed}')
			local ipaddress=$(printf '%s' "$output" | awk -F'|' '/Connecting to .*\|([^\|]+)\|/ {print $2}')
			local nodeName=$2
			printf "${YELLOW}%-32s${GREEN}%-24s${RED}%-14s${PLAIN}\n" "${nodeName}" "${ipaddress}" "${speedtest}"
		}

		speed_test_v6() {
			local output=$(LANG=C wget -6O /dev/null -T300 $1 2>&1)
			local speedtest=$(printf '%s' "$output" | awk '/\/dev\/null/ {speed=$3 $4} END {gsub(/\(|\)/,"",speed); print speed}')
			local ipaddress=$(printf '%s' "$output" | awk -F'|' '/Connecting to .*\|([^\|]+)\|/ {print $2}')
			local nodeName=$2
			printf "${YELLOW}%-32s${GREEN}%-24s${RED}%-14s${PLAIN}\n" "${nodeName}" "${ipaddress}" "${speedtest}"
		}

		speed_v4() {
			speed_test_v4 'http://cachefly.cachefly.net/100mb.test' 'CacheFly'
			speed_test_v4 'http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin' 'Linode, Tokyo2, JP'
			speed_test_v4 'http://speedtest.singapore.linode.com/100MB-singapore.bin' 'Linode, Singapore, SG'
			speed_test_v4 'http://speedtest.london.linode.com/100MB-london.bin' 'Linode, London, UK'
			speed_test_v4 'http://speedtest.frankfurt.linode.com/100MB-frankfurt.bin' 'Linode, Frankfurt, DE'
			speed_test_v4 'http://speedtest.fremont.linode.com/100MB-fremont.bin' 'Linode, Fremont, CA'
			speed_test_v4 'http://speedtest.dal05.softlayer.com/downloads/test100.zip' 'Softlayer, Dallas, TX'
			speed_test_v4 'http://speedtest.sea01.softlayer.com/downloads/test100.zip' 'Softlayer, Seattle, WA'
			speed_test_v4 'http://speedtest.fra02.softlayer.com/downloads/test100.zip' 'Softlayer, Frankfurt, DE'
			speed_test_v4 'http://speedtest.sng01.softlayer.com/downloads/test100.zip' 'Softlayer, Singapore, SG'
			speed_test_v4 'http://speedtest.hkg02.softlayer.com/downloads/test100.zip' 'Softlayer, HongKong, CN'
		}

		speed_v6() {
			speed_test_v6 'http://speedtest.atlanta.linode.com/100MB-atlanta.bin' 'Linode, Atlanta, GA'
			speed_test_v6 'http://speedtest.dallas.linode.com/100MB-dallas.bin' 'Linode, Dallas, TX'
			speed_test_v6 'http://speedtest.newark.linode.com/100MB-newark.bin' 'Linode, Newark, NJ'
			speed_test_v6 'http://speedtest.singapore.linode.com/100MB-singapore.bin' 'Linode, Singapore, SG'
			speed_test_v6 'http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin' 'Linode, Tokyo2, JP'
			speed_test_v6 'http://speedtest.sjc03.softlayer.com/downloads/test100.zip' 'Softlayer, San Jose, CA'
			speed_test_v6 'http://speedtest.wdc01.softlayer.com/downloads/test100.zip' 'Softlayer, Washington, WA'
			speed_test_v6 'http://speedtest.par01.softlayer.com/downloads/test100.zip' 'Softlayer, Paris, FR'
			speed_test_v6 'http://speedtest.sng01.softlayer.com/downloads/test100.zip' 'Softlayer, Singapore, SG'
			speed_test_v6 'http://speedtest.tok02.softlayer.com/downloads/test100.zip' 'Softlayer, Tokyo, JP'
		}

		io_test() {
			(LANG=C dd if=/dev/zero of=test_$$ bs=64k count=16k conv=fdatasync && rm -f test_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
		}

		calc_disk() {
			local total_size=0
			local array=$@
			for size in ${array[@]}
			do
				[ "${size}" == "0" ] && size_t=0 || size_t=`echo ${size:0:${#size}-1}`
				[ "`echo ${size:(-1)}`" == "K" ] && size=0
				[ "`echo ${size:(-1)}`" == "M" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' / 1024}' )
				[ "`echo ${size:(-1)}`" == "T" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' * 1024}' )
				[ "`echo ${size:(-1)}`" == "G" ] && size=${size_t}
				total_size=$( awk 'BEGIN{printf "%.1f", '$total_size' + '$size'}' )
			done
			echo ${total_size}
		}

		cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
		cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
		freq=$( awk -F'[ :]' '/cpu MHz/ {print $4;exit}' /proc/cpuinfo )
		tram=$( free -m | awk '/Mem/ {print $2}' )
		uram=$( free -m | awk '/Mem/ {print $3}' )
		swap=$( free -m | awk '/Swap/ {print $2}' )
		uswap=$( free -m | awk '/Swap/ {print $3}' )
		up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days, %d hour %d min\n",a,b,c)}' /proc/uptime )
		load=$( w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
		opsy=$( get_opsy )
		arch=$( uname -m )
		lbit=$( getconf LONG_BIT )
		kern=$( uname -r )
		#ipv6=$( wget -qO- -t1 -T2 ipv6.icanhazip.com )
		disk_size1=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|devtmpfs|by-uuid|chroot|Filesystem|udev|docker' | awk '{print $2}' ))
		disk_size2=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|devtmpfs|by-uuid|chroot|Filesystem|udev|docker' | awk '{print $3}' ))
		disk_total_size=$( calc_disk "${disk_size1[@]}" )
		disk_used_size=$( calc_disk "${disk_size2[@]}" )

		clear
		next
		echo -e "CPU model            : ${BLUE}$cname${PLAIN}"
		echo -e "Number of cores      : ${BLUE}$cores${PLAIN}"
		echo -e "CPU frequency        : ${BLUE}$freq MHz${PLAIN}"
		echo -e "Total size of Disk   : ${BLUE}$disk_total_size GB ($disk_used_size GB Used)${PLAIN}"
		echo -e "Total amount of Mem  : ${BLUE}$tram MB ($uram MB Used)${PLAIN}"
		echo -e "Total amount of Swap : ${BLUE}$swap MB ($uswap MB Used)${PLAIN}"
		echo -e "System uptime        : ${BLUE}$up${PLAIN}"
		echo -e "Load average         : ${BLUE}$load${PLAIN}"
		echo -e "OS                   : ${BLUE}$opsy${PLAIN}"
		echo -e "Arch                 : ${BLUE}$arch ($lbit Bit)${PLAIN}"
		echo -e "Kernel               : ${BLUE}$kern${PLAIN}"
		next
		io1=$( io_test )
		echo -e "I/O speed(1st run)   : ${YELLOW}$io1${PLAIN}"
		io2=$( io_test )
		echo -e "I/O speed(2nd run)   : ${YELLOW}$io2${PLAIN}"
		io3=$( io_test )
		echo -e "I/O speed(3rd run)   : ${YELLOW}$io3${PLAIN}"
		ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
		[ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
		ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
		[ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
		ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
		[ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
		ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
		ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
		echo -e "Average I/O speed    : ${YELLOW}$ioavg MB/s${PLAIN}"
		next
		printf "%-32s%-24s%-14s\n" "Node Name" "IPv4 address" "Download Speed"
		speed_v4 && next
		#if [[ "$ipv6" != "" ]]; then
		#    printf "%-32s%-24s%-14s\n" "Node Name" "IPv6 address" "Download Speed"
		#    speed_v6 && next
		#fi
	}
	
	#国内各地检测
	cbench(){
		#!/usr/bin/env bash
		#
		# Description: Auto system info & I/O test & network to China script
		#
		# Copyright (C) 2017 - 2018 Oldking <oooldking@gmail.com>
		#
		# Thanks: Bench.sh <i@teddysun.com>
		#
		# URL: https://www.oldking.net/350.html
		#

		# Colors
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		SKYBLUE='\033[0;36m'
		PLAIN='\033[0m'

		about() {
			echo ""
			echo " ========================================================= "
			echo " \                 Superbench.sh  Script                 / "
			echo " \       Basic system info, I/O test and speedtest       / "
			echo " \                   v1.1.5 (14 Jun 2019)                / "
			echo " \                   Created by Oldking                  / "
			echo " ========================================================= "
			echo ""
			echo " Intro: https://www.oldking.net/350.html"
			echo " Copyright (C) 2019 Oldking oooldking@gmail.com"
			echo -e " ${RED}Happy New Year!${PLAIN}"
			echo ""
		}

		cancel() {
			echo ""
			next;
			echo " Abort ..."
			echo " Cleanup ..."
			cleanup;
			echo " Done"
			exit
		}

		trap cancel SIGINT

		benchinit() {
			# check python
			if  [ ! -e '/usr/bin/python' ]; then
					#echo -e
					#read -p "${RED}Error:${PLAIN} python is not install. You must be install python command at first.\nDo you want to install? [y/n]" is_install
					#if [[ ${is_install} == "y" || ${is_install} == "Y" ]]; then
					echo " Installing Python ..."
						if [ "${release}" == "centos" ]; then
								yum update > /dev/null 2>&1
								yum -y install python > /dev/null 2>&1
							else
								apt-get update > /dev/null 2>&1
								apt-get -y install python > /dev/null 2>&1
							fi
					#else
					#    exit
					#fi
					
			fi

			# check curl
			if  [ ! -e '/usr/bin/curl' ]; then
				#echo -e
				#read -p "${RED}Error:${PLAIN} curl is not install. You must be install curl command at first.\nDo you want to install? [y/n]" is_install
				#if [[ ${is_install} == "y" || ${is_install} == "Y" ]]; then
					echo " Installing Curl ..."
						if [ "${release}" == "centos" ]; then
							yum update > /dev/null 2>&1
							yum -y install curl > /dev/null 2>&1
						else
							apt-get update > /dev/null 2>&1
							apt-get -y install curl > /dev/null 2>&1
						fi
				#else
				#    exit
				#fi
			fi

			# check wget
			if  [ ! -e '/usr/bin/wget' ]; then
				#echo -e
				#read -p "${RED}Error:${PLAIN} wget is not install. You must be install wget command at first.\nDo you want to install? [y/n]" is_install
				#if [[ ${is_install} == "y" || ${is_install} == "Y" ]]; then
					echo " Installing Wget ..."
						if [ "${release}" == "centos" ]; then
							yum update > /dev/null 2>&1
							yum -y install wget > /dev/null 2>&1
						else
							apt-get update > /dev/null 2>&1
							apt-get -y install wget > /dev/null 2>&1
						fi
				#else
				#    exit
				#fi
			fi

			# install virt-what
			#if  [ ! -e '/usr/sbin/virt-what' ]; then
			#	echo "Installing Virt-what ..."
			#    if [ "${release}" == "centos" ]; then
			#    	yum update > /dev/null 2>&1
			#        yum -y install virt-what > /dev/null 2>&1
			#    else
			#    	apt-get update > /dev/null 2>&1
			#        apt-get -y install virt-what > /dev/null 2>&1
			#    fi      
			#fi

			# install jq
			#if  [ ! -e '/usr/bin/jq' ]; then
			# 	echo " Installing Jq ..."
			#		if [ "${release}" == "centos" ]; then
			#	    yum update > /dev/null 2>&1
			#	    yum -y install jq > /dev/null 2>&1
			#	else
			#	    apt-get update > /dev/null 2>&1
			#	    apt-get -y install jq > /dev/null 2>&1
			#	fi      
			#fi

			# install speedtest-cli
			if  [ ! -e 'speedtest.py' ]; then
				echo " Installing Speedtest-cli ..."
				wget --no-check-certificate https://raw.github.com/sivel/speedtest-cli/master/speedtest.py > /dev/null 2>&1
			fi
			chmod a+rx speedtest.py


			# install tools.py
			if  [ ! -e 'tools.py' ]; then
				echo " Installing tools.py ..."
				wget --no-check-certificate https://raw.githubusercontent.com/oooldking/script/master/tools.py > /dev/null 2>&1
			fi
			chmod a+rx tools.py

			# install fast.com-cli
			if  [ ! -e 'fast_com.py' ]; then
				echo " Installing Fast.com-cli ..."
				wget --no-check-certificate https://raw.githubusercontent.com/sanderjo/fast.com/master/fast_com.py > /dev/null 2>&1
				wget --no-check-certificate https://raw.githubusercontent.com/sanderjo/fast.com/master/fast_com_example_usage.py > /dev/null 2>&1
			fi
			chmod a+rx fast_com.py
			chmod a+rx fast_com_example_usage.py

			sleep 5

			# start
			start=$(date +%s) 
		}

		get_opsy() {
			[ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
			[ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
			[ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
		}

		next() {
			printf "%-70s\n" "-" | sed 's/\s/-/g' | tee -a $log
		}

		speed_test(){
			if [[ $1 == '' ]]; then
				temp=$(python speedtest.py --share 2>&1)
				is_down=$(echo "$temp" | grep 'Download')
				result_speed=$(echo "$temp" | awk -F ' ' '/results/{print $3}')
				if [[ ${is_down} ]]; then
					local REDownload=$(echo "$temp" | awk -F ':' '/Download/{print $2}')
					local reupload=$(echo "$temp" | awk -F ':' '/Upload/{print $2}')
					local relatency=$(echo "$temp" | awk -F ':' '/Hosted/{print $2}')

					temp=$(echo "$relatency" | awk -F '.' '{print $1}')
					if [[ ${temp} -gt 50 ]]; then
						relatency=" (*)"${relatency}
					fi
					local nodeName=$2

					temp=$(echo "${REDownload}" | awk -F ' ' '{print $1}')
					if [[ $(awk -v num1=${temp} -v num2=0 'BEGIN{print(num1>num2)?"1":"0"}') -eq 1 ]]; then
						printf "${YELLOW}%-17s${GREEN}%-18s${RED}%-20s${SKYBLUE}%-12s${PLAIN}\n" " ${nodeName}" "${reupload}" "${REDownload}" "${relatency}" | tee -a $log
					fi
				else
					local cerror="ERROR"
				fi
			else
				temp=$(python speedtest.py --server $1 --share 2>&1)
				is_down=$(echo "$temp" | grep 'Download') 
				if [[ ${is_down} ]]; then
					local REDownload=$(echo "$temp" | awk -F ':' '/Download/{print $2}')
					local reupload=$(echo "$temp" | awk -F ':' '/Upload/{print $2}')
					local relatency=$(echo "$temp" | awk -F ':' '/Hosted/{print $2}')
					#local relatency=$(pingtest $3)
					#temp=$(echo "$relatency" | awk -F '.' '{print $1}')
					#if [[ ${temp} -gt 1000 ]]; then
						relatency=" - "
					#fi
					local nodeName=$2

					temp=$(echo "${REDownload}" | awk -F ' ' '{print $1}')
					if [[ $(awk -v num1=${temp} -v num2=0 'BEGIN{print(num1>num2)?"1":"0"}') -eq 1 ]]; then
						printf "${YELLOW}%-17s${GREEN}%-18s${RED}%-20s${SKYBLUE}%-12s${PLAIN}\n" " ${nodeName}" "${reupload}" "${REDownload}" "${relatency}" | tee -a $log
					fi
				else
					local cerror="ERROR"
				fi
			fi
		}

		print_speedtest() {
			printf "%-18s%-18s%-20s%-12s\n" " Node Name" "Upload Speed" "Download Speed" "Latency" | tee -a $log
			speed_test '' 'Speedtest.net'
			speed_fast_com
			speed_test '17251' 'Guangzhou CT'
			speed_test '23844' 'Wuhan     CT'
			speed_test '7509' 'Hangzhou  CT'
			speed_test '3973' 'Lanzhou   CT'
			speed_test '24447' 'Shanghai  CU'
			speed_test '5724' "Heifei    CU"
			speed_test '5726' 'Chongqing CU'
			speed_test '17228' 'Xinjiang  CM'
			speed_test '18444' 'Xizang    CM'
			 
			rm -rf speedtest.py
		}

		print_speedtest_fast() {
			printf "%-18s%-18s%-20s%-12s\n" " Node Name" "Upload Speed" "Download Speed" "Latency" | tee -a $log
			speed_test '' 'Speedtest.net'
			speed_fast_com
			speed_test '7509' 'Hangzhou  CT'
			speed_test '24447' 'Shanghai  CU'
			speed_test '18444' 'Xizang    CM'
			 
			rm -rf speedtest.py
		}

		speed_fast_com() {
			temp=$(python fast_com_example_usage.py 2>&1)
			is_down=$(echo "$temp" | grep 'Result') 
				if [[ ${is_down} ]]; then
					temp1=$(echo "$temp" | awk -F ':' '/Result/{print $2}')
					temp2=$(echo "$temp1" | awk -F ' ' '/Mbps/{print $1}')
					local REDownload="$temp2 Mbit/s"
					local reupload="0.00 Mbit/s"
					local relatency="-"
					local nodeName="Fast.com"

					printf "${YELLOW}%-18s${GREEN}%-18s${RED}%-20s${SKYBLUE}%-12s${PLAIN}\n" " ${nodeName}" "${reupload}" "${REDownload}" "${relatency}" | tee -a $log
				else
					local cerror="ERROR"
				fi
			rm -rf fast_com_example_usage.py
			rm -rf fast_com.py

		}

		io_test() {
			(LANG=C dd if=/dev/zero of=test_file_$$ bs=512K count=$1 conv=fdatasync && rm -f test_file_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
		}

		calc_disk() {
			local total_size=0
			local array=$@
			for size in ${array[@]}
			do
				[ "${size}" == "0" ] && size_t=0 || size_t=`echo ${size:0:${#size}-1}`
				[ "`echo ${size:(-1)}`" == "K" ] && size=0
				[ "`echo ${size:(-1)}`" == "M" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' / 1024}' )
				[ "`echo ${size:(-1)}`" == "T" ] && size=$( awk 'BEGIN{printf "%.1f", '$size_t' * 1024}' )
				[ "`echo ${size:(-1)}`" == "G" ] && size=${size_t}
				total_size=$( awk 'BEGIN{printf "%.1f", '$total_size' + '$size'}' )
			done
			echo ${total_size}
		}

		power_time() {

			result=$(smartctl -a $(result=$(cat /proc/mounts) && echo $(echo "$result" | awk '/data=ordered/{print $1}') | awk '{print $1}') 2>&1) && power_time=$(echo "$result" | awk '/Power_On/{print $10}') && echo "$power_time"
		}

		install_smart() {
			# install smartctl
			if  [ ! -e '/usr/sbin/smartctl' ]; then
				echo "Installing Smartctl ..."
				if [ "${release}" == "centos" ]; then
					yum update > /dev/null 2>&1
					yum -y install smartmontools > /dev/null 2>&1
				else
					apt-get update > /dev/null 2>&1
					apt-get -y install smartmontools > /dev/null 2>&1
				fi      
			fi
		}

		ip_info(){
			# use jq tool
			result=$(curl -s 'http://ip-api.com/json')
			country=$(echo $result | jq '.country' | sed 's/\"//g')
			city=$(echo $result | jq '.city' | sed 's/\"//g')
			isp=$(echo $result | jq '.isp' | sed 's/\"//g')
			as_tmp=$(echo $result | jq '.as' | sed 's/\"//g')
			asn=$(echo $as_tmp | awk -F ' ' '{print $1}')
			org=$(echo $result | jq '.org' | sed 's/\"//g')
			countryCode=$(echo $result | jq '.countryCode' | sed 's/\"//g')
			region=$(echo $result | jq '.regionName' | sed 's/\"//g')
			if [ -z "$city" ]; then
				city=${region}
			fi

			echo -e " ASN & ISP            : ${SKYBLUE}$asn, $isp${PLAIN}" | tee -a $log
			echo -e " Organization         : ${YELLOW}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${YELLOW}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log
		}

		ip_info2(){
			# no jq
			country=$(curl -s https://ipapi.co/country_name/)
			city=$(curl -s https://ipapi.co/city/)
			asn=$(curl -s https://ipapi.co/asn/)
			org=$(curl -s https://ipapi.co/org/)
			countryCode=$(curl -s https://ipapi.co/country/)
			region=$(curl -s https://ipapi.co/region/)

			echo -e " ASN & ISP            : ${SKYBLUE}$asn${PLAIN}" | tee -a $log
			echo -e " Organization         : ${SKYBLUE}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${GREEN}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log
		}

		ip_info3(){
			# use python tool
			country=$(python ip_info.py country)
			city=$(python ip_info.py city)
			isp=$(python ip_info.py isp)
			as_tmp=$(python ip_info.py as)
			asn=$(echo $as_tmp | awk -F ' ' '{print $1}')
			org=$(python ip_info.py org)
			countryCode=$(python ip_info.py countryCode)
			region=$(python ip_info.py regionName)

			echo -e " ASN & ISP            : ${SKYBLUE}$asn, $isp${PLAIN}" | tee -a $log
			echo -e " Organization         : ${GREEN}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${GREEN}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log

			rm -rf ip_info.py
		}

		ip_info4(){
			ip_date=$(curl -4 -s http://api.ip.la/en?json)
			echo $ip_date > ip_json.json
			isp=$(python tools.py geoip isp)
			as_tmp=$(python tools.py geoip as)
			asn=$(echo $as_tmp | awk -F ' ' '{print $1}')
			org=$(python tools.py geoip org)
			if [ -z "ip_date" ]; then
				echo $ip_date
				echo "hala"
				country=$(python tools.py ipip country_name)
				city=$(python tools.py ipip city)
				countryCode=$(python tools.py ipip country_code)
				region=$(python tools.py ipip province)
			else
				country=$(python tools.py geoip country)
				city=$(python tools.py geoip city)
				countryCode=$(python tools.py geoip countryCode)
				region=$(python tools.py geoip regionName)	
			fi
			if [ -z "$city" ]; then
				city=${region}
			fi

			echo -e " ASN & ISP            : ${SKYBLUE}$asn, $isp${PLAIN}" | tee -a $log
			echo -e " Organization         : ${YELLOW}$org${PLAIN}" | tee -a $log
			echo -e " Location             : ${SKYBLUE}$city, ${YELLOW}$country / $countryCode${PLAIN}" | tee -a $log
			echo -e " Region               : ${SKYBLUE}$region${PLAIN}" | tee -a $log

			rm -rf tools.py
			rm -rf ip_json.json
		}

		virt_check(){
			if hash ifconfig 2>/dev/null; then
				eth=$(ifconfig)
			fi

			virtualx=$(dmesg) 2>/dev/null

			# check dmidecode cmd
			if  [ $(which dmidecode) ]; then
				sys_manu=$(dmidecode -s system-manufacturer) 2>/dev/null
				sys_product=$(dmidecode -s system-product-name) 2>/dev/null
				sys_ver=$(dmidecode -s system-version) 2>/dev/null
			else
				sys_manu=""
				sys_product=""
				sys_ver=""
			fi
			
			if grep docker /proc/1/cgroup -qa; then
				virtual="Docker"
			elif grep lxc /proc/1/cgroup -qa; then
				virtual="Lxc"
			elif grep -qa container=lxc /proc/1/environ; then
				virtual="Lxc"
			elif [[ -f /proc/user_beancounters ]]; then
				virtual="OpenVZ"
			elif [[ "$virtualx" == *kvm-clock* ]]; then
				virtual="KVM"
			elif [[ "$cname" == *KVM* ]]; then
				virtual="KVM"
			elif [[ "$virtualx" == *"VMware Virtual Platform"* ]]; then
				virtual="VMware"
			elif [[ "$virtualx" == *"Parallels Software International"* ]]; then
				virtual="Parallels"
			elif [[ "$virtualx" == *VirtualBox* ]]; then
				virtual="VirtualBox"
			elif [[ -e /proc/xen ]]; then
				virtual="Xen"
			elif [[ "$sys_manu" == *"Microsoft Corporation"* ]]; then
				if [[ "$sys_product" == *"Virtual Machine"* ]]; then
					if [[ "$sys_ver" == *"7.0"* || "$sys_ver" == *"Hyper-V" ]]; then
						virtual="Hyper-V"
					else
						virtual="Microsoft Virtual Machine"
					fi
				fi
			else
				virtual="Dedicated"
			fi
		}

		power_time_check(){
			echo -ne " Power time of disk   : "
			install_smart
			ptime=$(power_time)
			echo -e "${SKYBLUE}$ptime Hours${PLAIN}"
		}

		freedisk() {
			# check free space
			#spacename=$( df -m . | awk 'NR==2 {print $1}' )
			#spacenamelength=$(echo ${spacename} | awk '{print length($0)}')
			#if [[ $spacenamelength -gt 20 ]]; then
			#	freespace=$( df -m . | awk 'NR==3 {print $3}' )
			#else
			#	freespace=$( df -m . | awk 'NR==2 {print $4}' )
			#fi
			freespace=$( df -m . | awk 'NR==2 {print $4}' )
			if [[ $freespace == "" ]]; then
				$freespace=$( df -m . | awk 'NR==3 {print $3}' )
			fi
			if [[ $freespace -gt 1024 ]]; then
				printf "%s" $((1024*2))
			elif [[ $freespace -gt 512 ]]; then
				printf "%s" $((512*2))
			elif [[ $freespace -gt 256 ]]; then
				printf "%s" $((256*2))
			elif [[ $freespace -gt 128 ]]; then
				printf "%s" $((128*2))
			else
				printf "1"
			fi
		}

		print_io() {
			if [[ $1 == "fast" ]]; then
				writemb=$((128*2))
			else
				writemb=$(freedisk)
			fi
			
			writemb_size="$(( writemb / 2 ))MB"
			if [[ $writemb_size == "1024MB" ]]; then
				writemb_size="1.0GB"
			fi

			if [[ $writemb != "1" ]]; then
				echo -n " I/O Speed( $writemb_size )   : " | tee -a $log
				io1=$( io_test $writemb )
				echo -e "${YELLOW}$io1${PLAIN}" | tee -a $log
				echo -n " I/O Speed( $writemb_size )   : " | tee -a $log
				io2=$( io_test $writemb )
				echo -e "${YELLOW}$io2${PLAIN}" | tee -a $log
				echo -n " I/O Speed( $writemb_size )   : " | tee -a $log
				io3=$( io_test $writemb )
				echo -e "${YELLOW}$io3${PLAIN}" | tee -a $log
				ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
				[ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
				ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
				[ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
				ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
				[ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
				ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
				ioavg=$( awk 'BEGIN{printf "%.1f", '$ioall' / 3}' )
				echo -e " Average I/O Speed    : ${YELLOW}$ioavg MB/s${PLAIN}" | tee -a $log
			else
				echo -e " ${RED}Not enough space!${PLAIN}"
			fi
		}

		print_system_info() {
			echo -e " CPU Model            : ${SKYBLUE}$cname${PLAIN}" | tee -a $log
			echo -e " CPU Cores            : ${YELLOW}$cores Cores ${SKYBLUE}@ $freq MHz $arch${PLAIN}" | tee -a $log
			echo -e " CPU Cache            : ${SKYBLUE}$corescache ${PLAIN}" | tee -a $log
			echo -e " OS                   : ${SKYBLUE}$opsy ($lbit Bit) ${YELLOW}$virtual${PLAIN}" | tee -a $log
			echo -e " Kernel               : ${SKYBLUE}$kern${PLAIN}" | tee -a $log
			echo -e " Total Space          : ${SKYBLUE}$disk_used_size GB / ${YELLOW}$disk_total_size GB ${PLAIN}" | tee -a $log
			echo -e " Total RAM            : ${SKYBLUE}$uram MB / ${YELLOW}$tram MB ${SKYBLUE}($bram MB Buff)${PLAIN}" | tee -a $log
			echo -e " Total SWAP           : ${SKYBLUE}$uswap MB / $swap MB${PLAIN}" | tee -a $log
			echo -e " Uptime               : ${SKYBLUE}$up${PLAIN}" | tee -a $log
			echo -e " Load Average         : ${SKYBLUE}$load${PLAIN}" | tee -a $log
			echo -e " TCP CC               : ${YELLOW}$tcpctrl${PLAIN}" | tee -a $log
		}

		print_end_time() {
			end=$(date +%s) 
			time=$(( $end - $start ))
			if [[ $time -gt 60 ]]; then
				min=$(expr $time / 60)
				sec=$(expr $time % 60)
				echo -ne " Finished in  : ${min} min ${sec} sec" | tee -a $log
			else
				echo -ne " Finished in  : ${time} sec" | tee -a $log
			fi
			#echo -ne "\n Current time : "
			#echo $(date +%Y-%m-%d" "%H:%M:%S)
			printf '\n' | tee -a $log
			#utc_time=$(date -u '+%F %T')
			#bj_time=$(date +%Y-%m-%d" "%H:%M:%S -d '+8 hours')
			bj_time=$(curl -s http://cgi.im.qq.com/cgi-bin/cgi_svrtime)
			#utc_time=$(date +"$bj_time" -d '-8 hours')

			if [[ $(echo $bj_time | grep "html") ]]; then
				bj_time=$(date -u +%Y-%m-%d" "%H:%M:%S -d '+8 hours')
			fi
			echo " Timestamp    : $bj_time GMT+8" | tee -a $log
			#echo " Finished!"
			echo " Results      : $log"
		}

		get_system_info() {
			cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
			cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
			freq=$( awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
			corescache=$( awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
			tram=$( free -m | awk '/Mem/ {print $2}' )
			uram=$( free -m | awk '/Mem/ {print $3}' )
			bram=$( free -m | awk '/Mem/ {print $6}' )
			swap=$( free -m | awk '/Swap/ {print $2}' )
			uswap=$( free -m | awk '/Swap/ {print $3}' )
			up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days %d hour %d min\n",a,b,c)}' /proc/uptime )
			load=$( w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
			opsy=$( get_opsy )
			arch=$( uname -m )
			lbit=$( getconf LONG_BIT )
			kern=$( uname -r )
			#ipv6=$( wget -qO- -t1 -T2 ipv6.icanhazip.com )
			disk_size1=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $2}' ))
			disk_size2=($( LANG=C df -hPl | grep -wvE '\-|none|tmpfs|overlay|shm|udev|devtmpfs|by-uuid|chroot|Filesystem' | awk '{print $3}' ))
			disk_total_size=$( calc_disk ${disk_size1[@]} )
			disk_used_size=$( calc_disk ${disk_size2[@]} )
			#tcp congestion control
			tcpctrl=$( sysctl net.ipv4.tcp_congestion_control | awk -F ' ' '{print $3}' )

			#tmp=$(python tools.py disk 0)
			#disk_total_size=$(echo $tmp | sed s/G//)
			#tmp=$(python tools.py disk 1)
			#disk_used_size=$(echo $tmp | sed s/G//)

			virt_check
		}

		print_intro() {
			printf ' Superbench.sh -- https://www.oldking.net/350.html\n' | tee -a $log
			printf " Mode  : \e${GREEN}%s\e${PLAIN}    Version : \e${GREEN}%s${PLAIN}\n" $mode_name 1.1.5 | tee -a $log
			printf ' Usage : wget -qO- git.io/superbench.sh | bash\n' | tee -a $log
		}

		sharetest() {
			echo " Share result:" | tee -a $log
			echo " · $result_speed" | tee -a $log
			log_preupload
			case $1 in
			'ubuntu')
				share_link=$( curl -v --data-urlencode "content@$log_up" -d "poster=superbench.sh" -d "syntax=text" "https://paste.ubuntu.com" 2>&1 | \
					grep "Location" | awk '{print $3}' );;
			'haste' )
				share_link=$( curl -X POST -s -d "$(cat $log)" https://hastebin.com/documents | awk -F '"' '{print "https://hastebin.com/"$4}' );;
			'clbin' )
				share_link=$( curl -sF 'clbin=<-' https://clbin.com < $log );;
			'ptpb' )
				share_link=$( curl -sF c=@- https://ptpb.pw/?u=1 < $log );;
			esac

			# print result info
			echo " · $share_link" | tee -a $log
			next
			echo ""
			rm -f $log_up

		}

		log_preupload() {
			log_up="$HOME/superbench_upload.log"
			true > $log_up
			$(cat superbench.log 2>&1 | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" > $log_up)
		}

		get_ip_whois_org_name(){
			#ip=$(curl -s ip.sb)
			result=$(curl -s https://rest.db.ripe.net/search.json?query-string=$(curl -s ip.sb))
			#org_name=$(echo $result | jq '.objects.object.[1].attributes.attribute.[1].value' | sed 's/\"//g')
			org_name=$(echo $result | jq '.objects.object[1].attributes.attribute[1]' | sed 's/\"//g')
			echo $org_name;
		}

		pingtest() {
			local ping_ms=$( ping -w 1 -c 1 $1 | grep 'rtt' | cut -d"/" -f5 )

			# get download speed and print
			if [[ $ping_ms == "" ]]; then
				printf "ping error!"  | tee -a $log
			else
				printf "%3i.%s ms" "${ping_ms%.*}" "${ping_ms#*.}"  | tee -a $log
			fi
		}

		cleanup() {
			rm -f test_file_*;
			rm -f speedtest.py;
			rm -f fast_com*;
			rm -f tools.py;
			rm -f ip_json.json
		}

		bench_all(){
			mode_name="Standard"
			about;
			benchinit;
			clear
			next;
			print_intro;
			next;
			get_system_info;
			print_system_info;
			ip_info4;
			next;
			print_io;
			next;
			print_speedtest;
			next;
			print_end_time;
			next;
			cleanup;
			sharetest ubuntu;
		}

		fast_bench(){
			mode_name="Fast"
			about;
			benchinit;
			clear
			next;
			print_intro;
			next;
			get_system_info;
			print_system_info;
			ip_info4;
			next;
			print_io fast;
			next;
			print_speedtest_fast;
			next;
			print_end_time;
			next;
			cleanup;
		}




		log="$HOME/superbench.log"
		true > $log

		case $1 in
			'info'|'-i'|'--i'|'-info'|'--info' )
				about;sleep 3;next;get_system_info;print_system_info;next;;
			'version'|'-v'|'--v'|'-version'|'--version')
				next;about;next;;
			'io'|'-io'|'--io'|'-drivespeed'|'--drivespeed' )
				next;print_io;next;;
			'speed'|'-speed'|'--speed'|'-speedtest'|'--speedtest'|'-speedcheck'|'--speedcheck' )
				about;benchinit;next;print_speedtest;next;cleanup;;
			'ip'|'-ip'|'--ip'|'geoip'|'-geoip'|'--geoip' )
				about;benchinit;next;ip_info4;next;cleanup;;
			'bench'|'-a'|'--a'|'-all'|'--all'|'-bench'|'--bench' )
				bench_all;;
			'about'|'-about'|'--about' )
				about;;
			'fast'|'-f'|'--f'|'-fast'|'--fast' )
				fast_bench;;
			'share'|'-s'|'--s'|'-share'|'--share' )
				bench_all;
				is_share="share"
				if [[ $2 == "" ]]; then
					sharetest ubuntu;
				else
					sharetest $2;
				fi
				;;
			'debug'|'-d'|'--d'|'-debug'|'--debug' )
				get_ip_whois_org_name;;
		*)
			bench_all;;
		esac



		if [[  ! $is_share == "share" ]]; then
			case $2 in
				'share'|'-s'|'--s'|'-share'|'--share' )
					if [[ $3 == '' ]]; then
						sharetest ubuntu;
					else
						sharetest $3;
					fi
					;;
			esac
		fi
	}
	
	#开始菜单
	start_menu_bench(){
		clear
		echo && echo -e " 系统性能一键测试脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
		  -- 胖波比 --
		
————————————性能测试————————————
 ${Green_font_prefix}1.${Font_color_suffix} 执行推荐的测试
 ${Green_font_prefix}2.${Font_color_suffix} 执行国际测试
 ${Green_font_prefix}3.${Font_color_suffix} 执行国内三网测试
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		echo
		read -p " 请输入数字 [1-5](默认:5):" num
		[ -z "${num}" ] && num=5
		case "$num" in
			1)
			qybench
			;;
			2)
			ibench
			;;
			3)
			cbench
			;;
			4)
			start_menu_main
			;;
			5)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-5]"
			sleep 2s
			start_menu_bench
			;;
		esac
	}
	
	start_menu_bench
}

#重装VPS系统
reinstall_sys(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH

	#=================================================
	#	System Required: CentOS 6/7,Debian 8/9,Ubuntu 16+
	#	Description: 一键重装系统
	#	Version: 1.0.1
	#	Author: 千影,Vicer
	#	Blog: https://www.94ish.me/
	#=================================================

	github="raw.githubusercontent.com/chiakge/installNET/master"

	#安装环境
	first_job(){
	if [[ "${release}" == "centos" ]]; then
		yum install -y xz openssl gawk file
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		apt-get update
		apt-get install -y xz-utils openssl gawk file	
	fi
	}

	# 安装系统
	InstallOS(){
	echo -e "${Info}重装系统需要时间,请耐心等待..."
	echo -e "${Info}重装完成后,请用root身份从22端口连接服务器！\n"
	read -p " 请设置密码(默认:pangbobi):" pw
	[ -z "${pw}" ] && pw="pangbobi"
	if [[ "${model}" == "自动" ]]; then
		model="a"
	else 
		model="m"
	fi
	if [[ "${country}" == "国外" ]]; then
		country=""
	else 
		if [[ "${os}" == "c" ]]; then
			country="--mirror https://mirrors.tuna.tsinghua.edu.cn/centos/"
		elif [[ "${os}" == "u" ]]; then
			country="--mirror https://mirrors.tuna.tsinghua.edu.cn/ubuntu/"
		elif [[ "${os}" == "d" ]]; then
			country="--mirror https://mirrors.tuna.tsinghua.edu.cn/debian/"
		fi
	fi
	wget --no-check-certificate https://${github}/InstallNET.sh && chmod -x InstallNET.sh
	bash InstallNET.sh -${os} ${1} -v ${vbit} -${model} -p ${pw} ${country}
	}
	# 安装系统
	installadvanced(){
	read -p " 请设置参数:" advanced
	wget --no-check-certificate https://${github}/InstallNET.sh && chmod -x InstallNET.sh
	bash InstallNET.sh $advanced
	}
	# 切换位数
	switchbit(){
	if [[ "${vbit}" == "64" ]]; then
		vbit="32"
	else
		vbit="64"
	fi
	}
	# 切换模式
	switchmodel(){
	if [[ "${model}" == "自动" ]]; then
		model="手动"
	else
		model="自动"
	fi
	}
	# 切换国家
	switchcountry(){
	if [[ "${country}" == "国外" ]]; then
		country="国内"
	else
		country="国外"
	fi
	}

	#安装CentOS
	installCentos(){
	clear
	os="c"
	echo && echo -e " 一键网络重装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  -- 就是爱生活 | 94ish.me --
	  
————————————选择版本————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 CentOS6.8系统
 ${Green_font_prefix}2.${Font_color_suffix} 安装 CentOS6.9系统
————————————切换模式————————————
 ${Green_font_prefix}3.${Font_color_suffix} 切换安装位数
 ${Green_font_prefix}4.${Font_color_suffix} 切换安装模式
 ${Green_font_prefix}5.${Font_color_suffix} 切换镜像源
————————————————————————————————
 ${Green_font_prefix}0.${Font_color_suffix} 返回主菜单" && echo

	echo -e " 当前模式: 安装${Red_font_prefix}${vbit}${Font_color_suffix}位系统，${Red_font_prefix}${model}${Font_color_suffix}模式,${Red_font_prefix}${country}${Font_color_suffix}镜像源。"
	echo
	read -p " 请输入数字 [0-11](默认:0):" num
	[ -z "${num}" ] && num=0
	case "$num" in
		0)
		start_menu_resys
		;;
		1)
		InstallOS "6.8"
		;;
		2)
		InstallOS "6.9"
		;;
		3)
		switchbit
		installCentos
		;;
		4)
		switchmodel
		installCentos
		;;
		5)
		switchcountry
		installCentos
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [0-11]"
		sleep 2s
		installCentos
		;;
	esac
	}

	#安装Debian
	installDebian(){
	clear
	os="d"
	echo && echo -e " 一键网络重装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 就是爱生活 | 94ish.me --
	  
————————————选择版本————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 Debian7系统
 ${Green_font_prefix}2.${Font_color_suffix} 安装 Debian8系统
 ${Green_font_prefix}3.${Font_color_suffix} 安装 Debian9系统
————————————切换模式————————————
 ${Green_font_prefix}4.${Font_color_suffix} 切换安装位数
 ${Green_font_prefix}5.${Font_color_suffix} 切换安装模式
 ${Green_font_prefix}6.${Font_color_suffix} 切换镜像源
————————————————————————————————
 ${Green_font_prefix}0.${Font_color_suffix} 返回主菜单" && echo

	echo -e " 当前模式: 安装${Red_font_prefix}${vbit}${Font_color_suffix}位系统，${Red_font_prefix}${model}${Font_color_suffix}模式,${Red_font_prefix}${country}${Font_color_suffix}镜像源。"
	echo
	read -p " 请输入数字 [0-11](默认:3):" num
	[ -z "${num}" ] && num=3
	case "$num" in
		0)
		start_menu_resys
		;;
		1)
		InstallOS "7"
		;;
		2)
		InstallOS "8"
		;;
		3)
		InstallOS "9"
		;;
		4)
		switchbit
		installDebian
		;;
		5)
		switchmodel
		installDebian
		;;
		6)
		switchcountry
		installDebian
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [0-11]"
		sleep 2s
		installCentos
		;;
	esac
	}

	#安装Ubuntu
	installUbuntu(){
	clear
	os="u"
	echo && echo -e " 一键网络重装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 就是爱生活 | 94ish.me --
	  
————————————选择版本————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 Ubuntu14系统
 ${Green_font_prefix}2.${Font_color_suffix} 安装 Ubuntu16系统
 ${Green_font_prefix}3.${Font_color_suffix} 安装 Ubuntu18系统
————————————切换模式————————————
 ${Green_font_prefix}4.${Font_color_suffix} 切换安装位数
 ${Green_font_prefix}5.${Font_color_suffix} 切换安装模式
 ${Green_font_prefix}6.${Font_color_suffix} 切换镜像源
————————————————————————————————
 ${Green_font_prefix}0.${Font_color_suffix} 返回主菜单" && echo

	echo -e " 当前模式: 安装${Red_font_prefix}${vbit}${Font_color_suffix}位系统，${Red_font_prefix}${model}${Font_color_suffix}模式,${Red_font_prefix}${country}${Font_color_suffix}镜像源。"
	echo
	read -p " 请输入数字 [0-11](默认:3):" num
	[ -z "${num}" ] && num=3
	case "$num" in
		0)
		start_menu_resys
		;;
		1)
		InstallOS "trusty"
		;;
		2)
		InstallOS "xenial"
		;;
		3)
		InstallOS "cosmic"
		;;
		4)
		switchbit
		installUbuntu
		;;
		5)
		switchmodel
		installUbuntu
		;;
		6)
		switchcountry
		installUbuntu
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [0-11]"
		sleep 2s
		installCentos
		;;
	esac
	}
	#开始菜单
	start_menu_resys(){
	clear
	echo && echo -e " 一键网络重装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 就是爱生活 | 94ish.me --
	  
————————————重装系统————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 CentOS系统
 ${Green_font_prefix}2.${Font_color_suffix} 安装 Debian系统
 ${Green_font_prefix}3.${Font_color_suffix} 安装 Ubuntu系统
 ${Green_font_prefix}4.${Font_color_suffix} 高级模式（自定义参数）
————————————切换模式————————————
 ${Green_font_prefix}5.${Font_color_suffix} 切换安装位数
 ${Green_font_prefix}6.${Font_color_suffix} 切换安装模式
 ${Green_font_prefix}7.${Font_color_suffix} 切换镜像源
————————————————————————————————" && echo

	echo -e " 当前模式: 安装${Red_font_prefix}${vbit}${Font_color_suffix}位系统，${Red_font_prefix}${model}${Font_color_suffix}模式,${Red_font_prefix}${country}${Font_color_suffix}镜像源。"
	echo
	read -p " 请输入数字 [0-7](默认:2):" num
	[ -z "${num}" ] && num=2
	case "$num" in
		1)
		installCentos
		;;
		2)
		installDebian
		;;
		3)
		installUbuntu
		;;
		4)
		installadvanced
		;;
		5)
		switchbit
		start_menu_resys
		;;
		6)
		switchmodel
		start_menu_resys
		;;
		7)
		switchcountry
		start_menu_resys
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [0-7]"
		sleep 2s
		start_menu_resys
		;;
	esac
	}
	
	first_job
	model="自动"
	vbit="64"
	country="国外"
	start_menu_resys
}

#设置防火墙
set_firewall(){
	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH
	
	add_firewall_single(){
		clear
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			read -p " 请输入端口号[1-65535]：" port
		done
		add_firewall
		firewall_restart
	}
	delete_firewall_single(){
		clear
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			read -p " 请输入端口号[1-65535]：" port
		done
		delete_firewall
		firewall_restart
	}
	add_firewall_all(){
		echo -e "${Info}开始设置防火墙..."
		if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
			firewall-cmd --get-active-zones
			firewall-cmd --permanent --zone=public --add-port=1-65535/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=1-65535/udp > /dev/null 2>&1
		else
			iptables -I INPUT -p tcp --dport 1:65535 -j ACCEPT
			iptables -I INPUT -p udp --dport 1:65535 -j ACCEPT
			ip6tables -I INPUT -p tcp --dport 1:65535 -j ACCEPT
			ip6tables -I INPUT -p udp --dport 1:65535 -j ACCEPT
		fi
		firewall_restart
	}
	delete_firewall_all(){
		echo -e "${Info}开始设置防火墙..."
		ssh_port=`grep ^Port /etc/ssh/sshd_config | awk '{print $2}'`
		if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
			firewall-cmd --get-active-zones
			firewall-cmd --permanent --zone=public --remove-port=1-65535/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --remove-port=1-65535/udp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${ssh_port}/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${ssh_port}/udp > /dev/null 2>&1
		else
			iptables -I INPUT -p tcp --dport 1:65535 -j DROP
			iptables -I INPUT -p udp --dport 1:65535 -j DROP
			ip6tables -I INPUT -p tcp --dport 1:65535 -j DROP
			ip6tables -I INPUT -p udp --dport 1:65535 -j DROP
			iptables -I INPUT -p tcp --dport ${ssh_port} -j ACCEPT
			iptables -I INPUT -p udp --dport ${ssh_port} -j ACCEPT
			ip6tables -I INPUT -p tcp --dport ${ssh_port} -j ACCEPT
			ip6tables -I INPUT -p udp --dport ${ssh_port} -j ACCEPT
		fi
		firewall_restart
	}
	clear
	unset port
	echo && echo -e " Firewall一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
		
————————Firewall管理————————
 ${Green_font_prefix}1.${Font_color_suffix} 添加防火墙端口
 ${Green_font_prefix}2.${Font_color_suffix} 删除防火墙端口
 ${Green_font_prefix}3.${Font_color_suffix} 添加所有防火墙
 ${Green_font_prefix}4.${Font_color_suffix} 删除所有防火墙
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
————————————————————————————" && echo
	read -p " 请输入数字 [1-6](默认:6):" num
	[ -z "${num}" ] && num=6
	case "$num" in
		1)
		add_firewall_single
		;;
		2)
		delete_firewall_single
		;;
		3)
		add_firewall_all
		;;
		4)
		delete_firewall_all
		;;
		5)
		start_menu_main
		;;
		6)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-6]"
		sleep 2s
		set_firewall
		;;
	esac
	set_firewall
}

#安装宝塔面板
install_btpanel(){
	#!/bin/bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH
	LANG=en_US.UTF-8

	Red_Error(){
		echo '=================================================';
		printf '\033[1;31;40m%b\033[0m\n' "$1";
		exit 0;
	}

	is64bit=$(getconf LONG_BIT)
	if [ "${is64bit}" != '64' ];then
		Red_Error "抱歉, 6.0不支持32位系统, 请使用64位系统或安装宝塔5.9!";
	fi
	isPy26=$(python -V 2>&1|grep '2.6.')
	if [ "${isPy26}" ];then
		Red_Error "抱歉, 6.0不支持Centos6.x,请安装Centos7或安装宝塔5.9";
	fi
	Install_Check(){
		while [ "$yes" != 'yes' ] && [ "$yes" != 'n' ]
		do
			echo -e "----------------------------------------------------"
			echo -e "已有Web环境，安装宝塔可能影响现有站点"
			echo -e "Web service is alreday installed,Can't install panel"
			echo -e "----------------------------------------------------"
			read -p "输入yes强制安装/Enter yes to force installation (yes/n): " yes;
		done 
		if [ "$yes" == 'n' ];then
			exit;
		fi
	}
	System_Check(){
		for serviceS in nginx httpd mysqld
		do
			if [ -f "/etc/init.d/${serviceS}" ]; then
				if [ "${serviceS}" = "httpd" ]; then
					serviceCheck=$(cat /etc/init.d/${serviceS}|grep /www/server/apache)
				elif [ "${serviceS}" = "mysqld" ]; then
					serviceCheck=$(cat /etc/init.d/${serviceS}|grep /www/server/mysql)
				else
					serviceCheck=$(cat /etc/init.d/${serviceS}|grep /www/server/${serviceS})
				fi
				[ -z "${serviceCheck}" ] && Install_Check
			fi
		done
	}

	Auto_Swap()
	{
		swap=$(free |grep Swap|awk '{print $2}')
		if [ ${swap} -gt 1 ];then
			echo "Swap total sizse: $swap";
			return;
		fi
		if [ ! -d /www ];then
			mkdir /www
		fi
		swapFile="/www/swap"
		dd if=/dev/zero of=$swapFile bs=1M count=1025
		mkswap -f $swapFile
		swapon $swapFile
		echo "$swapFile    swap    swap    defaults    0 0" >> /etc/fstab
		swap=`free |grep Swap|awk '{print $2}'`
		if [ $swap -gt 1 ];then
			echo "Swap total sizse: $swap";
			return;
		fi
		
		sed -i "/\/www\/swap/d" /etc/fstab
		rm -f $swapFile
	}

	Service_Add(){
		if [ "${PM}" == "yum" ] || [ "${PM}" == "dnf" ]; then
			chkconfig --add bt
			chkconfig --level 2345 bt on
		elif [ "${PM}" == "apt-get" ]; then
			update-rc.d bt defaults
		fi 
	}

	get_node_url(){
		echo '---------------------------------------------';
		echo "Selected download node...";
		nodes=(http://183.235.223.101:3389 http://119.188.210.21:5880 http://125.88.182.172:5880 http://103.224.251.67 http://45.32.116.160 http://download.bt.cn);
		i=1;
		if [ ! -f /bin/curl ];then
			if [ "${PM}" = "yum" ]; then
				yum install curl -y
			elif [ "${PM}" = "apt-get" ]; then
				apt-get install curl -y
			fi
		fi
		for node in ${nodes[@]};
		do
			start=`date +%s.%N`
			result=`curl -sS --connect-timeout 3 -m 60 $node/check.txt`
			if [ $result = 'True' ];then
				end=`date +%s.%N`
				start_s=`echo $start | cut -d '.' -f 1`
				start_ns=`echo $start | cut -d '.' -f 2`
				end_s=`echo $end | cut -d '.' -f 1`
				end_ns=`echo $end | cut -d '.' -f 2`
				time_micro=$(( (10#$end_s-10#$start_s)*1000000 + (10#$end_ns/1000 - 10#$start_ns/1000) ))
				time_ms=$(($time_micro/1000))
				values[$i]=$time_ms;
				urls[$time_ms]=$node
				i=$(($i+1))
			fi
		done
		j=5000
		for n in ${values[@]};
		do
			if [ $j -gt $n ];then
				j=$n
			fi
		done
		if [ $j = 5000 ];then
			NODE_URL='http://download.bt.cn';
		else
			NODE_URL=${urls[$j]}
		fi
		download_Url=$NODE_URL
		echo "Download node: $download_Url";
		echo '---------------------------------------------';
	}
	Install_RPM_Pack(){
		yumPath=/etc/yum.conf
		isExc=`cat $yumPath|grep httpd`
		if [ "$isExc" = "" ];then
			echo "exclude=httpd nginx php mysql mairadb python-psutil python2-psutil" >> $yumPath
		fi

		yum install ntp -y
		rm -rf /etc/localtime
		ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

		#尝试同步时间(从bt.cn)
		echo 'Synchronizing system time...'
		getBtTime=$(curl -sS --connect-timeout 3 -m 60 http://www.bt.cn/api/index/get_time)
		if [ "${getBtTime}" ];then	
			date -s "$(date -d @$getBtTime +"%Y-%m-%d %H:%M:%S")"
		fi

		#尝试同步国际时间(从ntp服务器)
		ntpdate 0.asia.pool.ntp.org
		setenforce 0
		startTime=`date +%s`
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
		yumPacks="wget python-devel python-imaging zip unzip openssl openssl-devel gcc libxml2 libxml2-devel libxslt* zlib zlib-devel libjpeg-devel libpng-devel libwebp libwebp-devel freetype freetype-devel lsof pcre pcre-devel vixie-cron crontabs icu libicu-devel c-ares"
		yum install -y ${yumPacks}

		for yumPack in ${yumPacks}
		do
			rpmPack=$(rpm -q ${yumPack})
			packCheck=$(echo ${rpmPack}|grep not)
			if [ "${packCheck}" ]; then
				yum install ${yumPack} -y
			fi
		done

		if [ -f "/usr/bin/dnf" ]; then
			dnf install -y redhat-rpm-config
		fi
		yum install python-devel -y
	}
	Install_Deb_Pack(){
		ln -sf bash /bin/sh
		apt-get update -y
		apt-get install ruby -y
		apt-get install lsb-release -y
		#apt-get install ntp ntpdate -y
		#/etc/init.d/ntp stop
		#update-rc.d ntp remove
		#cat >>~/.profile<<EOF
		#TZ='Asia/Shanghai'; export TZ
		#EOF
		#rm -rf /etc/localtime
		#cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
		#echo 'Synchronizing system time...'
		#ntpdate 0.asia.pool.ntp.org
		#apt-get upgrade -y
		for pace in wget curl python python-dev python-imaging zip unzip openssl libssl-dev gcc libxml2 libxml2-dev libxslt zlib1g zlib1g-dev libjpeg-dev libpng-dev lsof libpcre3 libpcre3-dev cron;
		do apt-get -y install $pace --force-yes; done
		apt-get -y install python-dev

		tmp=$(python -V 2>&1|awk '{print $2}')
		pVersion=${tmp:0:3}
		if [ "${pVersion}" == '2.7' ];then
			apt-get -y install python2.7-dev
		fi
	}
	Install_Bt(){
		setup_path="/www"
		read -p "请输入宝塔面板登录端口(默认:1314):" panelPort
		[ -z "${panelPort}" ] && panelPort=1314
		if [ -f ${setup_path}/server/panel/data/port.pl ];then
			panelPort=$(cat ${setup_path}/server/panel/data/port.pl)
		fi
		mkdir -p ${setup_path}/server/panel/logs
		mkdir -p ${setup_path}/server/panel/vhost/apache
		mkdir -p ${setup_path}/server/panel/vhost/nginx
		mkdir -p ${setup_path}/server/panel/vhost/rewrite
		mkdir -p /www/server
		mkdir -p /www/wwwroot
		mkdir -p /www/wwwlogs
		mkdir -p /www/backup/database
		mkdir -p /www/backup/site

		if [ ! -f "/usr/bin/unzip" ]; then
			if [ "${PM}" = "yum" ]; then
				yum install unzip -y
			elif [ "${PM}" = "apt-get" ]; then
				apt-get install unzip -y
			fi
		fi

		if [ -f "/etc/init.d/bt" ]; then
			/etc/init.d/bt stop
			sleep 1
		fi

		wget -O panel.zip ${download_Url}/install/src/panel6.zip -T 10
		wget -O /etc/init.d/bt ${download_Url}/install/src/bt6.init -T 10

		if [ -f "${setup_path}/server/panel/data/default.db" ];then
			if [ -d "/${setup_path}/server/panel/old_data" ];then
				rm -rf ${setup_path}/server/panel/old_data
			fi
			mkdir -p ${setup_path}/server/panel/old_data
			mv -f ${setup_path}/server/panel/data/default.db ${setup_path}/server/panel/old_data/default.db
			mv -f ${setup_path}/server/panel/data/system.db ${setup_path}/server/panel/old_data/system.db
			mv -f ${setup_path}/server/panel/data/port.pl ${setup_path}/server/panel/old_data/port.pl
			mv -f ${setup_path}/server/panel/data/admin_path.pl ${setup_path}/server/panel/old_data/admin_path.pl
		fi

		unzip -o panel.zip -d ${setup_path}/server/ > /dev/null

		if [ -d "${setup_path}/server/panel/old_data" ];then
			mv -f ${setup_path}/server/panel/old_data/default.db ${setup_path}/server/panel/data/default.db
			mv -f ${setup_path}/server/panel/old_data/system.db ${setup_path}/server/panel/data/system.db
			mv -f ${setup_path}/server/panel/old_data/port.pl ${setup_path}/server/panel/data/port.pl
			mv -f ${setup_path}/server/panel/old_data/admin_path.pl ${setup_path}/server/panel/data/admin_path.pl
			if [ -d "/${setup_path}/server/panel/old_data" ];then
				rm -rf ${setup_path}/server/panel/old_data
			fi
		fi

		rm -f panel.zip

		if [ ! -f ${setup_path}/server/panel/tools.py ];then
			Red_Error "ERROR: Failed to download, please try install again!"
		fi

		rm -f ${setup_path}/server/panel/class/*.pyc
		rm -f ${setup_path}/server/panel/*.pyc

		chmod +x /etc/init.d/bt
		chmod -R 600 ${setup_path}/server/panel
		chmod -R +x ${setup_path}/server/panel/script
		ln -sf /etc/init.d/bt /usr/bin/bt
		echo "${panelPort}" > ${setup_path}/server/panel/data/port.pl
	}
	Install_Pip(){
		isPip=$(pip -V|grep python)
		if [ -z "${isPip}" ];then
			wget -O get-pip.py ${download_Url}/src/get-pip.py
			python get-pip.py
			rm -f get-pip.py
			isPip=$(pip -V|grep python)
			if [ -z "${isPip}" ];then
				if [ "${PM}" = "yum" ]; then
					yum install python-pip -y
				elif [ "${PM}" = "apt-get" ]; then
					apt-get install python-pip -y
				fi
			fi
		fi
	}
	Install_Pillow()
	{
		isSetup=$(python -m PIL 2>&1|grep package)
		if [ "$isSetup" = "" ];then
			isFedora = `cat /etc/redhat-release |grep Fedora`
			if [ "${isFedora}" ];then
				pip install Pillow
				return;
			fi
			wget -O Pillow-3.2.0.zip $download_Url/install/src/Pillow-3.2.0.zip -T 10
			unzip Pillow-3.2.0.zip
			rm -f Pillow-3.2.0.zip
			cd Pillow-3.2.0
			python setup.py install
			cd ..
			rm -rf Pillow-3.2.0
		fi
		
		isSetup=$(python -m PIL 2>&1|grep package)
		if [ -z "${isSetup}" ];then
			Red_Error "Pillow installation failed."
		fi
	}
	Install_psutil()
	{
		isSetup=`python -m psutil 2>&1|grep package`
		if [ "$isSetup" = "" ];then
			wget -O psutil-5.2.2.tar.gz $download_Url/install/src/psutil-5.2.2.tar.gz -T 10
			tar xvf psutil-5.2.2.tar.gz
			rm -f psutil-5.2.2.tar.gz
			cd psutil-5.2.2
			python setup.py install
			cd ..
			rm -rf psutil-5.2.2
		fi
		isSetup=$(python -m psutil 2>&1|grep package)
		if [ "${isSetup}" = "" ];then
			Red_Error "Psutil installation failed."
		fi
	}
	Install_chardet()
	{
		isSetup=$(python -m chardet 2>&1|grep package)
		if [ "${isSetup}" = "" ];then
			wget -O chardet-2.3.0.tar.gz $download_Url/install/src/chardet-2.3.0.tar.gz -T 10
			tar xvf chardet-2.3.0.tar.gz
			rm -f chardet-2.3.0.tar.gz
			cd chardet-2.3.0
			python setup.py install
			cd ..
			rm -rf chardet-2.3.0
		fi	
		
		isSetup=$(python -m chardet 2>&1|grep package)
		if [ -z "${isSetup}" ];then
			Red_Error "chardet installation failed."
		fi
	}
	Install_Python_Lib(){
		isPsutil=$(python -m psutil 2>&1|grep package)
		if [ "${isPsutil}" ];then
			PSUTIL_VERSION=`python -c 'import psutil;print psutil.__version__;' |grep '5.'` 
			if [ -z "${PSUTIL_VERSION}" ];then
				pip uninstall psutil -y 
			fi
		fi

		if [ "${PM}" = "yum" ]; then
			yum install libffi-devel -y
		elif [ "${PM}" = "apt-get" ]; then
			apt install libffi-dev -y
		fi

		curl -Ss --connect-timeout 3 -m 60 http://download.bt.cn/install/pip_select.sh|bash
		pip install --upgrade setuptools 
		pip install -r ${setup_path}/server/panel/requirements.txt
		isGevent=$(pip list|grep gevent)
		if [ "$isGevent" = "" ];then
			if [ "${PM}" = "yum" ]; then
				yum install python-gevent -y
			elif [ "${PM}" = "apt-get" ]; then
				apt-get install python-gevent -y
			fi
		fi
		pip install psutil chardet virtualenv Flask Flask-Session Flask-SocketIO flask-sqlalchemy Pillow gunicorn gevent-websocket paramiko
		
		Install_Pillow
		Install_psutil
		Install_chardet
		pip install gunicorn

	}

	Set_Bt_Panel(){
		password=$(cat /dev/urandom | head -n 16 | md5sum | head -c 8)
		sleep 1
		admin_auth="/www/server/panel/data/admin_path.pl"
		if [ ! -f ${admin_auth} ];then
			auth_path=$(cat /dev/urandom | head -n 16 | md5sum | head -c 8)
			echo "/${auth_path}" > ${admin_auth}
		fi
		auth_path=$(cat ${admin_auth})
		cd ${setup_path}/server/panel/
		/etc/init.d/bt start
		python -m py_compile tools.py
		python tools.py username
		username=$(python tools.py panel ${password})
		cd ~
		echo "${password}" > ${setup_path}/server/panel/default.pl
		chmod 600 ${setup_path}/server/panel/default.pl
		/etc/init.d/bt restart
		sleep 3
		isStart=$(ps aux |grep 'gunicorn'|grep -v grep|awk '{print $2}')
		if [ -z "${isStart}" ];then
			Red_Error "ERROR: The BT-Panel service startup failed."
		fi
	}
	Set_Firewall(){
		sshPort=$(cat /etc/ssh/sshd_config | grep 'Port '|awk '{print $2}')
		if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
			systemctl enable firewalld
			systemctl start firewalld
			firewall-cmd --set-default-zone=public > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=20/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=21/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=22/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=80/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=888/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${panelPort}/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${sshPort}/tcp > /dev/null 2>&1
			#firewall-cmd --permanent --zone=public --add-port=39000-40000/tcp > /dev/null 2>&1
			firewall-cmd --reload
		else
			iptables -I INPUT -p tcp --dport 20 -j ACCEPT
			iptables -I INPUT -p tcp --dport 21 -j ACCEPT
			iptables -I INPUT -p tcp --dport 22 -j ACCEPT
			iptables -I INPUT -p tcp --dport 80 -j ACCEPT
			iptables -I INPUT -p tcp --dport 888 -j ACCEPT
			iptables -I INPUT -p tcp --dport ${panelPort} -j ACCEPT
			iptables -I INPUT -p tcp --dport ${sshPort} -j ACCEPT
			#iptables -I INPUT -p tcp --dport 39000:40000 -j ACCEPT
			if [[ ${release} == "centos" ]]; then
				service iptables save
				service ip6tables save
			else
				iptables-save > /etc/iptables.up.rules
				ip6tables-save > /etc/ip6tables.up.rules
			fi
		fi
	}
	Get_Ip_Address(){
		getIpAddress=""
		getIpAddress=$(curl -sS --connect-timeout 10 -m 60 https://www.bt.cn/Api/getIpAddress)
		if [ -z "${getIpAddress}" ] || [ "${getIpAddress}" = "0.0.0.0" ]; then
			isHosts=$(cat /etc/hosts|grep 'www.bt.cn')
			if [ -z "${isHosts}" ];then
				echo "" >> /etc/hosts
				echo "103.224.251.67 www.bt.cn" >> /etc/hosts
				getIpAddress=$(curl -sS --connect-timeout 10 -m 60 https://www.bt.cn/Api/getIpAddress)
				if [ -z "${getIpAddress}" ];then
					sed -i "/bt.cn/d" /etc/hosts
				fi
			fi
		fi

		ipv4Check=$(python -c "import re; print(re.match('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$','${getIpAddress}'))")
		if [ "${ipv4Check}" == "None" ];then
			ipv6Address=$(echo ${getIpAddress}|tr -d "[]")
			ipv6Check=$(python -c "import re; print(re.match('^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$','${ipv6Address}'))")
			if [ "${ipv6Check}" == "None" ]; then
				getIpAddress="SERVER_IP"
			else
				echo "True" > ${setup_path}/server/panel/data/ipv6.pl
				sleep 1
				/etc/init.d/bt restart
			fi
		fi

		if [ "${getIpAddress}" != "SERVER_IP" ];then
			echo "${getIpAddress}" > ${setup_path}/server/panel/data/iplist.txt
		fi
	}
	Setup_Count(){
		curl -sS --connect-timeout 10 -m 60 https://www.bt.cn/Api/SetupCount?type=Linux\&o=$1 > /dev/null 2>&1
		if [ "$1" != "" ];then
			echo $1 > /www/server/panel/data/o.pl
			cd /www/server/panel
			python tools.py o
		fi
		echo /www > /var/bt_setupPath.conf
	}

	Install_Main(){
		System_Check
		get_node_url

		Auto_Swap

		startTime=`date +%s`
		if [ "${PM}" = "yum" ]; then
			Install_RPM_Pack
		elif [ "${PM}" = "apt-get" ]; then
			Install_Deb_Pack
		fi

		Install_Bt

		Install_Pip
		Install_Python_Lib

		Set_Bt_Panel
		Service_Add
		Set_Firewall

		Get_Ip_Address
		Setup_Count
	}

	echo "
	+----------------------------------------------------------------------
	| Bt-WebPanel 6.0 FOR CentOS/Ubuntu/Debian
	+----------------------------------------------------------------------
	| Copyright © 2015-2099 BT-SOFT(http://www.bt.cn) All rights reserved.
	+----------------------------------------------------------------------
	| The WebPanel URL will be http://SERVER_IP:1314 when installed.
	+----------------------------------------------------------------------
	"
	while [ "$go" != 'y' ] && [ "$go" != 'n' ]
	do
		read -p "Do you want to install Bt-Panel to the $setup_path directory now?(y/n): " go;
	done

	if [ "$go" == 'n' ];then
		exit;
	fi

	Install_Main

	echo -e "=================================================================="
	echo -e "\033[32mCongratulations! Installed successfully!\033[0m"
	echo -e "=================================================================="
	echo  "Bt-Panel: http://${getIpAddress}:${panelPort}$auth_path"
	echo -e "username: $username"
	echo -e "password: $password"
	echo -e "\033[33mWarning:\033[0m"
	echo -e "\033[33mIf you cannot access the panel, \033[0m"
	echo -e "\033[33mrelease the following port (1314|888|80|443|20|21) in the security group\033[0m"
	echo -e "=================================================================="

	endTime=`date +%s`
	((outTime=($endTime-$startTime)/60))
	echo -e "Time consumed:\033[32m $outTime \033[0mMinute!"
	echo -e "${Info}请务必及时记录登录信息!"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
	start_menu_main
}

#安装Kodexplorer
install_kodexplorer(){
    install_docker
	read -p "请输入访问端口[1-65535](默认:999):" port
	[ -z "${port}" ] && port=999
	add_firewall
	firewall_restart
    docker run -d -p ${port}:80 --name kodexplorer -v /opt/kodcloud:/code baiyuetribe/kodexplorer
	echo -e "${Info}已安装完成!"
	echo -e "${Info}请访问http://$(get_ip):${port}"
    echo -e "${Info}默认宿主机目录/opt/kodcloud"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
	start_menu_main
}

#更新脚本
update_sv(){
	github="raw.githubusercontent.com/AmuyangA/internet/master/supervpn"
	echo -e "${Info}当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
	sh_new_ver=$(wget --no-check-certificate -qO- "http://${github}/sv.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && start_menu_main
	if [[ ${sh_new_ver} != ${sh_ver} ]]; then
		echo -e "${Info}发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
		read -p "(默认: y):" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ ${yn} == [Yy] ]]; then
			wget -N --no-check-certificate http://${github}/sv.sh && chmod +x sv.sh
			echo -e "${Info}脚本已更新为最新版本[ ${sh_new_ver} ] !"
			echo -e "${Info}旧版本已被覆盖,下次启动将运行最新版！"
		else
			echo && echo "${Info}已取消..." && echo
		fi
	else
		echo -e "${Info}当前已是最新版本[ ${sh_new_ver} ] !"
		sleep 2s
	fi
}

#开始菜单
start_menu_main(){
	clear
	echo "###################################################"
	echo "#  SuperVpn----One click Install                  #"
	echo "#  Author: Pangbobi                               #"
	echo "#  Github: https://github.com/AmuyangA/internet/  #"
	echo "###################################################"
	echo -e "
  超级VPN 一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
	执行脚本：./sv.sh
  终止正在进行的操作：Ctrl+C
	  
—————————————VPN搭建——————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装V2Ray
 ${Green_font_prefix}2.${Font_color_suffix} SSR安装管理
 ${Green_font_prefix}3.${Font_color_suffix} BBR/Lotserver安装管理
 ${Green_font_prefix}4.${Font_color_suffix} 一键安装SS-Panel/Kodexplorer
———————————设置伪装(二选一)———————
 ${Green_font_prefix}5.${Font_color_suffix} Caddy安装管理
 ${Green_font_prefix}6.${Font_color_suffix} Nginx安装管理(推荐)
—————————————系统设置—————————————
 ${Green_font_prefix}7.${Font_color_suffix} 设置SSH端口
 ${Green_font_prefix}8.${Font_color_suffix} 设置root密码
 ${Green_font_prefix}9.${Font_color_suffix} 系统性能测试
 ${Green_font_prefix}10.${Font_color_suffix} 重装VPS系统
 ${Green_font_prefix}11.${Font_color_suffix} 设置防火墙
 ${Green_font_prefix}12.${Font_color_suffix} 安装宝塔面板
 ${Green_font_prefix}13.${Font_color_suffix} Kodexplorer安装管理
—————————————脚本设置—————————————
 ${Green_font_prefix}14.${Font_color_suffix} 设置脚本自启
 ${Green_font_prefix}15.${Font_color_suffix} 关闭脚本自启
 ${Green_font_prefix}16.${Font_color_suffix} 更新脚本
 ${Green_font_prefix}17.${Font_color_suffix} 退出脚本
——————————————————————————————————" && echo
	read -p " 请输入数字 [1-17](默认:17):" num
	[ -z "${num}" ] && num=17
	case "$num" in
		1)
		install_v2ray
		;;
		2)
		install_ssr
		;;
		3)
		install_bbr
		;;
		4)
		install_sspanel
		;;
		5)
		install_caddy
		;;
		6)
		install_nginx
		;;
		7)
		set_ssh
		;;
		8)
		set_root
		;;
		9)
		test_sys
		;;
		10)
		reinstall_sys
		;;
		11)
		set_firewall
		;;
		12)
		install_btpanel
		;;
		13)
		install_kodexplorer
		;;
		14)
		echo "./sv.sh" >> .bash_profile
		;;
		15)
		sed -i "/sv.sh/d" .bash_profile
		;;
		16)
		update_sv
		;;
		17)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-17]:"
		sleep 2s
		start_menu_main
		;;
	esac
	start_menu_main
}

check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
#安装依赖
test ! -e /root/testde || start_menu_main
echo -e "${Info}首次运行此脚本会安装依赖环境,按任意键继续..."
char=`get_char`
if [[ "${release}" == "centos" ]]; then
	yum install -y python python-devel python-setuptools openssl openssl-devel git bash curl wget zip unzip gcc automake autoconf make libtool ca-certificates python3-pip subversion jq
elif [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
	apt-get -y install python python-dev python-setuptools openssl libssl-dev git bash curl wget zip unzip gcc automake autoconf make libtool ca-certificates python3-pip subversion vim jq
	iptables -A INPUT -p icmp --icmp-type any -j ACCEPT
	iptables -A INPUT -s localhost -d localhost -j ACCEPT
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -P INPUT DROP
	iptables-save > /etc/iptables.up.rules
	ip6tables-save > /etc/ip6tables.up.rules
	echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
	chmod +x /etc/network/if-pre-up.d/iptables
fi
touch /root/testde
start_menu_main