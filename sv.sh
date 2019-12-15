#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#版本
sh_ver="7.1.5"
#颜色信息
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}" && Error="${Red_font_prefix}[错误]${Font_color_suffix}" && Tip="${Green_font_prefix}[注意]${Font_color_suffix}"
red='\033[0;31m' && green='\033[0;32m' && yellow='\033[0;33m' && plain='\033[0m'
#check root
[ $(id -u) != "0" ] && { echo -e "${Error}: 您必须以root用户运行此脚本"; exit 1; }

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
	#检查系统安装格式
	if [ -f "/usr/bin/yum" ] && [ -f "/etc/yum.conf" ]; then
		PM="yum"
	elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
		PM="apt-get"		
	fi
	myinfo="企鹅号:3450633979"
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
	if [[ ${release} == "centos" ]]; then
		if [[ ${version} -ge "7" ]]; then
			firewall-cmd --reload
		else
			service iptables save
			service ip6tables save
		fi
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
	echo -e "${Info}防火墙设置完成！"
}
add_firewall(){
	if [[ ${release} == "centos" &&  ${version} -ge "7" ]]; then
		firewall-cmd --permanent --zone=public --add-port=${port}/tcp > /dev/null 2>&1
		firewall-cmd --permanent --zone=public --add-port=${port}/udp > /dev/null 2>&1
	else
		iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
		iptables -I INPUT -p udp --dport ${port} -j ACCEPT
		ip6tables -I INPUT -p tcp --dport ${port} -j ACCEPT
		ip6tables -I INPUT -p udp --dport ${port} -j ACCEPT
	fi
}
add_firewall_base(){
	ssh_port=$(cat /etc/ssh/sshd_config|grep 'Port '|head -1|awk -F ' ' '{print $2}')
	if [[ ${release} == "centos" &&  ${version} -ge "7" ]]; then
		firewall-cmd --permanent --zone=public --add-port=${ssh_port}/tcp > /dev/null 2>&1
		firewall-cmd --permanent --zone=public --add-port=${ssh_port}/udp > /dev/null 2>&1
	else
		iptables -A INPUT -p icmp --icmp-type any -j ACCEPT
		iptables -A INPUT -s localhost -d localhost -j ACCEPT
		iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
		iptables -P INPUT DROP
		iptables -I INPUT -p tcp --dport ${ssh_port} -j ACCEPT
		iptables -I INPUT -p udp --dport ${ssh_port} -j ACCEPT
	fi
}
add_firewall_all(){
	echo -e "${Info}开始设置防火墙..."
	if [[ ${release} == "centos" &&  ${version} -ge "7" ]]; then
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
delete_firewall(){
	if [[ ${release} == "centos" &&  ${version} -ge "7" ]]; then
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
		echo -e "${Info}您的系统已安装docker"
	else
		${PM} --fix-broken install
		echo -e "${Info}开始安装docker..."
		docker version > /dev/null || curl -fsSL get.docker.com | bash
		service docker restart
		systemctl enable docker 
	fi
	#安装Docker环境
	if [ -x "$(command -v docker-compose)" ]; then
		echo -e "${Info}系统已存在Docker环境"
	else
		echo -e "${Info}正在安装Docker环境..."
		curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
		chmod +x /usr/local/bin/docker-compose
	fi
}

#安装V2ray
manage_v2ray(){
	v2ray_info(){
		sed -i "s#ps\":.*,#ps\": \"${myinfo}\",#g" $(cat /root/test/v2raypath)
		clear
		v2ray info
	}
	change_uuid(){
		clear
		num=$(jq ".inbounds | length" /etc/v2ray/config.json)
		echo -e "\n${Info}当前用户总数：${Red_font_prefix}${num}${Font_color_suffix}\n"
		unset i
		until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
		do
			stty erase ^H && read -p "请输入要修改的用户序号 [1-${num}]:" i
		done
		i=$[${i}-1]
		uuid1=$(jq -r ".inbounds[${i}].settings.clients[0].id" /etc/v2ray/config.json)
		uuid2=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#${uuid1}#${uuid2}#g" /etc/v2ray/config.json
		clear
		v2ray restart
		v2ray_info
		echo && echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续更改UUID
 ${Green_font_prefix}2.${Font_color_suffix} 返回V2Ray用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			1)
			change_uuid
			;;
			2)
			manage_v2ray_user
			;;
			3)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-3]:"
			sleep 2s
			manage_v2ray_user
			;;
		esac
	}
	change_ws(){
		num=$(jq ".inbounds | length" /etc/v2ray/config.json)
		for(( i = 0; i < ${num}; i++ ))
		do
			protocol=$(jq -r ".inbounds[${i}].streamSettings.network" /etc/v2ray/config.json)
			if [[ "${protocol}" != "ws" ]]; then
				cat /etc/v2ray/config.json | jq "del(.inbounds[${i}].streamSettings.${protocol}Settings[])" | jq '.inbounds['${i}'].streamSettings.network="ws"' > /root/test/temp.json
				temppath="/$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)/"
				cat /root/test/temp.json | jq '.inbounds['${i}'].streamSettings.wsSettings.path="'${temppath}'"' | jq '.inbounds['${i}'].streamSettings.wsSettings.headers.Host="www.bilibili.com"' > /etc/v2ray/config.json
			fi
		done
		v2ray restart
		clear
		v2ray_info
		echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
		char=`get_char`
		manage_v2ray_user
	}
	set_tfo(){
		set_tfo_single(){
			v2ray tfo
			v2ray_info
			echo && echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续设置TcpFastOpen
 ${Green_font_prefix}2.${Font_color_suffix} 返回V2Ray用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				1)
				set_tfo_single
				;;
				2)
				manage_v2ray_user
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]:"
				sleep 2s
				set_tfo_menu
				;;
			esac
		}
		set_tfo_multi(){
			num=$(jq ".inbounds | length" /etc/v2ray/config.json)
			for(( i = 0; i < ${num}; i++ ))
			do
				cat /etc/v2ray/config.json | jq '.inbounds['${i}'].streamSettings.sockopt.mark=0' | jq '.inbounds['${i}'].streamSettings.sockopt.tcpFastOpen=true' > /root/test/temp.json
				cp /root/test/temp.json /etc/v2ray/config.json
			done
			v2ray restart
			clear
			v2ray_info
			echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
			char=`get_char`
			manage_v2ray_user
		}
		set_tfo_menu(){
			clear
			echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 逐个设置
 ${Green_font_prefix}2.${Font_color_suffix} 全部设置
 ${Green_font_prefix}3.${Font_color_suffix} 返回V2Ray用户管理页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
 —————————————————————" && echo
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				set_tfo_single
				;;
				2)
				set_tfo_multi
				;;
				3)
				manage_v2ray_user
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-4]:"
				sleep 2s
				set_tfo_menu
				;;
			esac
		}
		set_tfo_menu
	}
	add_user_v2ray(){
		add_v2ray_single(){
			clear
			echo -e "\n${Info}当前用户总数：${Red_font_prefix}$(jq ".inbounds | length" /etc/v2ray/config.json)${Font_color_suffix}\n"
			v2ray add
			firewall_restart
			v2ray_info
			echo -e "
   ————胖波比————
——————————————————————
${Green_font_prefix}1.${Font_color_suffix} 继续添加用户
${Green_font_prefix}2.${Font_color_suffix} 返回V2Ray用户管理页
${Green_font_prefix}3.${Font_color_suffix} 退出脚本
——————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				1)
				add_v2ray_single
				;;
				2)
				manage_v2ray_user
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]:"
				sleep 2s
				manage_v2ray_user
				;;
			esac
		}
		add_v2ray_multi(){
			clear
			echo -e "\n${Info}当前用户总数：${Red_font_prefix}$(jq ".inbounds | length" /etc/v2ray/config.json)${Font_color_suffix}\n"
			stty erase ^H && read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			for(( i = 0; i < ${num}; i++ ))
			do
				echo | v2ray add
			done
			firewall_restart
			v2ray_info
			echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
			char=`get_char`
			manage_v2ray_user
		}
		add_v2ray_menu(){
			clear
			echo -e "
   ————胖波比————
—————————————————————
${Green_font_prefix}1.${Font_color_suffix} 逐个添加
${Green_font_prefix}2.${Font_color_suffix} 批量添加
${Green_font_prefix}3.${Font_color_suffix} 返回V2Ray用户管理页
${Green_font_prefix}4.${Font_color_suffix} 退出脚本
—————————————————————" && echo
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				add_v2ray_single
				;;
				2)
				add_v2ray_multi
				;;
				3)
				manage_v2ray_user
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-4]:"
				sleep 2s
				add_v2ray_menu
				;;
			esac
		}
		add_v2ray_menu
	}
	manage_v2ray_user(){
		clear
		echo && echo -e "   V2Ray用户管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
手动修改配置文件：vi /etc/v2ray/config.json

————————V2Ray用户管理————————
${Green_font_prefix}1.${Font_color_suffix} 更改UUID
${Green_font_prefix}2.${Font_color_suffix} 查看用户链接
${Green_font_prefix}3.${Font_color_suffix} 流量统计
${Green_font_prefix}4.${Font_color_suffix} 添加用户
${Green_font_prefix}5.${Font_color_suffix} 删除用户
${Green_font_prefix}6.${Font_color_suffix} 更改端口
${Green_font_prefix}7.${Font_color_suffix} 更改协议
${Green_font_prefix}8.${Font_color_suffix} 更改TcpFastOpen
${Green_font_prefix}9.${Font_color_suffix} 原版管理窗口
${Green_font_prefix}10.${Font_color_suffix} 改为WebSocket传输
${Green_font_prefix}11.${Font_color_suffix} 走cdn
${Green_font_prefix}12.${Font_color_suffix} 更改tls
${Green_font_prefix}13.${Font_color_suffix} 回到主页
${Green_font_prefix}14.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-14](默认:14):" num
		[ -z "${num}" ] && num=14
		case "$num" in
			1)
			change_uuid
			;;
			2)
			v2ray_info
			echo -e "${Info}按任意键继续..."
			char=`get_char`
			;;
			3)
			v2ray iptables
			;;
			4)
			add_user_v2ray
			;;
			5)
			v2ray del
			;;
			6)
			v2ray port
			;;
			7)
			v2ray stream
			;;
			8)
			set_tfo
			;;
			9)
			clear
			v2ray
			;;
			10)
			change_ws
			;;
			11)
			v2ray cdn
			;;
			12)
			v2ray tls
			;;
			13)
			start_menu_main
			;;
			14)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-14]"
			sleep 2s
			manage_v2ray_user
			;;
		esac
		manage_v2ray_user
	}
	install_v2ray(){
		source <(curl -sL ${v2ray_url}) --zh
		find / -name group.py | grep v2ray_util > /root/test/v2raypath
		port=$(cat /etc/v2ray/config.json | grep 'port": ' | tail -1 | sed 's/,//g' | awk -F ' ' '{print $2}')
		add_firewall
		firewall_restart
		echo -e "${Info}任意键继续..."
		char=`get_char`
		manage_v2ray_user
	}
	install_v2ray_repair(){
		source <(curl -sL ${v2ray_url}) -k
		echo -e "${Info}已保留配置更新，任意键继续..."
		char=`get_char`
	}
	start_menu_v2ray(){
		v2ray_url="https://multi.netlify.com/v2ray.sh"
		clear
		echo && echo -e " V2Ray一键安装脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --

—————————V2Ray安装—————————
${Green_font_prefix}1.${Font_color_suffix} 管理V2Ray用户
${Green_font_prefix}2.${Font_color_suffix} 安装V2Ray
${Green_font_prefix}3.${Font_color_suffix} 修复V2Ray
${Green_font_prefix}4.${Font_color_suffix} 卸载V2Ray
${Green_font_prefix}5.${Font_color_suffix} 重启V2Ray
${Green_font_prefix}6.${Font_color_suffix} 关闭V2Ray
${Green_font_prefix}7.${Font_color_suffix} 启动V2Ray
${Green_font_prefix}8.${Font_color_suffix} 查看V2Ray状态
${Green_font_prefix}9.${Font_color_suffix} 回到主页
${Green_font_prefix}10.${Font_color_suffix} 退出脚本
———————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-10](默认:10):" num
		[ -z "${num}" ] && num=10
		case "$num" in
			1)
			manage_v2ray_user
			;;
			2)
			install_v2ray
			;;
			3)
			install_v2ray_repair
			;;
			4)
			source <(curl -sL ${v2ray_url}) --remove
			echo -e "${Info}已卸载，任意键继续..."
			char=`get_char`
			;;
			5)
			v2ray restart
			;;
			6)
			v2ray stop
			;;
			7)
			v2ray start
			;;
			8)
			v2ray status
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
			start_menu_v2ray
			;;
		esac
		start_menu_v2ray
	}
	start_menu_v2ray
}

#安装SSR
install_ssr(){
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
		stty erase ^H && read -p "Which cipher you'd select(默认: ${ciphers[1]}):" pick
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
		stty erase ^H && read -p "Which protocol you'd select(默认: ${protocols[3]}):" protocol
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
		stty erase ^H && read -p "Which obfs you'd select(默认: ${obfs[2]}):" r_obfs
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
		stty erase ^H && read -p "(默认密码: pangbobi):" password
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
		stty erase ^H && read -p "(默认随机端口: ${dport}):" port
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
	# Install cleanup
	install_cleanup(){
		cd ${cur_dir}
		rm -rf ${shadowsocks_r_file} ${libsodium_file}
		rm -f ${shadowsocks_r_file}.tar.gz ${libsodium_file}.tar.gz
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
			install_cleanup
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
 ${Green_font_prefix}1.${Font_color_suffix} 进入SSR用户管理页
 ${Green_font_prefix}2.${Font_color_suffix} 回到主页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:3):" num
			[ -z "${num}" ] && num=3
			case "$num" in
				1)
				manage_ssr
				;;
				2)
				start_menu_main
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]"
				sleep 2s
				start_menu_main
				;;
			esac
		else
			echo -e "${Error}:ShadowsocksR install failed, please Email to Teddysun <i@teddysun.com> and contact"
			install_cleanup
			exit 1
		fi
	}
	# Uninstall ShadowsocksR
	uninstall_shadowsocksr(){
		printf "Are you sure uninstall ShadowsocksR? (y/n)"
		printf "\n"
		stty erase ^H && read -p "(Default: n):" answer
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
		Remarksbase64=$(urlsafe_base64 "${myinfo}")
		Groupbase64=$(urlsafe_base64 "我们爱中国")
	}
	#读取端口密码
	get_pp(){
		cat > /root/test/ppj<<-EOF
$(jq '.port_password' /etc/shadowsocks.json)
EOF
		pp=$(jq -r "to_entries|map(\"\(.key):\(.value|tostring)\")|.[]" /root/test/ppj)
		cat > /root/test/ppj<<-EOF
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
		echo -e "\n${Info}端口：${Red_font_prefix}${port}${Font_color_suffix}   密码：${Red_font_prefix}${password}${Font_color_suffix}"
		echo -e "${Info}SSR链接 : ${Red_font_prefix}${SSRurl}${Font_color_suffix}\n"
	}
	#查看所有链接
	view_ssrurl(){
		clear
		get_pp
		cat /root/test/ppj | while read line; do
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
		change_pw_single(){
			clear
			jq '.port_password' /etc/shadowsocks.json
			echo -e "${Info}以上是配置文件的内容\n"
			#判断端口是否已有,清空port内存
			unset port
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && "${port}" -ge "1000" && "${port}" -le "65535" && "${port}" -ne "1080" ]]
			do
				stty erase ^H && read -p "请输入要改密的端口号：" port
			done
			password1=$(jq -r '.port_password."'${port}'"' /etc/shadowsocks.json)
			password=$(openssl rand -base64 6)
			et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
			sed -i "${et}s#${password1}#${password}#g" /etc/shadowsocks.json
			#调用生成链接的函数
			set_ssrurl
			echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续更改密码
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				1)
				change_pw_single
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
				change_pw_menu
				;;
			esac
		}
		change_pw_multi(){
			clear
			get_pp
			cat /root/test/ppj | while read line; do
				port=`echo $line|awk -F ':' '{print $1}'`
				password1=`echo $line|awk -F ':' '{print $2}'`
				password=$(openssl rand -base64 6)
				et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
				sed -i "${et}s#${password1}#${password}#g" /etc/shadowsocks.json
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
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			echo -e "${Info}按任意键回到SSR用户管理页..."
			char=`get_char`
			manage_ssr
		}
		change_pw_menu(){
			clear
			echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 逐个修改
 ${Green_font_prefix}2.${Font_color_suffix} 全部修改
 ${Green_font_prefix}3.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
 —————————————————————" && echo
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				change_pw_single
				;;
				2)
				change_pw_multi
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
				change_pw_menu
				;;
			esac
		}
		change_pw_menu
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
				stty erase ^H && read -p "请输入要添加的端口号[1000-65535]：" port
			done
			add_firewall
			firewall_restart
			password=$(openssl rand -base64 6)
			cat /etc/shadowsocks.json | jq '.port_password."'${port}'"="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
			set_ssrurl
			echo -e "    ————胖波比————
 ——————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续添加用户
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 ——————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
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
			stty erase ^H && read -p "请输入要添加的用户个数(默认:1)：" num
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
				cat /etc/shadowsocks.json | jq '.port_password."'${port}'"="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/shadowsocks.json
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
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
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
	delete_user(){
		delete_user_single(){
			clear
			jq '.port_password' /etc/shadowsocks.json
			echo -e "${Info}以上是配置文件的内容\n"
			unset port
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && "${port}" -ge "1000" && "${port}" -le "65535" && "${port}" -ne "1080" ]]
			do
				stty erase ^H && read -p "请输入要删除的端口:" port
			done
			cat /etc/shadowsocks.json | jq 'del(.port_password."'${port}'")' > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
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
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				1)
				delete_user_single
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
		delete_user_multi(){
			clear
			get_pp
			cat /root/test/ppj | while read line; do
				port=`echo $line|awk -F ':' '{print $1}'`
				delete_firewall
			done
			firewall_restart
			cat /etc/shadowsocks.json | jq "del(.port_password[])" > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
			echo -e "${Info}所有用户已删除！"
			echo -e "${Info}SSR至少要有一个用户，任意键添加用户..."
			char=`get_char`
			add_user
		}
		delete_user_menu(){
			clear
			echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 逐个删除
 ${Green_font_prefix}2.${Font_color_suffix} 全部删除
 ${Green_font_prefix}3.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
 —————————————————————" && echo
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				delete_user_single
				;;
				2)
				delete_user_multi
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
				delete_user_menu
				;;
			esac
		}
		delete_user_menu
	}
	#更改端口
	change_port(){
		clear
		get_pp
		jq '.port_password' /etc/shadowsocks.json
		echo -e "${Info}以上是配置文件的内容\n"
		unset port
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && "${port}" -ge "1000" && "${port}" -le "65535" && "${port}" -ne "1080" ]]
		do
			stty erase ^H && read -p "请输入要修改的端口号：" port
		done
		password=$(cat /root/test/ppj | grep "${port}:" | awk -F ':' '{print $2}')
		delete_firewall
		port1=${port}
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '0' && "${port}" -ge "1000" && "${port}" -le "65535" ]]
		do
			stty erase ^H && read -p "请输入修改后的端口[1000-65535]:" port
		done
		add_firewall
		firewall_restart
		sed -i "s/${port1}/${port}/g"  /etc/shadowsocks.json
		set_ssrurl
		echo -e "	————胖波比————
 ———————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续更改端口
 ${Green_font_prefix}2.${Font_color_suffix} 返回SSR用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 ———————————————————————————"
		stty erase ^H && read -p "请输入数字 [1-3](默认:3)：" num
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
 ${Green_font_prefix}2.${Font_color_suffix} 查看用户链接
 ${Green_font_prefix}3.${Font_color_suffix} 添加用户
 ${Green_font_prefix}4.${Font_color_suffix} 删除用户
 ${Green_font_prefix}5.${Font_color_suffix} 更改端口
 ${Green_font_prefix}6.${Font_color_suffix} 更改加密
 ${Green_font_prefix}7.${Font_color_suffix} 更改协议
 ${Green_font_prefix}8.${Font_color_suffix} 更改混淆
 ${Green_font_prefix}9.${Font_color_suffix} 回到主页
 ${Green_font_prefix}10.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-10](默认:10):" num
		[ -z "${num}" ] && num=10
		case "$num" in
			1)
			change_pw
			;;
			2)
			testmpo=2
			view_ssrurl
			;;
			3)
			add_user
			;;
			4)
			delete_user
			;;
			5)
			change_port
			;;
			6)
			change_method
			;;
			7)
			change_protocol
			;;
			8)
			change_obfs
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
		stty erase ^H && read -p "请输入数字 [1-9](默认:9):" num
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

#安装Trojan
manage_trojan(){
	choose_letsencrypt(){
		clear
		letsencrypt_ip(){
			clear
			ydomain=$(get_ip)
			echo -e "${Info}即将生成证书,输入假信息即可,任意键继续..."
			char=`get_char`
			openssl req -newkey rsa:2048 -nodes -keyout privkey.pem -x509 -days 3650 -out certificate.pem
		}
		letsencrypt_enc(){
			clear && cd /root
			if [ ! -d /root/letsencrypt ]; then
				git clone https://github.com/letsencrypt/letsencrypt
			fi
			cd letsencrypt
			stty erase ^H && read -p "请输入已解析成功的域名：" ydomain
			rm -rf /etc/letsencrypt/live/${ydomain}*
			rm -rf /etc/letsencrypt/archive/${ydomain}
			rm -f /etc/letsencrypt/renewal/${ydomain}.conf
			stty erase ^H && read -p "请输入真实邮箱：" yemail
			echo "a y"|sh ./letsencrypt-auto certonly --standalone -d ${ydomain} --email ${yemail}
			chmod -R 755 /etc/letsencrypt
			cp /etc/letsencrypt/live/${ydomain}/fullchain.pem /usr/local/trojan/certificate.pem
			cp /etc/letsencrypt/live/${ydomain}/privkey.pem /usr/local/trojan/privkey.pem
			cd /usr/local/trojan
		}
		echo && echo -e "   Trojan证书管理脚本
	  -- 胖波比 --

————————Trojan用户管理————————
 ${Green_font_prefix}1.${Font_color_suffix} 使用IP自签发证书
 ${Green_font_prefix}2.${Font_color_suffix} 使用Let's Encrypt域名证书
 ${Green_font_prefix}3.${Font_color_suffix} 回到主页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-4](默认:1):" num
		[ -z "${num}" ] && num=1
		case "$num" in
			1)
			letsencrypt_ip
			;;
			2)
			letsencrypt_enc
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
			choose_letsencrypt
			;;
		esac
	}
	install_trojan(){
		if [ ! -e /root/test/trojan ]; then
			port=80
			add_firewall
			port=443
			add_firewall
			firewall_restart
			touch /root/test/trojan
		fi
		cd /usr/local
		VERSION=1.13.0
		DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v${VERSION}/trojan-${VERSION}-linux-amd64.tar.xz"
		wget --no-check-certificate "${DOWNLOADURL}"
		tar xf "trojan-$VERSION-linux-amd64.tar.xz"
		rm -f "trojan-$VERSION-linux-amd64.tar.xz"
		cd trojan
		chmod -R 755 /usr/local/trojan
		mv config.json /etc/trojan.json
		password=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#password1#${password}#g" /etc/trojan.json
		password=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#password2#${password}#g" /etc/trojan.json
		sed -i 's#open": false#open": true#g' /etc/trojan.json
		cp examples/client.json-example /root/test/config.json
		sed -i 's#open": false#open": true#g' /root/test/config.json
		choose_letsencrypt
		sed -i "s#/path/to/certificate.crt#/usr/local/trojan/certificate.pem#g" /etc/trojan.json
		sed -i "s#/path/to/private.key#/usr/local/trojan/privkey.pem#g" /etc/trojan.json
		sed -i "s#example.com#${ydomain}#g" /root/test/config.json
		sed -i 's#verify": true#verify": false#g' /root/test/config.json
		sed -i 's#hostname": true#hostname": false#g' /root/test/config.json
		cp /usr/local/trojan/certificate.pem /root/test/certificate.pem
		sed -i 's#cert": "#cert": "certificate.pem#g' /root/test/config.json
		sed -i "s#sni\": \"#sni\": \"${ydomain}#g" /root/test/config.json
		echo "${ydomain}" > /root/test/trojan
		base64 -d <<< W1VuaXRdDQpBZnRlcj1uZXR3b3JrLnRhcmdldCANCg0KW1NlcnZpY2VdDQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC90cm9qYW4vdHJvamFuIC1jIC9ldGMvdHJvamFuLmpzb24NClJlc3RhcnQ9YWx3YXlzDQoNCltJbnN0YWxsXQ0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQ=  > /etc/systemd/system/trojan.service
		systemctl daemon-reload
		systemctl enable trojan
		systemctl start trojan
		testmpo=2
		view_password
		echo -e "${Info}安装完成,如需设置伪装,请手动删除配置文件中监听的 443 端口,否则会报错!!!"
		echo -e "${Info}任意键返回Trojan用户管理页..."
		char=`get_char`
		manage_user_trojan
	}
	uninstall_trojan(){
		systemctl stop trojan
		rm -rf /usr/local/trojan
		rm -f /etc/trojan.json /etc/systemd/system/trojan.service
	}
	add_user_trojan(){
		clear
		add_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			password=$(cat /proc/sys/kernel/random/uuid)
			cat /etc/trojan.json | jq '.password['${num}']="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			systemctl restart trojan
			testmpo=2
			view_password
			echo -e "    ————胖波比————
 ——————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续添加用户
 ${Green_font_prefix}2.${Font_color_suffix} 返回Trojan用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 ——————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				1)
				add_trojan_single
				;;
				2)
				manage_user_trojan
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]"
				sleep 2s
				add_user_trojan
				;;
			esac
		}
		add_trojan_multi(){
			clear
			stty erase ^H && read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			base=$(jq '.password | length' /etc/trojan.json)
			for(( i = 0; i < ${num}; i++ ))
			do
				password=$(cat /proc/sys/kernel/random/uuid)
				j=$[ $base + $i ]
				cat /etc/trojan.json | jq '.password['${j}']="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/trojan.json
			done
			systemctl restart trojan
			testmpo=1
			view_password
		}
		echo && echo -e "    ————胖波比————
—————————————————————
${Green_font_prefix}1.${Font_color_suffix} 逐个添加
${Green_font_prefix}2.${Font_color_suffix} 批量添加
${Green_font_prefix}3.${Font_color_suffix} 返回Trojan用户管理页
${Green_font_prefix}4.${Font_color_suffix} 退出脚本
—————————————————————" && echo
		stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
		[ -z "${num}" ] && num=4
		case "$num" in
			1)
			add_trojan_single
			;;
			2)
			add_trojan_multi
			;;
			3)
			manage_user_trojan
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}:请输入正确数字 [1-4]"
			sleep 2s
			add_user_trojan
			;;
		esac
	}
	delete_user_trojan(){
		delete_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			echo -e "\n${Info}当前用户总数：${Red_font_prefix}${num}${Font_color_suffix}\n"
			unset i
			until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
			do
				stty erase ^H && read -p "请输入要删除的用户序号 [1-${num}]:" i
			done
			i=$[${i}-1]
			cat /etc/trojan.json | jq 'del(.password['${i}'])' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			systemctl restart trojan
			testmpo=2
			view_password
			echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续删除用户
 ${Green_font_prefix}2.${Font_color_suffix} 返回Trojan用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————"
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				1)
				delete_trojan_single
				;;
				2)
				manage_user_trojan
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]"
				sleep 2s
				manage_user_trojan
				;;
			esac
		}
		delete_trojan_multi(){
			clear
			cat /etc/trojan.json | jq 'del(.password[])' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			echo -e "${Info}所有用户已删除！"
			echo -e "${Info}Trojan至少要有一个用户，任意键添加用户..."
			char=`get_char`
			add_user_trojan
		}
		delete_trojan_menu(){
			clear
			echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 逐个删除
 ${Green_font_prefix}2.${Font_color_suffix} 全部删除
 ${Green_font_prefix}3.${Font_color_suffix} 返回Trojan用户管理页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
 —————————————————————" && echo
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				delete_trojan_single
				;;
				2)
				delete_trojan_multi
				;;
				3)
				manage_user_trojan
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-4]"
				sleep 2s
				delete_trojan_menu
				;;
			esac
		}
		delete_trojan_menu
	}
	change_pw_trojan(){
		change_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			echo -e "\n${Info}当前用户总数：${Red_font_prefix}${num}${Font_color_suffix}\n"
			unset i
			until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
			do
				stty erase ^H && read -p "请输入要改密的用户序号 [1-${num}]:" i
			done
			i=$[${i}-1]
			password1=$(cat /etc/trojan.json | jq '.password['${i}']' | sed 's#"##g')
			password=$(cat /proc/sys/kernel/random/uuid)
			sed -i "s#${password1}#${password}#g" /etc/trojan.json
			systemctl restart trojan
			testmpo=2
			view_password
			echo -e "	————胖波比————
 —————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 继续更改密码
 ${Green_font_prefix}2.${Font_color_suffix} 返回Trojan用户管理页
 ${Green_font_prefix}3.${Font_color_suffix} 退出脚本
 —————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				1)
				change_trojan_single
				;;
				2)
				manage_user_trojan
				;;
				3)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-3]:"
				sleep 2s
				change_trojan_menu
				;;
			esac
		}
		change_trojan_multi(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			for(( i = 0; i < ${num}; i++ ))
			do
				password=$(cat /proc/sys/kernel/random/uuid)
				cat /etc/trojan.json | jq '.password['${i}']="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/trojan.json
			done
			testmpo=1
			view_password
		}
		change_trojan_menu(){
			clear
			echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 逐个修改
 ${Green_font_prefix}2.${Font_color_suffix} 全部修改
 ${Green_font_prefix}3.${Font_color_suffix} 返回Trojan用户管理页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
 —————————————————————" && echo
			stty erase ^H && read -p "请输入数字[1-4](默认:4)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				change_trojan_single
				;;
				2)
				change_trojan_multi
				;;
				3)
				manage_user_trojan
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}:请输入正确数字 [1-4]"
				sleep 2s
				change_trojan_menu
				;;
			esac
		}
		change_trojan_menu
	}
	view_password(){
		clear
		temp=$(jq '.password' /etc/trojan.json)
		cat /root/test/config.json | jq ".password=${temp}" > /root/test/temp.json
		cp /root/test/temp.json /root/test/config.json
		jq '.password' /etc/trojan.json
		echo -e "${Info}IP或域名：${Red_font_prefix}$(cat /root/test/trojan)${Font_color_suffix}"
		echo -e "${Info}端口：${Red_font_prefix}443${Font_color_suffix}"
		echo -e "${Info}当前用户总数：${Red_font_prefix}$(jq '.password | length' /etc/trojan.json)${Font_color_suffix}\n"
		if [[ ${testmpo} == "1" ]]; then
			echo -e "${Info}任意键返回Trojan用户管理页..."
			char=`get_char`
			manage_user_trojan
		fi
	}
	manage_user_trojan(){
		clear
		echo && echo -e "   Trojan用户管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
手动修改配置文件：vi /etc/trojan.json

————————Trojan用户管理————————
 ${Green_font_prefix}1.${Font_color_suffix} 添加用户
 ${Green_font_prefix}2.${Font_color_suffix} 删除用户
 ${Green_font_prefix}3.${Font_color_suffix} 更改密码
 ${Green_font_prefix}4.${Font_color_suffix} 查看用户密码
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
——————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
		[ -z "${num}" ] && num=6
		case "$num" in
			1)
			add_user_trojan
			;;
			2)
			delete_user_trojan
			;;
			3)
			change_pw_trojan
			;;
			4)
			testmpo=1
			view_password
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
			manage_user_trojan
			;;
		esac
	}
	start_menu_trojan(){
		clear
		echo && echo -e " Trojan一键安装脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
    -- 胖波比 --

—————————Trojan安装————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装Trojan
 ${Green_font_prefix}2.${Font_color_suffix} 卸载Trojan
 ${Green_font_prefix}3.${Font_color_suffix} 管理Trojan用户
 ${Green_font_prefix}4.${Font_color_suffix} 重启Trojan
 ${Green_font_prefix}5.${Font_color_suffix} 关闭Trojan
 ${Green_font_prefix}6.${Font_color_suffix} 启动Trojan
 ${Green_font_prefix}7.${Font_color_suffix} 查看Trojan状态
 ${Green_font_prefix}8.${Font_color_suffix} 回到主页
 ${Green_font_prefix}9.${Font_color_suffix} 退出脚本
———————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-9](默认:9):" num
		[ -z "${num}" ] && num=9
		case "$num" in
			1)
			install_trojan
			;;
			2)
			uninstall_trojan
			;;
			3)
			manage_user_trojan
			;;
			4)
			systemctl restart trojan
			;;
			5)
			systemctl stop trojan
			;;
			6)
			systemctl start trojan
			;;
			7)
			systemctl status trojan
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
			start_menu_trojan
			;;
		esac
		start_menu_trojan
	}
	start_menu_trojan
}

#安装BBR或锐速
install_bbr(){
	github="raw.githubusercontent.com/chiakge/Linux-NetSpeed/master"
	#安装BBR内核
	installbbr(){
		kernel_version="4.11.8"
		if [[ "${release}" == "centos" ]]; then
			if [[ "${version}" -ge "8" ]]; then
				echo -e "${Error}暂不支持CentOS ${version}系统!!!任意键返回主页..."
				char=`get_char`
				start_menu_main
			fi
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
		stty erase '^H' && stty erase ^H && read -p "需要重启VPS后，才能开启BBR/BBR魔改版，是否现在重启 ? [Y/n] :" yn
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
			if [[ "${version}" -ge "8" ]]; then
				echo -e "${Error}暂不支持CentOS ${version}系统!!!任意键返回主页..."
				char=`get_char`
				start_menu_main
			fi
			wget -N --no-check-certificate https://${github}/bbrplus/${release}/${version}/kernel-headers-${kernel_version}.rpm
			wget -N --no-check-certificate https://${github}/bbrplus/${release}/${version}/kernel-${kernel_version}.rpm
			yum install -y kernel-headers-${kernel_version}.rpm
			yum install -y kernel-${kernel_version}.rpm
			rm -f kernel-headers-${kernel_version}.rpm
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
		stty erase '^H' && stty erase ^H && read -p "需要重启VPS后，才能开启BBRplus，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装Lotserver内核
	installlot(){
		if [[ "${release}" == "centos" ]]; then
			if [[ "${version}" -ge "8" ]]; then
				echo -e "${Error}暂不支持CentOS ${version}系统!!!任意键返回主页..."
				char=`get_char`
				start_menu_main
			fi
			kernel_version="2.6.32-504"
			rpm --import http://${github}/lotserver/${release}/RPM-GPG-KEY-elrepo.org
			yum remove -y kernel-firmware
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-firmware-${kernel_version}.rpm
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-${kernel_version}.rpm
			yum remove -y kernel-headers
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-headers-${kernel_version}.rpm
			yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-devel-${kernel_version}.rpm
		elif [[ "${release}" == "ubuntu" || "${release}" == "debian" ]]; then
			bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}Lotserver${Font_color_suffix}"
		stty erase '^H' && stty erase ^H && read -p "需要重启VPS后，才能开启Lotserver，是否现在重启 ? [Y/n] :" yn
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
		stty erase ^H && read -p "需要重启VPS后，才能生效系统优化配置，是否现在重启 ? [Y/n] :" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#############内核管理组件#############
	#删除多余内核
	detele_kernel(){
		if [[ "${release}" == "centos" ]]; then
			rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
			if [ "${rpm_total}" > "1" ]; then
				echo -e "${Info}检测到 ${rpm_total} 个其余内核，开始卸载..."
				for((integer = 1; integer <= ${rpm_total}; integer++)); do
					rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
					echo -e "${Info}开始卸载 ${rpm_del} 内核..."
					rpm --nodeps -e ${rpm_del}
					echo -e "${Info}卸载 ${rpm_del} 内核卸载完成，继续..."
				done
				echo -e "${Info}内核卸载完毕，继续..."
			else
				echo -e "${Info}检测到 内核 数量不正确，请检查 !" && exit 1
			fi
		elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
			deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
			if [ "${deb_total}" > "1" ]; then
				echo -e "${Info}检测到 ${deb_total} 个其余内核，开始卸载..."
				for((integer = 1; integer <= ${deb_total}; integer++)); do
					deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
					echo -e "${Info}开始卸载 ${deb_del} 内核..."
					apt-get purge -y ${deb_del}
					echo -e "${Info}卸载 ${deb_del} 内核卸载完成，继续..."
				done
				echo -e "${Info}内核卸载完毕，继续..."
			else
				echo -e "${Info}检测到 内核 数量不正确，请检查 !" && exit 1
			fi
		fi
	}

	#更新引导
	BBR_grub(){
		if [[ "${release}" == "centos" ]]; then
			if [[ ${version} == "6" ]]; then
				if [ ! -f "/boot/grub/grub.conf" ]; then
					echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
					exit 1
				fi
				sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
			elif [[ ${version} -ge "7" ]]; then
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

	#############系统检测组件#############
	#检查Linux版本
	check_version_bbr(){
		bit=`uname -m`
		if [[ "${bit}" =~ "64" ]]; then
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
	stty erase ^H && read -p "请输入数字 [1-12](默认:12):" num
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
	check_version_bbr
	start_menu_bbr
}

#安装宝塔面板
install_btpanel(){
	LANG=en_US.UTF-8

	Red_Error(){
		echo '=================================================';
		printf '\033[1;31;40m%b\033[0m\n' "$1";
		exit 0;
	}

	is64bit=$(getconf LONG_BIT)
	if [ "${is64bit}" != '64' ];then
		Red_Error "抱歉, 6.0不支持32位系统,请使用64位系统或安装宝塔5.9!";
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
			stty erase ^H && read -p "输入yes强制安装/Enter yes to force installation (yes/n): " yes;
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
	Auto_Swap(){
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
		stty erase ^H && read -p "请输入宝塔面板登录端口(默认:1314):" panelPort
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
	Install_Pillow(){
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
	Install_psutil(){
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
	Install_chardet(){
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
			else
				iptables-save > /etc/iptables.up.rules
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
		stty erase ^H && read -p "Do you want to install Bt-Panel to the $setup_path directory now?(y/n): " go;
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

#安装ZFAKA
manage_zfaka(){
	install_zfaka(){
		install_docker
		mkdir -p /opt/zfaka && cd /opt/zfaka
		rm -f docker-compose.yml
		wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/zfaka/docker-compose.yml
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成"
		docker-compose up -d
		echo -e "\n${Info}首页地址： http://$(get_ip):666"
		echo -e "打开网站安装数据库时请修改如下信息"
		echo -e "请将数据库127.0.0.1改为：mysql"
		echo -e "请将数据库密码改为：baiyue.one"
		echo -e "${Info}phpMyAdmin地址：http://$(get_ip):602 用户名：root 密码：baiyue.one"
		echo -e "\n${Info}按任意键返回主页..."
		char=`get_char`
		start_menu_main
	}
	uninstall_zfaka(){
		cd /opt/zfaka
		docker-compose down
		rm -fr /opt/zfaka
	}
	restart_zfaka(){
		cd /opt/zfaka
		docker-compose restart
	}
	stop_zfaka(){
		cd /opt/zfaka
		docker-compose kill
	}
	start_menu_zfaka(){
		clear
		echo && echo -e " ZFAKA一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
			
————————ZFAKA管理————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装ZFAKA
 ${Green_font_prefix}2.${Font_color_suffix} 卸载ZFAKA
 ${Green_font_prefix}3.${Font_color_suffix} 重启ZFAKA
 ${Green_font_prefix}4.${Font_color_suffix} 停止ZFAKA
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
—————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
		[ -z "${num}" ] && num=6
		case "$num" in
			1)
			install_zfaka
			;;
			2)
			uninstall_zfaka
			;;
			3)
			restart_zfaka
			;;
			4)
			stop_zfaka
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
			start_menu_zfaka
			;;
		esac
	}
	start_menu_zfaka
}

#安装SSR控制面板
manage_sspanel(){
	#安装前端
	install_sspanel_front(){
		install_sspanel(){
			if [ -e /root/test/sp ]; then
				echo -e "${Info}SS-PANEL已安装"
			else
				install_docker
				echo -e "${Info}正在开始安装SS-PANEL..."
				mkdir -p /opt/sspanel && cd /opt/sspanel
				rm -f docker-compose.yml
				echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成"
				wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/ssrpanel/docker-compose.yml
				sed -i "s/sspanel_type/${sspaneltype}/g" /opt/sspanel/docker-compose.yml
				docker-compose up -d
				touch /root/test/sp && touch /root/test/ko
				if [ -e /root/test/cr ]; then
					echo -e "${Info}定时任务已添加"
				else
					echo -e "${Info}正在添加定时任务..."
					echo '30 22 * * * docker exec -t sspanel php xcat sendDiaryMail' >> /var/spool/cron/crontabs/root
					echo '0 0 * * * docker exec -t sspanel php -n xcat dailyjob' >> /var/spool/cron/crontabs/root
					echo '*/1 * * * * docker exec -t sspanel php xcat checkjob' >> /var/spool/cron/crontabs/root
					echo '*/1 * * * * docker exec -t sspanel php xcat syncnode' >> /var/spool/cron/crontabs/root
					echo '0 */20 * * * docker exec -t sspanel php -n xcat backup' >> /var/spool/cron/crontabs/root
					echo '5 0 * * * docker exec -t sspanel php xcat sendFinanceMail_day' >> /var/spool/cron/crontabs/root
					echo '6 0 * * 0 docker exec -t sspanel php xcat sendFinanceMail_week' >> /var/spool/cron/crontabs/root
					echo '7 0 1 * * docker exec -t sspanel php xcat sendFinanceMail_month' >> /var/spool/cron/crontabs/root
					/etc/init.d/cron restart
					touch /root/test/cr
				fi
				if [ ! -e /root/msp.sh ]; then
					cd /root && wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/ssrpanel/msp.sh && chmod +x msp.sh
				fi
				clear
				echo -e "\n${Info}网站首页：http://$(get_ip):603"
				echo -e "${Info}Kodexplorer：http://$(get_ip):604"
				echo -e "${Info}网站地址：/opt/sspanel/code"
				echo -e "\n${Info}即将同步数据库并创建管理员账户\n${Info}请输入：./msp.sh"
				echo -e "${Info}任意键继续..."
				char=`get_char`
				exit 1
			fi
		}
		select_sspanel_type(){
			clear
			echo -e "\n${Info}SS-PANEL前端只需要安装在面板机！！！
	-- 胖波比 --

————————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装开发版
 ${Green_font_prefix}2.${Font_color_suffix} 安装稳定版
 ${Green_font_prefix}3.${Font_color_suffix} 回到主页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本 
————————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-4](默认:4):" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				sspaneltype="dev"
				install_sspanel
				;;
				2)
				sspaneltype="master"
				install_sspanel
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
				select_sspanel_type
				;;
			esac
		}
		select_sspanel_type
	}
	#安装后端
	install_sspanel_back(){
		node_database(){
			stty erase ^H && read -p "请输入面板创建的节点序号(例如:3):" nodeid
			if [ ! -e /root/test/spdb ]; then
				stty erase ^H && read -p "请输入面板机域名或IP(默认本机IP):" mysqldomain
				[ -z "${mysqldomain}" ] && mysqldomain="127.0.0.1"
				install_docker
				docker run -d --name=ssrmu -e NODE_ID=${nodeid} -e API_INTERFACE=glzjinmod -e MYSQL_HOST=${mysqldomain} -e MYSQL_USER=root -e MYSQL_DB=sspanel -e MYSQL_PASS=sspanel --network=host --log-opt max-size=50m --log-opt max-file=3 --restart=always fanvinga/docker-ssrmu
				add_firewall_all
				touch /root/test/spdb
			else
				echo -e "${Info}暂未完善，等待修复，敬请期待..."
				sleep 3s
			fi
		}
		node_webapi(){
			stty erase ^H && read -p "请输入面板创建的节点序号(例如:3):" nodeid
			if [ ! -e /root/test/spwa ]; then
				stty erase ^H && read -p "请输入面板机域名或IP(默认本机IP):" mysqldomain
				[ -z "${mysqldomain}" ] && mysqldomain="127.0.0.1"
				mysqldomain="http://${mysqldomain}"
				install_docker
				docker run -d --name=ssrmu -e NODE_ID=${nodeid} -e API_INTERFACE=modwebapi -e WEBAPI_URL=${mysqldomain} -e WEBAPI_TOKEN=NimaQu --network=host --log-opt max-size=50m --log-opt max-file=3 --restart=always fanvinga/docker-ssrmu
				add_firewall_all
				touch /root/test/spwa
			else
				echo -e "${Info}暂未完善，等待修复，敬请期待..."
				sleep 3s
			fi
		}
		sspanel_db_menu(){
			clear
			echo -e "
SS-PANEL_UIM 后端对接一键脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
	  
————————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} Database对接
 ${Green_font_prefix}2.${Font_color_suffix} WebApi对接
 ${Green_font_prefix}3.${Font_color_suffix} 回到主页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-4](默认:4):" num
			[ -z "${num}" ] && num=4
			case "$num" in
				1)
				node_database
				;;
				2)
				node_webapi
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
				sspanel_db_menu
				;;
			esac
		}
		sspanel_db_menu
	}
	uninstall_sspanel(){
		cd /opt/sspanel
		docker-compose down
		rm -rf /opt/sspanel && rm -f /root/test/sp && rm -f /root/test/ko
		rm -f /root/test/spdb && rm -f /root/test/spwa && rm -f /root/test/my
	}
	#管理面板
	sspanel_start_menu(){
		clear
		echo -e "
SS-PANEL_UIM 一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
修改网站配置文件：vi /opt/sspanel/code/config/.config.php

————————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装SS-PANEL前端
 ${Green_font_prefix}2.${Font_color_suffix} 安装SS-PANEL后端
 ${Green_font_prefix}3.${Font_color_suffix} 卸载SS-PANEL
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-5](默认:5):" num
		[ -z "${num}" ] && num=5
		case "$num" in
			1)
			install_sspanel_front
			;;
			2)
			install_sspanel_back
			;;
			3)
			uninstall_sspanel
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
			sspanel_start_menu
			;;
		esac
	}
	sspanel_start_menu
}

#安装Kodexplorer
manage_kodexplorer(){
	install_kodexplorer(){
		if [ -e /root/test/ko ]; then
			echo -e "${Info}Kodexplorer已安装!"
		else
			install_docker
			echo -e "${Info}正在安装Kodexplorer..."
			docker run -d -p 604:80 --name kodexplorer -v /opt/kodcloud:/code baiyuetribe/kodexplorer
			touch /root/test/ko
			echo -e "\n${Info}请访问http://$(get_ip):604"
			echo -e "${Info}默认宿主机目录/opt/kodcloud"
			echo -e "\n${Info}按任意键返回主页..."
			char=`get_char`
			start_menu_main
		fi
	}
	start_menu_kodexplorer(){
		clear
		echo && echo -e " Kodexplorer一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --

—————Kodexplorer管理—————
 ${Green_font_prefix}1.${Font_color_suffix} 安装Kodexplorer
 ${Green_font_prefix}2.${Font_color_suffix} 卸载Kodexplorer
 ${Green_font_prefix}3.${Font_color_suffix} 重启Kodexplorer
 ${Green_font_prefix}4.${Font_color_suffix} 停止Kodexplorer
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
—————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
		[ -z "${num}" ] && num=6
		case "$num" in
			1)
			install_kodexplorer
			;;
			2)
			cd /opt/kodcloud
			docker-compose down
			rm -rf /opt/kodcloud
			rm -f /root/test/ko
			;;
			3)
			cd /opt/kodcloud
			docker-compose restart
			;;
			4)
			cd /opt/kodcloud
			docker-compose kill
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
			start_menu_kodexplorer
			;;
		esac
	}
	start_menu_kodexplorer
}

#安装WordPress
manage_wordpress(){
	install_wordpress(){
		unset port
		until [[ ${port} -ge "1" && ${port} -le "65535" ]]
		do
			clear
			echo -e "\n${Info}请输入网站访问端口,必须是未占用端口,否则安装失败!!!"
			stty erase ^H && read -p "请输入网站访问端口(默认:80)：" port
			[ -z "${port}" ] && port=80
		done
		install_docker
		mkdir -p /opt/wordpress && cd /opt/wordpress
		rm -f docker-compose.yml
		wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/wordpress/docker-compose.yml
		sed -i "s#66#${port}#g" docker-compose.yml
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成"
		docker-compose up -d
		echo -e "\n${Info}首页地址： http://$(get_ip):${port}"
		echo -e "${Info}phpMyAdmin地址：http://$(get_ip):605 用户名：root 密码：pangbobi"
		echo -e "\n${Info}按任意键返回主页..."
		char=`get_char`
		start_menu_main
	}
	uninstall_wordpress(){
		cd /opt/wordpress
		docker-compose down
		rm -fr /opt/wordpress
	}
	restart_wordpress(){
		cd /opt/wordpress
		docker-compose restart
	}
	stop_wordpress(){
		cd /opt/wordpress
		docker-compose kill
	}
	start_menu_wordpress(){
		clear
		echo && echo -e " WordPress一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --

——————WordPress管理——————
 ${Green_font_prefix}1.${Font_color_suffix} 安装WordPress
 ${Green_font_prefix}2.${Font_color_suffix} 卸载WordPress
 ${Green_font_prefix}3.${Font_color_suffix} 重启WordPress
 ${Green_font_prefix}4.${Font_color_suffix} 停止WordPress
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
—————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
		[ -z "${num}" ] && num=6
		case "$num" in
			1)
			install_wordpress
			;;
			2)
			uninstall_wordpress
			;;
			3)
			restart_wordpress
			;;
			4)
			stop_wordpress
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
			start_menu_wordpress
			;;
		esac
	}
	start_menu_wordpress
}

#安装Docker
manage_docker(){
	install_seagull(){
		install_docker
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成"
		docker run -d -p 10086:10086 -v /var/run/docker.sock:/var/run/docker.sock tobegit3hub/seagull
		echo -e "\n${Info}首页地址： http://$(get_ip):10086"
		echo -e "\n${Info}按任意键返回主页..."
		char=`get_char`
		start_menu_main
	}
	uninstall_docker(){
		${PM} --purge docker-engine
	}
	uninstall_docker_all(){
		docker stop $(docker ps -a -q)
		docker rm $(docker ps -a -q)
		docker rmi -f $(docker images -q)
	}
	start_menu_docker(){
		clear
		echo && echo -e " Docker一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
			
————————Docker管理———————
 ${Green_font_prefix}1.${Font_color_suffix} 安装Docker
 ${Green_font_prefix}2.${Font_color_suffix} 安装海鸥Docker管理器
 ${Green_font_prefix}3.${Font_color_suffix} 卸载Docker
 ${Green_font_prefix}4.${Font_color_suffix} 删除所有Docker镜像,容器,卷
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
—————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
		[ -z "${num}" ] && num=6
		case "$num" in
			1)
			install_docker
			;;
			2)
			install_seagull
			;;
			3)
			uninstall_docker
			;;
			4)
			uninstall_docker_all
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
			start_menu_docker
			;;
		esac
	}
	start_menu_docker
}

#安装Caddy
install_caddy(){
	file="/usr/local/caddy/"
	caddy_file="/usr/local/caddy/caddy"
	caddy_conf_file="/usr/local/caddy/Caddyfile"
	Info_font_prefix="\033[32m" && Error_font_prefix="\033[31m" && Info_background_prefix="\033[42;37m" && Error_background_prefix="\033[41;37m" && Font_suffix="\033[0m"

	check_installed_status(){
		[[ ! -e ${caddy_file} ]] && echo -e "${Error_font_prefix}[错误]${Font_suffix} Caddy 没有安装，请检查 !" && install_caddy
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
			echo -e "${Error_font_prefix}[错误]${Font_suffix} 不支持 [${bit}] !请向本站反馈[]中的名称，我会看看是否可以添加支持。" && exit 1
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
	}
	caddy_install(){
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
		svn checkout "https://github.com/AmuyangA/public/trunk/html" /usr/local/caddy/listenport
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
	#配置Caddy
	set_caddy_ip(){
		clear
		port=80
		add_firewall
		port=443
		add_firewall
		firewall_restart
		echo "$(get_ip):80 {
	gzip
	root /usr/local/caddy/listenport
}
$(get_ip):443 {
	gzip
	root /usr/local/caddy/listenport
}" > /usr/local/caddy/Caddyfile
		service caddy restart
		echo -e "${Info}Caddy重启成功!"
		sleep 2s
	}
	set_caddy_domain(){
		clear
		echo && echo -e " Caddy监听一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --"
		stty erase ^H && read -p "请输入你的域名:" domain
		stty erase ^H && read -p "请输入你的邮箱:" yemail
		echo "$domain {
		gzip
		tls $yemail
		root /usr/local/caddy/listenport
		}" > /usr/local/caddy/Caddyfile
		service caddy restart
		echo -e "${Info}Caddy重启成功!"
		sleep 2s
	}
	caddy_back(){
		caddy_back_ip(){
			clear
			port=80
			add_firewall
			port=443
			add_firewall
			firewall_restart
			stty erase ^H && read -p "请输入代理端口[1-65535]:" port
			echo "$(get_ip):80 {
	gzip
	proxy / localhost:$port
}
$(get_ip):443 {
	gzip
	proxy / localhost:$port
}" > /usr/local/caddy/Caddyfile
			service caddy restart
			echo -e "${Info}Caddy重启成功!"
			sleep 2s
		}
		caddy_back_domain(){
			clear
			echo && echo -e " Caddy反向代理一键设置
	-- 胖波比 --"
			stty erase ^H && read -p "请输入你的域名:" domain
			stty erase ^H && read -p "请输入代理端口[1-65535]:" port
			stty erase ^H && read -p "请输入你的邮箱:" yemail
			echo "$domain {
			gzip
			tls $yemail
			proxy / localhost:$port
			}" > /usr/local/caddy/Caddyfile
			service caddy restart
			echo -e "${Info}Caddy重启成功!"
			sleep 2s
		}
		caddy_back_menu(){
			clear
			echo && echo -e " Caddy反向代理管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --

——————————Caddy反向代理—————————
 ${Green_font_prefix}1.${Font_color_suffix} 使用本机IP
 ${Green_font_prefix}2.${Font_color_suffix} 使用已解析生效的域名
 ${Green_font_prefix}3.${Font_color_suffix} 回到Caddy管理页
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-5](默认:5):" num
			[ -z "${num}" ] && num=5
			case "$num" in
				1)
				caddy_back_ip
				;;
				2)
				caddy_back_domain
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
				caddy_back_menu
				;;
			esac
			caddy_back_menu
		}
		caddy_back_menu
	}
	manage_caddy(){
			clear
			echo && echo -e " Caddy一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
手动修改配置文件：vi /usr/local/caddy/Caddyfile

————————————Caddy管理———————————
 ${Green_font_prefix}1.${Font_color_suffix} 使用本机IP
 ${Green_font_prefix}2.${Font_color_suffix} 使用已解析生效的域名
 ${Green_font_prefix}3.${Font_color_suffix} 反向代理
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-5](默认:5):" num
			[ -z "${num}" ] && num=5
			case "$num" in
				1)
				set_caddy_ip
				;;
				2)
				set_caddy_domain
				;;
				3)
				caddy_back
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
 ${Green_font_prefix}2.${Font_color_suffix} 管理Caddy
 ${Green_font_prefix}3.${Font_color_suffix} 卸载Caddy
 ${Green_font_prefix}4.${Font_color_suffix} 重启Caddy
 ${Green_font_prefix}5.${Font_color_suffix} 关闭Caddy
 ${Green_font_prefix}6.${Font_color_suffix} 启动Caddy
 ${Green_font_prefix}7.${Font_color_suffix} 查看Caddy状态
 ${Green_font_prefix}8.${Font_color_suffix} 回到主页
 ${Green_font_prefix}9.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-9](默认:9):" num
		[ -z "${num}" ] && num=9
		case "$num" in
			1)
			caddy_install
			;;
			2)
			manage_caddy
			;;
			3)
			uninstall_caddy
			;;
			4)
			service caddy restart
			;;
			5)
			service caddy stop
			;;
			6)
			service caddy start
			;;
			7)
			service caddy status
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
			start_menu_caddy
			;;
		esac
	}
	extension=$2
	start_menu_caddy
}

#安装Nginx
install_nginx(){
	nginx_install(){
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
		echo -e "${Info}安装完成！2秒后开启Nginx"
		sleep 2s
		systemctl start nginx.service
		echo -e "${Info}Nginx已开启！2秒后回到管理页"
		sleep 2s
		manage_nginx
	}
	#配置Nginx
	set_nginx(){
		#配置结尾
		set_nginx_success(){
			echo -e "${Info}修改Nginx配置成功，2秒后重启Nginx"
			sleep 2s
			systemctl restart nginx.service
			echo -e "${Info}Nginx重启成功，2秒后回到配置管理页"
			sleep 2s
			set_nginx_menu
		}
		#默认配置
		set_nginx_first(){
			#设置Nginx网页
			rm -f /usr/share/nginx/html/index.html
			echo -e "${Info}正在下载网页。请稍等···"
			sleep 2s
			svn checkout "https://github.com/AmuyangA/public/trunk/html" /usr/share/nginx/html
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
			touch /root/test/ng
			port=80
			add_firewall
			port=443
			add_firewall
			firewall_restart
			echo -e "${Info}已默认添加80,443端口"
			sleep 2s
			set_nginx_success
		}
		#添加监听端口
		add_nginx(){
			set_nginx_first
			cat /etc/nginx/conf.d/default.conf
			stty erase ^H && read -p "请输入端口[1-65535],不可重复,(默认:8080):" port
			[ -z "${port}" ] && port=8080
			add_firewall
			firewall_restart
			sed -i "2i\\\tlisten ${port};" /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#删除监听端口
		delete_nginx(){
			cat /etc/nginx/conf.d/default.conf
			stty erase ^H && read -p "请输入端口[1-65535],已有端口,(默认:8080):" port
			[ -z "${port}" ] && port=8080
			port=$(sed -n -e '/${port}/=' /etc/nginx/conf.d/default.conf)
			sed -i '${port} d' /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#反向代理
		nginx_back(){
			clear
			echo && echo -e " Nginx反向代理一键设置
    -- 胖波比 --"
			stty erase ^H && read -p "请输入你的域名(默认本机IP):" domain
			[ -z "${domain}" ] && domain=$(get_ip)
			stty erase ^H && read -p "请输入代理端口[1-65535]:" port
			echo "server {
	listen 80;
	server_name  $domain;
	location / {
		proxy_pass http://$(get_ip):$port;
	}
}" > /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#配置方式选择
		set_nginx_menu(){
			clear
			echo && echo -e " Nginx配置管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
手动修改配置文件：vi /etc/nginx/conf.d/default.conf
		
——————————Nginx配置管理—————————
 ${Green_font_prefix}1.${Font_color_suffix} 恢复默认设置
 ${Green_font_prefix}2.${Font_color_suffix} 添加监听端口(不可添加已占用端口)
 ${Green_font_prefix}3.${Font_color_suffix} 删除监听端口
 ${Green_font_prefix}4.${Font_color_suffix} 反向代理
 ${Green_font_prefix}5.${Font_color_suffix} 回到主页
 ${Green_font_prefix}6.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
			stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
			[ -z "${num}" ] && num=6
			case "$num" in
				1)
				set_nginx_first
				;;
				2)
				add_nginx
				;;
				3)
				delete_nginx
				;;
				4)
				nginx_back
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
				set_nginx_menu
				;;
			esac
		}
		test ! -e /root/test/ng || set_nginx_menu
		set_nginx_first
	}
	nginx_uninstall(){
		if [[ "${release}" == "centos" ]]; then
			yum --purge remove nginx
		else
			apt-get --purge remove nginx
		fi
		rm -f testng
	}
	#Nginx管理
	manage_nginx(){
		clear
		echo && echo -e " Nginx一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
		
————————————Nginx管理————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装Nginx
 ${Green_font_prefix}2.${Font_color_suffix} 配置Nginx
 ${Green_font_prefix}3.${Font_color_suffix} 卸载Nginx
 ${Green_font_prefix}4.${Font_color_suffix} 启动Nginx
 ${Green_font_prefix}5.${Font_color_suffix} 关闭Nginx
 ${Green_font_prefix}6.${Font_color_suffix} 重启Nginx
 ${Green_font_prefix}7.${Font_color_suffix} 查看Nginx状态
 ${Green_font_prefix}8.${Font_color_suffix} 回到主页
 ${Green_font_prefix}9.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-9](默认:9):" num
		[ -z "${num}" ] && num=9
		case "$num" in
			1)
			nginx_install
			;;
			2)
			set_nginx
			;;
			3)
			nginx_uninstall
			;;
			4)
			systemctl start nginx.service
			;;
			5)
			systemctl stop nginx.service
			;;
			6)
			systemctl restart nginx.service
			;;
			7)
			systemctl status nginx.service
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
			manage_nginx
			;;
		esac
	}
	manage_nginx
 }

#设置SSH端口
set_ssh(){
	clear
	ssh_port=$(cat /etc/ssh/sshd_config|grep 'Port '|head -1|awk -F ' ' '{print $2}')
	while :; do echo
		stty erase ^H && read -p "Please input SSH port(Default: $ssh_port): " SSH_PORT
		[ -z "$SSH_PORT" ] && SSH_PORT=$ssh_port
		if [ $SSH_PORT -eq 22 >/dev/null 2>&1 -o $SSH_PORT -gt 1024 >/dev/null 2>&1 -a $SSH_PORT -lt 65535 >/dev/null 2>&1 ];then
			break
		else
			echo "${Error}input error! Input range: 22,1025~65534${CEND}"
		fi
	done
	if [[ ${SSH_PORT} != "${ssh_port}" ]]; then
		#开放安全权限
		if [[ -x "$(command -v sestatus)" && $(getenforce) != "Disabled" ]]; then
			if [[ ! -x "$(command -v semanage)" && ${release} == "centos" ]]; then
				pack_semanage=$(yum provides semanage|grep ' : '|head -1|awk -F ' :' '{print $1}')
				yum -y install ${pack_semanage}
			fi
			semanage port -a -t ssh_port_t -p tcp ${SSH_PORT}
		fi
		#修改SSH端口
		sed -i "s/.*Port ${ssh_port}/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
		#开放端口
		port=$SSH_PORT
		add_firewall
		port=$ssh_port
		delete_firewall
		firewall_restart
		#重启SSH
		if [[ ${release} == "centos" ]]; then
			service sshd restart
		else
			service ssh restart
		fi
		#关闭安全权限
		if [[ -x "$(command -v semanage)" && ${ssh_port} != "22" ]]; then
			semanage port -d -t ssh_port_t -p tcp ${ssh_port}
		fi
		echo -e "${Info}SSH防火墙已重启！"
	fi
	echo -e "${Info}已将SSH端口修改为：${Red_font_prefix}${SSH_PORT}${Font_color_suffix}"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
	start_menu_main
}

#设置Root密码
set_root(){
	clear
	echo && echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 使用高强度随机密码
 ${Green_font_prefix}2.${Font_color_suffix} 输入自定义密码
 ${Green_font_prefix}3.${Font_color_suffix} 返回主页
 —————————————————————" && echo
	stty erase ^H && read -p "请输入数字[1-3](默认:3)：" num
	[ -z "${num}" ] && num=3
	case "$num" in
		1)
		pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom | head -c 17)
		;;
		2)
		stty erase ^H && read -p "请设置密码(默认:pangbobi):" pw
		[ -z "${pw}" ] && pw="pangbobi"
		;;
		3)
		start_menu_main
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-3]"
		sleep 2s
		set_root
		;;
	esac
	echo root:${pw} | chpasswd
	# 启用root密码登陆
	sed -i '1,/PermitRootLogin/{s/.*PermitRootLogin.*/PermitRootLogin yes/}' /etc/ssh/sshd_config
	sed -i '1,/PasswordAuthentication/{s/.*PasswordAuthentication.*/PasswordAuthentication yes/}' /etc/ssh/sshd_config
	# 重启ssh服务
	if [[ "${release}" == "centos" ]]; then
		service sshd restart
	else
		service ssh restart
	fi
	echo -e "\n${Info}您的密码是：${Red_font_prefix}${pw}${Font_color_suffix}"
	echo -e "${Info}请务必记录您的密码！然后任意键返回主页"
	char=`get_char`
	start_menu_main
}

#系统性能测试
test_sys(){
	#千影大佬的脚本
	qybench(){
		wget https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/linuxtest.sh && chmod +x linuxtest.sh
		clear
		echo && echo -e " 系统性能一键测试综合脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	-- 胖波比 --
			
————————————性能测试————————————
 ${Green_font_prefix}1.${Font_color_suffix} 运行（不含UnixBench）
 ${Green_font_prefix}2.${Font_color_suffix} 运行（含UnixBench）
 ${Green_font_prefix}3.${Font_color_suffix} 回到主页
 ${Green_font_prefix}4.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo
		stty erase ^H && read -p "请输入数字 [1-4](默认:4):" num
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
		# Colors
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		SKYBLUE='\033[0;36m'
		PLAIN='\033[0m'

		about() {
			echo ""
			echo " Copyright (C) 2019 胖波比 hsxmuyang68@gmail.com"
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
					#stty erase ^H && read -p "${RED}Error:${PLAIN} python is not install. You must be install python command at first.\nDo you want to install? [y/n]" is_install
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
				#stty erase ^H && read -p "${RED}Error:${PLAIN} curl is not install. You must be install curl command at first.\nDo you want to install? [y/n]" is_install
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
				#stty erase ^H && read -p "${RED}Error:${PLAIN} wget is not install. You must be install wget command at first.\nDo you want to install? [y/n]" is_install
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
 ${Green_font_prefix}1.${Font_color_suffix} 执行全局测试
 ${Green_font_prefix}2.${Font_color_suffix} 执行国际测试
 ${Green_font_prefix}3.${Font_color_suffix} 执行国内三网测试
 ${Green_font_prefix}4.${Font_color_suffix} 回到主页
 ${Green_font_prefix}5.${Font_color_suffix} 退出脚本
————————————————————————————————" && echo

		echo
		stty erase ^H && read -p "请输入数字 [1-5](默认:5):" num
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
	clear
	echo -e "${Info}重装系统需要时间,请耐心等待..."
	echo -e "${Info}重装完成后,请用root身份从22端口连接服务器！\n"
	echo -e "    ————胖波比————
 —————————————————————
 ${Green_font_prefix}1.${Font_color_suffix} 使用高强度随机密码
 ${Green_font_prefix}2.${Font_color_suffix} 输入自定义密码
 ${Green_font_prefix}3.${Font_color_suffix} 返回主页
 —————————————————————" && echo
	stty erase ^H && read -p "请输入数字[1-3](默认:3)：" num
	[ -z "${num}" ] && num=3
	case "$num" in
		1)
		pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom | head -c 17)
		;;
		2)
		stty erase ^H && read -p "请设置密码(默认:pangbobi):" pw
		[ -z "${pw}" ] && pw="pangbobi"
		;;
		3)
		start_menu_main
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-3]"
		sleep 2s
		reinstall_sys
		;;
	esac
	echo -e "\n${Info}您的密码是：${Red_font_prefix}${pw}${Font_color_suffix}"
	echo -e "${Info}请务必记录您的密码！然后任意键继续..."
	char=`get_char`
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
	stty erase ^H && read -p "请设置参数:" advanced
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
	stty erase ^H && read -p "请输入数字 [0-11](默认:0):" num
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
	stty erase ^H && read -p "请输入数字 [0-11](默认:3):" num
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
	stty erase ^H && read -p "请输入数字 [0-11](默认:3):" num
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
	stty erase ^H && read -p "请输入数字 [0-7](默认:2):" num
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
	add_firewall_single(){
		clear
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			stty erase ^H && read -p "请输入端口号[1-65535]：" port
		done
		add_firewall
		firewall_restart
	}
	delete_firewall_single(){
		clear
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			stty erase ^H && read -p "请输入端口号[1-65535]：" port
		done
		delete_firewall
		firewall_restart
	}
	delete_firewall_all(){
		echo -e "${Info}开始设置防火墙..."
		if [[ "${release}" == "centos" &&  "${version}" -ge "7" ]]; then
			firewall-cmd --permanent --zone=public --remove-port=1-65535/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --remove-port=1-65535/udp > /dev/null 2>&1
		else
			iptables -P INPUT ACCEPT
			iptables -F
			iptables -X
		fi
		add_firewall_base
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
	stty erase ^H && read -p "请输入数字 [1-6](默认:6):" num
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

#开始菜单
start_menu_main(){
	clear
	echo -e "
   超级VPN一键设置脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
	  -- 胖波比 --
	执行脚本：./sv.sh
   终止正在进行的操作：Ctrl+C
	  
—————————————VPN搭建——————————————
 ${Green_font_prefix}1.${Font_color_suffix} V2Ray安装管理
 ${Green_font_prefix}2.${Font_color_suffix} SSR安装管理
 ${Green_font_prefix}3.${Font_color_suffix} Trojan安装管理
 ${Green_font_prefix}4.${Font_color_suffix} BBR/Lotserver安装管理
—————————————控制面板—————————————
 ${Green_font_prefix}5.${Font_color_suffix} 安装宝塔面板
 ${Green_font_prefix}6.${Font_color_suffix} ZFAKA安装管理
 ${Green_font_prefix}7.${Font_color_suffix} SS-Panel安装管理
 ${Green_font_prefix}8.${Font_color_suffix} Kodexplorer安装管理
 ${Green_font_prefix}9.${Font_color_suffix} WordPress安装管理
 ${Green_font_prefix}10.${Font_color_suffix} Docker安装管理
———————————设置伪装(二选一)———————
 ${Green_font_prefix}11.${Font_color_suffix} Caddy安装管理
 ${Green_font_prefix}12.${Font_color_suffix} Nginx安装管理
—————————————系统设置—————————————
 ${Green_font_prefix}13.${Font_color_suffix} 设置SSH端口
 ${Green_font_prefix}14.${Font_color_suffix} 设置root密码
 ${Green_font_prefix}15.${Font_color_suffix} 系统性能测试
 ${Green_font_prefix}16.${Font_color_suffix} 重装VPS系统
 ${Green_font_prefix}17.${Font_color_suffix} 设置防火墙
—————————————脚本设置—————————————
 ${Green_font_prefix}18.${Font_color_suffix} 设置脚本自启
 ${Green_font_prefix}19.${Font_color_suffix} 关闭脚本自启
 ${Green_font_prefix}20.${Font_color_suffix} 退出脚本
——————————————————————————————————" && echo
	stty erase ^H && read -p "请输入数字 [1-20](默认:20):" num
	[ -z "${num}" ] && num=20
	case "$num" in
		1)
		manage_v2ray
		;;
		2)
		install_ssr
		;;
		3)
		manage_trojan
		;;
		4)
		install_bbr
		;;
		5)
		install_btpanel
		;;
		6)
		manage_zfaka
		;;
		7)
		manage_sspanel
		;;
		8)
		manage_kodexplorer
		;;
		9)
		manage_wordpress
		;;
		10)
		manage_docker
		;;
		11)
		install_caddy
		;;
		12)
		install_nginx
		;;
		13)
		set_ssh
		;;
		14)
		set_root
		;;
		15)
		test_sys
		;;
		16)
		reinstall_sys
		;;
		17)
		set_firewall
		;;
		18)
		if [[ `grep -c "./sv.sh" .bash_profile` -eq '0' ]]; then
			echo "./sv.sh" >> /root/.bash_profile
		fi
		;;
		19)
		sed -i "/sv.sh/d" .bash_profile
		;;
		20)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}:请输入正确数字 [1-20]"
		sleep 2s
		start_menu_main
		;;
	esac
	start_menu_main
}

check_sys
test ! -e /root/test/de || start_menu_main
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
if [[ "${release}" == "centos" ]]; then
	if [[ "${version}" -ge "7" ]]; then
		systemctl start firewalld
		systemctl enable firewalld
	else
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	fi
else
	iptables-save > /etc/iptables.up.rules
	ip6tables-save > /etc/ip6tables.up.rules
	echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
	chmod +x /etc/network/if-pre-up.d/iptables
fi
echo "export LANG=\"en_US.UTF-8\"" >> /root/.bash_profile
add_firewall_base
#是阿里云则卸载云盾
org=$(curl -s https://ipapi.co/org/)
if [[ "${org}" =~ "Alibaba" ]]; then
	wget http://update.aegis.aliyun.com/download/uninstall.sh && chmod +x uninstall.sh && ./uninstall.sh
	wget http://update.aegis.aliyun.com/download/quartz_uninstall.sh && chmod +x quartz_uninstall.sh && ./quartz_uninstall.sh
	pkill aliyun-service
	rm -fr /etc/init.d/agentwatch /usr/sbin/aliyun-service /usr/local/aegis*
	rm -f uninstall.sh quartz_uninstall.sh
	iptables -I INPUT -s 140.205.201.0/28 -j DROP
	iptables -I INPUT -s 140.205.201.16/29 -j DROP
	iptables -I INPUT -s 140.205.201.32/28 -j DROP
	iptables -I INPUT -s 140.205.225.192/29 -j DROP
	iptables -I INPUT -s 140.205.225.200/30 -j DROP
	iptables -I INPUT -s 140.205.225.184/29 -j DROP
	iptables -I INPUT -s 140.205.225.183/32 -j DROP
	iptables -I INPUT -s 140.205.225.206/32 -j DROP
	iptables -I INPUT -s 140.205.225.205/32 -j DROP
	iptables -I INPUT -s 140.205.225.195/32 -j DROP
	iptables -I INPUT -s 140.205.225.204/32 -j DROP
fi
firewall_restart
echo -e "${Info}首次运行此脚本会安装依赖环境,按任意键继续..."
char=`get_char`
if [[ ${release} == "centos" ]]; then
	yum -y install jq
	yum -y install epel-release git bash curl wget zip unzip gcc python36 openssl openssl-devel automake autoconf make libtool ca-certificates python3-pip subversion vim
else
	apt-get --fix-broken install
	apt-get -y install git bash curl wget zip unzip gcc jq python python-setuptools openssl libssl-dev automake autoconf make libtool ca-certificates python3-pip subversion vim
fi
mkdir -p /root/test && touch /root/test/de
country=$(curl -s https://ipapi.co/country/)
sed -i "s#${myinfo}#${country}-${myinfo}#g" sv.sh
exec ./sv.sh