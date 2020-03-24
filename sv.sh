#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
stty erase ^H

#版本
sh_ver="7.4.4"

#颜色信息
green_font(){
	echo -e "\033[32m\033[01m$1\033[0m\033[37m\033[01m$2\033[0m"
}
red_font(){
	echo -e "\033[31m\033[01m$1\033[0m"
}
white_font(){
	echo -e "\033[37m\033[01m$1\033[0m"
}
yello_font(){
	echo -e "\033[33m\033[01m$1\033[0m"
}
Info=`green_font [信息]` && Error=`red_font [错误]` && Tip=`yello_font [注意]`

#check root
[ $(id -u) != '0' ] && { echo -e "${Error}您必须以root用户运行此脚本"; exit 1; }

######系统检测组件######
check_sys(){
	#检查系统
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
	#检查系统安装命令
	if [[ ${release} == "centos" ]]; then
		PM='yum'
	else
		PM='apt'
	fi
	bit=`uname -m`
	myinfo="企鹅号:3450633979"
}
#获取IP
get_ip(){
	IP=$(curl -s ipinfo.io/ip)
	[ -z ${IP} ] && IP=$(curl -s http://api.ipify.org)
	[ -z ${IP} ] && IP=$(curl -s ipv4.icanhazip.com)
	[ -z ${IP} ] && IP=$(curl -s ipv6.icanhazip.com)
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
	if [[ ${release} == 'centos' ]]; then
		if [[ ${version} -ge '7' ]]; then
			firewall-cmd --reload
		else
			service iptables save
			if [ -e /root/test/ipv6 ]; then
				service ip6tables save
			fi
		fi
	else
		iptables-save > /etc/iptables.up.rules
		if [ -e /root/test/ipv6 ]; then
			ip6tables-save > /etc/ip6tables.up.rules
		fi
	fi
	echo -e "${Info}防火墙设置完成！"
}
add_firewall(){
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		if [[ -z $(firewall-cmd --zone=public --list-ports |grep -w ${port}/tcp) ]]; then
			firewall-cmd --zone=public --add-port=${port}/tcp --add-port=${port}/udp --permanent >/dev/null 2>&1
		fi
	else
		if [[ -z $(iptables -nvL INPUT |grep :|awk -F ':' '{print $2}' |grep -w ${port}) ]]; then
			iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
			iptables -I INPUT -p udp --dport ${port} -j ACCEPT
			iptables -I OUTPUT -p tcp --sport ${port} -j ACCEPT
			iptables -I OUTPUT -p udp --sport ${port} -j ACCEPT
			if [ -e /root/test/ipv6 ]; then
				ip6tables -I INPUT -p tcp --dport ${port} -j ACCEPT
				ip6tables -I INPUT -p udp --dport ${port} -j ACCEPT
				ip6tables -I OUTPUT -p tcp --sport ${port} -j ACCEPT
				ip6tables -I OUTPUT -p udp --sport ${port} -j ACCEPT
			fi
		fi
	fi
}
add_firewall_base(){
	ssh_port=$(cat /etc/ssh/sshd_config |grep 'Port ' |awk -F ' ' '{print $2}')
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		if [[ -z $(firewall-cmd --zone=public --list-ports |grep -w ${ssh_port}/tcp) ]]; then
			firewall-cmd --zone=public --add-port=${ssh_port}/tcp --add-port=${ssh_port}/udp --permanent >/dev/null 2>&1
		fi
	else
		iptables_base(){
			$1 -A INPUT -p icmp --icmp-type any -j ACCEPT
			$1 -A INPUT -s localhost -d localhost -j ACCEPT
			$1 -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			$1 -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			$1 -P INPUT DROP
			$1 -I INPUT -p tcp --dport ${ssh_port} -j ACCEPT
			$1 -I INPUT -p udp --dport ${ssh_port} -j ACCEPT
		}
		iptables_base iptables
		if [ -e /root/test/ipv6 ]; then
			iptables_base ip6tables
		fi
	fi
}
add_firewall_all(){
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		firewall-cmd --zone=public --add-port=1-65535/tcp --add-port=1-65535/udp --permanent >/dev/null 2>&1
	else
		iptables -I INPUT -p tcp --dport 1:65535 -j ACCEPT
		iptables -I INPUT -p udp --dport 1:65535 -j ACCEPT
		if [ -e /root/test/ipv6 ]; then
			ip6tables -I INPUT -p tcp --dport 1:65535 -j ACCEPT
			ip6tables -I INPUT -p udp --dport 1:65535 -j ACCEPT
		fi
	fi
	firewall_restart
}
delete_firewall(){
	if [[ ${release} == 'centos' &&  ${version} -ge '7' ]]; then
		if [[ -n $(firewall-cmd --zone=public --list-ports |grep -w ${port}/tcp) ]]; then
			firewall-cmd --zone=public --remove-port=${port}/tcp --remove-port=${port}/udp --permanent >/dev/null 2>&1
		fi
	else
		if [[ -n $(iptables -nvL INPUT |grep :|awk -F ':' '{print $2}' |grep -w ${port}) ]]; then
			clean_iptables(){
				TYPE=$1
				LINE_ARRAY=($(iptables -nvL $TYPE --line-number|grep :|grep -w ${port}|awk -F ':' '{print $2"  " $1}'|awk '{print $2" "$1}'|awk -F ' ' '{print $1}'))
				length=${#LINE_ARRAY[@]}
				for(( i = 0; i < ${length}; i++ ))
				do
					LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$i]
					iptables -D $TYPE ${LINE_ARRAY[$i]}
				done
			}
			clean_iptables INPUT
			clean_iptables OUTPUT
			if [ -e /root/test/ipv6 ]; then
				clean_ip6tables(){
					TYPE=$1
					LINE_ARRAY=($(ip6tables -nvL $TYPE --line-number|grep :|grep -w ${port}|awk '{printf "%s %s\n",$1,$NF}'|awk -F ' ' '{print $1}'))
					length=${#LINE_ARRAY[@]}
					for(( i = 0; i < ${length}; i++ ))
					do
						LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$i]
						ip6tables -D $TYPE ${LINE_ARRAY[$i]}
					done
				}
				clean_ip6tables INPUT
				clean_ip6tables OUTPUT
			fi
		fi
	fi
}
#安装Docker
install_docker(){
	#安装docker
	if type docker >/dev/null 2>&1; then
		echo -e "${Info}您的系统已安装docker"
	else
		${PM} --fix-broken install
		echo -e "${Info}开始安装docker..."
		docker version > /dev/null || curl -fsSL get.docker.com | bash
		service docker restart
		systemctl enable docker 
	fi
	#安装Docker环境
	if type docker-compose >/dev/null 2>&1; then
		echo -e "${Info}系统已存在Docker环境"
	else
		echo -e "${Info}正在安装Docker环境..."
		curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
		chmod +x /usr/local/bin/docker-compose
	fi
}
#检查VPN运行状态
check_vpn_status(){
	command=$1 && TYPE=$2 && message=$3
	if [[ `${command}|grep Active` =~ 'running' ]]; then
		green_font "${TYPE}${message}成功..."
		sleep 2s
	else
		red_font "${TYPE}${message}失败！q 键退出..."
		${command}
	fi
}

#安装V2ray
manage_v2ray(){
	check_pip(){
		if [[ ! `pip -V|awk -F '(' '{print $2}'` =~ 'python 3' ]]; then
			pip_array=($(whereis pip|awk -F 'pip: ' '{print $2}'))
			for node in ${pip_array[@]};
			do
				if [[ ! $node =~ [0-9] ]]; then
					rm -f $node
				fi
				if [[ $node =~ '3.' ]]; then
					pip_path=$node
				fi
			done
			if [[ -n $pip_path ]]; then
				ln -s $pip_path /usr/local/bin/pip
				ln -s $pip_path /usr/bin/pip
				pip install --upgrade pip
			else
				unset CMD
				py_array=(python3.1 python3.2 python3.3 python3.4 python3.5 python3.6 python3.7 python3.8 python3.9)
				for node in ${py_array[@]};
				do
					if type $node >/dev/null 2>&1; then
						CMD=$node
					fi
				done
				if [[ -n $CMD ]]; then
					wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py
					$CMD get-pip.py
					rm -f get-pip.py
				else
					zlib_ver='1.2.11'
					wget "http://www.zlib.net/zlib-${zlib_ver}.tar.gz"
					tar -xvzf zlib-${zlib_ver}.tar.gz
					cd zlib-${zlib_ver}
					./configure
					make && make install && cd /root
					rm -rf zlib*
					py_ver='3.7.7'
					wget "https://www.python.org/ftp/python/${py_ver}/Python-${py_ver}.tgz"
					tar xvf Python-${py_ver}.tgz
					cd Python-${py_ver}
					./configure --prefix=/usr/local
					make && make install && cd /root
					rm -rf Python*
				fi
				check_pip
			fi
		fi
	}
	v2ray_info(){
		sed -i 's#ps": ".*"#ps": "'${myinfo}'"#g' $(cat /root/test/v2raypath)
		clear
		if [[ $1 == '1' ]]; then
			i=$[${i}+1]
			start=$(v2ray info |grep -Fxn ${i}. |awk -F: '{print $1}')
			if [[ $i == "${num}" ]]; then
				end=$(v2ray info |grep -wn Tip: |awk -F: '{print $1}')
			else
				end=$(v2ray info |grep -Fxn $[${i}+1]. |awk -F: '{print $1}')
			fi
			v2ray info | sed -n "${start},$[${end}-1]p"
		else
			v2ray info
		fi
	}
	change_uuid(){
		clear
		num=$(jq ".inbounds | length" /etc/v2ray/config.json)
		echo -e "\n${Info}当前用户总数：$(red_font $num)\n"
		unset i
		until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
		do
			read -p "请输入要修改的用户序号[1-${num}]：" i
		done
		i=$[${i}-1]
		uuid1=$(jq -r ".inbounds[${i}].settings.clients[0].id" /etc/v2ray/config.json)
		uuid2=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#${uuid1}#${uuid2}#g" /etc/v2ray/config.json
		clear
		v2ray restart
		v2ray_info '1'
		white_font '      ————胖波比————'
		yello_font '——————————————————————————'
		green_font ' 1.' '  继续更改UUID'
		yello_font '——————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 2.' '  返回V2Ray用户管理页'
		green_font ' 3.' '  退出脚本'
		yello_font "——————————————————————————\n"
		read -p "请输入数字[0-3](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			0)
			start_menu_main
			;;
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
			echo -e "${Error}请输入正确数字 [0-3]"
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
			if [[ ${protocol} != "ws" ]]; then
				cat /etc/v2ray/config.json | jq "del(.inbounds[${i}].streamSettings.${protocol}Settings[])" | jq '.inbounds['${i}'].streamSettings.network="ws"' > /root/test/temp.json
				temppath="/$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)/"
				cat /root/test/temp.json | jq '.inbounds['${i}'].streamSettings.wsSettings.path="'${temppath}'"' | jq '.inbounds['${i}'].streamSettings.wsSettings.headers.Host="www.bilibili.com"' > /etc/v2ray/config.json
			fi
		done
		v2ray restart
		clear
		v2ray_info '2'
		echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
		char=`get_char`
		manage_v2ray_user
	}
	set_tfo(){
		set_tfo_single(){
			v2ray tfo
			v2ray_info '2'
			white_font "\n	————胖波比————\n"
			yello_font '——————————————————————————'
			green_font ' 1.' '  继续设置TcpFastOpen'
			yello_font '——————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回V2Ray用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "——————————————————————————\n"
			read -p "请输入数字[1-3](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [1-3]"
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
			v2ray_info '2'
			echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
			char=`get_char`
			manage_v2ray_user
		}
		set_tfo_menu(){
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '——————————————————————————'
			green_font ' 1.' '  逐个设置'
			green_font ' 2.' '  全部设置'
			yello_font '——————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回V2Ray用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "——————————————————————————\n"
			read -p "请输入数字[0-4](默认:3)：" num
			[ -z "${num}" ] && num=3
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
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
			i=$(jq ".inbounds | length" /etc/v2ray/config.json)
			echo -e "\n${Info}当前用户总数：$(red_font ${i})\n"
			v2ray add
			firewall_restart
			num=$[${i}+1]
			v2ray_info '1'
			white_font '     ————胖波比————'
			yello_font '——————————————————————————'
			green_font ' 1.' '  继续添加用户'
			yello_font '——————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回V2Ray用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "——————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_v2ray_user
				;;
			esac
		}
		add_v2ray_multi(){
			clear
			echo -e "\n${Info}当前用户总数：$(red_font $(jq ".inbounds | length" /etc/v2ray/config.json))\n"
			read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			for(( i = 0; i < ${num}; i++ ))
			do
				echo | v2ray add
			done
			firewall_restart
			v2ray_info '2'
			echo -e "\n${Info}按任意键返回V2Ray用户管理页..."
			char=`get_char`
			manage_v2ray_user
		}
		add_v2ray_menu(){
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '——————————————————————————'
			green_font ' 1.' '  逐个添加'
			green_font ' 2.' '  批量添加'
			yello_font '——————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回V2Ray用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "——————————————————————————\n"
			read -p "请输入数字[0-4](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				add_v2ray_menu
				;;
			esac
		}
		add_v2ray_menu
	}
	manage_v2ray_user(){
		clear
		white_font "\n   V2Ray用户管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	  -- 胖波比 --'
		white_font "手动修改配置文件：vi /etc/v2ray/config.json\n"
		yello_font '——————————————————————————'
		green_font ' 1.' '  更改UUID'
		green_font ' 2.' '  查看用户链接'
		green_font ' 3.' '  流量统计'
		yello_font '——————————————————————————'
		green_font ' 4.' '  添加用户'
		green_font ' 5.' '  删除用户'
		green_font ' 6.' '  更改端口'
		green_font ' 7.' '  更改协议'
		yello_font '——————————————————————————'
		green_font ' 8.' '  设置TcpFastOpen'
		green_font ' 9.' '  设置WebSocket传输'
		green_font ' 10.' ' 原版管理窗口'
		green_font ' 11.' ' 设置CDN'
		green_font ' 12.' ' 设置TLS'
		yello_font '——————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 13.' ' 返回上页'
		green_font ' 14.' ' 退出脚本'
		yello_font "——————————————————————————\n"
		read -p "请输入数字[0-14](默认:1)：" num
		[ -z "${num}" ] && num=1
		clear
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			change_uuid
			;;
			2)
			v2ray_info '2'
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
			change_ws
			;;
			10)
			v2ray
			;;
			11)
			v2ray cdn
			;;
			12)
			v2ray tls
			;;
			13)
			start_menu_v2ray
			;;
			14)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-14]"
			sleep 2s
			manage_v2ray_user
			;;
		esac
		manage_v2ray_user
	}
	install_v2ray(){
		check_pip
		bash <(curl -sL $v2ray_url) --zh
		find /usr/local/lib/python*/*-packages/v2ray_util -name group.py > /root/test/v2raypath
		echo -e "${Info}任意键继续..."
		char=`get_char`
		manage_v2ray_user
	}
	install_v2ray_repair(){
		check_pip
		bash <(curl -sL $v2ray_url) -k
		echo -e "${Info}已保留配置更新，任意键继续..."
		char=`get_char`
	}
	start_menu_v2ray(){
		v2ray_url='https://multi.netlify.com/v2ray.sh'
		clear
		white_font "\n V2Ray一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '——————————————————————————'
		green_font ' 1.' '  管理V2Ray用户'
		yello_font '——————————————————————————'
		green_font ' 2.' '  安装V2Ray'
		green_font ' 3.' '  修复V2Ray'
		green_font ' 4.' '  卸载V2Ray'
		yello_font '——————————————————————————'
		green_font ' 5.' '  重启V2Ray'
		green_font ' 6.' '  关闭V2Ray'
		green_font ' 7.' '  启动V2Ray'
		green_font ' 8.' '  查看V2Ray状态'
		yello_font '——————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 9.' '  退出脚本'
		yello_font "——————————————————————————\n"
		read -p "请输入数字[1-10](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
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
			bash <(curl -sL $v2ray_url) --remove
			echo -e "${Info}已卸载，任意键继续..."
			char=`get_char`
			;;
			5)
			v2ray restart && sleep 2s
			;;
			6)
			v2ray stop && sleep 2s
			;;
			7)
			v2ray start && sleep 2s
			;;
			8)
			check_vpn_status 'service v2ray status' 'V2Ray' '运行'
			;;
			9)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-9]"
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
	libsodium_file="libsodium-1.0.17"
	libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"
	shadowsocks_r_file="shadowsocksr-3.2.2"
	shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"

	#Current folder
	cur_dir=`pwd`
	red='\033[0;31m' && green='\033[0;32m' && plain='\033[0m'
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
			dport=$(shuf -i 1000-9999 -n1)
			echo -e "${Info}请设置ShadowsocksR端口[1000-9999]："
			read -p "(默认随机端口:${dport})：" port
			[ -z "${port}" ] && port=${dport}
			expr ${port} + 1 &>/dev/null
			if [ $? -eq 0 ]; then
				if [ ${port} -ge 1000 ] && [ ${port} -le 9999 ] && [ -z $(lsof -i:${port}) ]; then
					echo
					echo "---------------------------"
					echo "port = ${port}"
					echo "---------------------------"
					echo
					break
				fi
			fi
			echo -e "[${red}Error${plain}] Please enter a correct number [1000-9999]"
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
			echo -e "Congratulations, ShadowsocksR server install completed!"
			echo -e "Your Server IP        : \033[41;37m $(get_ip) \033[0m"
			echo -e "Your Server Port      : \033[41;37m ${port} \033[0m"
			echo -e "Your Password         : \033[41;37m ${password} \033[0m"
			echo -e "Your Protocol         : \033[41;37m ${protocol} \033[0m"
			echo -e "Your obfs             : \033[41;37m ${obfs} \033[0m"
			echo -e "Your Encryption Method: \033[41;37m ${method} \033[0m"
			white_font "\n	Enjoy it!\n	请记录你的SSR信息!\n"
			yello_font '——————————胖波比—————————'
			green_font ' 1.' '  进入SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-2](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				manage_ssr
				;;
				2)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-2]"
				sleep 2s
				start_menu_main
				;;
			esac
		else
			echo -e "${Error}ShadowsocksR install failed, please Email to Teddysun <i@teddysun.com> and contact"
			install_cleanup
			exit 1
		fi
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
	#生成SSR链接
	set_ssrurl(){
		SSRPWDbase64=$(urlsafe_base64 "${password}")
		SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
		SSRurl="ssr://${SSRbase64}"
		service shadowsocks restart
		clear
		#输出链接
		echo -e "\n${Info}端口：$(red_font $port)   密码：$(red_font $password)"
		echo -e "${Info}SSR链接：$(red_font $SSRurl)\n"
	}
	#查看所有链接
	view_ssrurl(){
		clear
		jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
		cat /root/test/ppj | while read line; do
			port=`echo $line|awk -F ':' '{print $1}'`
			password=`echo $line|awk -F ':' '{print $2}'`
			echo -e "端口：$(red_font $port)   密码：$(red_font $password)"
			SSRPWDbase64=$(urlsafe_base64 "${password}")
			SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
			SSRurl="ssr://${SSRbase64}"
			echo -e "SSR链接 ：$(red_font $SSRurl)\n"
		done
		echo -e "服务器IP    ：$(red_font $(get_ip))"
		echo -e "加密方式    ：$(red_font $method)"
		echo -e "协议        ：$(red_font $protocol)"
		echo -e "混淆        ：$(red_font $obfs)"
		echo -e "当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
		if [[ $1 == "1" ]]; then
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
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && ${port} -ge '1000' && ${port} -le '9999' && ${port} -ne '1080' ]]
			do
				read -p "请输入要改密的端口号：" port
			done
			password1=$(jq -r '.port_password."'${port}'"' /etc/shadowsocks.json)
			password=$(openssl rand -base64 6)
			et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
			sed -i "${et}s#${password1}#${password}#g" /etc/shadowsocks.json
			#调用生成链接的函数
			set_ssrurl
			white_font "\n	 ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  继续更改密码'
			green_font ' 2.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-3](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				change_pw_menu
				;;
			esac
		}
		change_pw_multi(){
			clear
			jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
			cat /root/test/ppj | while read line; do
				port=`echo $line|awk -F ':' '{print $1}'`
				password1=`echo $line|awk -F ':' '{print $2}'`
				password=$(openssl rand -base64 6)
				et=$(sed -n -e "/${port}/=" /etc/shadowsocks.json)
				sed -i "${et}s#${password1}#${password}#g" /etc/shadowsocks.json
				echo -e "端口：$(red_font $port)   密码：$(red_font $password)"
				SSRPWDbase64=$(urlsafe_base64 "${password}")
				SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
				SSRurl="ssr://${SSRbase64}"
				echo -e "SSR链接 : $(red_font $SSRurl)\n"
			done
			echo -e "服务器IP    ：$(red_font $(get_ip))"
			echo -e "加密方式    ：$(red_font $method)"
			echo -e "协议        ：$(red_font $protocol)"
			echo -e "混淆        ：$(red_font $obfs)"
			echo -e "当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			echo -e "${Info}按任意键回到SSR用户管理页..."
			char=`get_char`
			manage_ssr
		}
		change_pw_menu(){
			clear
			white_font "\n    ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  逐个修改'
			green_font ' 2.' '  全部修改'
			green_font ' 3.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
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
			port=$(shuf -i 1000-9999 -n1)
			until [[ -z $(lsof -i:${port}) && ${port} -ne '1080' ]]
			do
				port=$(shuf -i 1000-9999 -n1)
			done
			add_firewall
			firewall_restart
			password=$(openssl rand -base64 6)
			cat /etc/shadowsocks.json | jq '.port_password."'${port}'"="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /etc/shadowsocks.json
			set_ssrurl
			white_font "     ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  继续添加用户'
			green_font ' 2.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_ssr
				;;
			esac
		}
		#批量添加
		add_user_multi(){
			clear
			echo -e "\n${Info}当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
			read -p "请输入要添加的用户个数(默认:1)：" num
			[ -z "${num}" ] && num=1
			unset port
			for(( i = 0; i < ${num}; i++ ))
			do
				port=$(shuf -i 1000-9999 -n1)
				until [[ -z $(lsof -i:${port}) && ${port} -ne '1080' ]]
				do
					port=$(shuf -i 1000-9999 -n1)
				done
				add_firewall
				password=$(openssl rand -base64 6)
				cat /etc/shadowsocks.json | jq '.port_password."'${port}'"="'${password}'"' > /root/test/temp.json
				cp /root/test/temp.json /etc/shadowsocks.json
				SSRPWDbase64=$(urlsafe_base64 "${password}")
				SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
				SSRurl="ssr://${SSRbase64}"
				echo -e "${Info}端口：$(red_font $port)   密码：$(red_font $password)"
				echo -e "${Info}SSR链接：$(red_font $SSRurl)\n"
			done
			firewall_restart
			service shadowsocks restart
			echo -e "${Info}SSR已重启！"
			echo -e "${Info}当前用户总数：$(red_font $(jq '.port_password | length' /etc/shadowsocks.json))\n"
			echo -e "${Info}按任意键返回SSR用户管理页..."
			char=`get_char`
			manage_ssr
		}
		#添加用户菜单
		add_user_menu(){
			clear
			white_font "\n     ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  逐个添加'
			green_font ' 2.' '  批量添加'
			green_font ' 3.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-4](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
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
			until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && ${port} -ge '1000' && ${port} -le '9999' && ${port} -ne '1080' ]]
			do
				read -p "请输入要删除的端口：" port
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
			white_font "\n    ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  继续删除用户'
			green_font ' 2.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				manage_ssr
				;;
			esac
		}
		delete_user_multi(){
			clear
			jq '.port_password' /etc/shadowsocks.json |sed '1d' |sed '$d' |sed 's#"##g' |sed 's# ##g' |sed 's#,##g' > /root/test/ppj
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
			white_font "\n    ————胖波比————\n"
			yello_font '—————————————————————————'
			green_font ' 1.' '  逐个删除'
			green_font ' 2.' '  全部删除'
			green_font ' 3.' '  返回SSR用户管理页'
			yello_font '—————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
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
		jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
		jq '.port_password' /etc/shadowsocks.json
		echo -e "${Info}以上是配置文件的内容\n"
		unset port
		until [[ `grep -c "${port}" /etc/shadowsocks.json` -eq '1' && ${port} -ge '1000' && ${port} -le '9999' && ${port} -ne '1080' ]]
		do
			read -p "请输入要修改的端口号：" port
		done
		password=$(cat /root/test/ppj | grep "${port}:" | awk -F ':' '{print $2}')
		delete_firewall
		port1=${port}
		port=$(shuf -i 1000-9999 -n1)
		until [[ -z $(lsof -i:${port}) && ${port} -ne '1080' ]]
		do
			port=$(shuf -i 1000-9999 -n1)
		done
		add_firewall
		firewall_restart
		sed -i "s/${port1}/${port}/g"  /etc/shadowsocks.json
		set_ssrurl
		white_font "     ————胖波比————\n"
		yello_font '—————————————————————————'
		green_font ' 1.' '  继续更改端口'
		green_font ' 2.' '  返回SSR用户管理页'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-3](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
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
			echo -e "${Error}请输入正确数字 [0-3]"
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
		view_ssrurl '1'
	}
	#更改协议
	change_protocol(){
		protocol1=$(jq -r '.protocol' /etc/shadowsocks.json)
		set_protocol
		sed -i "s/${protocol1}/${protocol}/g"  /etc/shadowsocks.json
		SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
		view_ssrurl '1'
	}
	#更改混淆
	change_obfs(){
		obfs1=$(jq -r '.obfs' /etc/shadowsocks.json)
		set_obfs
		sed -i "s/${obfs1}/${obfs}/g"  /etc/shadowsocks.json
		SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
		view_ssrurl '1'
	}
	
	#管理SSR配置
	manage_ssr(){
		clear
		get_info
		white_font "\n   SSR用户管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	  -- 胖波比 --'
		white_font "手动修改配置文件：vi /etc/shadowsocks.json\n"
		yello_font '———————SSR用户管理———————'
		green_font ' 1.' '  更改密码'
		green_font ' 2.' '  查看用户链接'
		yello_font '—————————————————————————'
		green_font ' 3.' '  添加用户'
		green_font ' 4.' '  删除用户'
		yello_font '—————————————————————————'
		green_font ' 5.' '  更改端口'
		green_font ' 6.' '  更改加密'
		green_font ' 7.' '  更改协议'
		green_font ' 8.' '  更改混淆'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 9.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-9](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			change_pw
			;;
			2)
			view_ssrurl '2'
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-9]"
			sleep 2s
			manage_ssr
			;;
		esac
	}
	
	# Initialization step
	start_menu_ssr(){
		clear
		white_font "\n SSR一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	 -- 胖波比 --\n"
		yello_font '—————————SSR安装—————————'
		green_font ' 1.' '  管理SSR用户'
		yello_font '—————————————————————————'
		green_font ' 2.' '  安装SSR'
		green_font ' 3.' '  卸载SSR'
		yello_font '—————————————————————————'
		green_font ' 4.' '  重启SSR'
		green_font ' 5.' '  关闭SSR'
		green_font ' 6.' '  启动SSR'
		green_font ' 7.' '  查看SSR状态'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			manage_ssr
			;;
			2)
			install_shadowsocksr
			;;
			3)
			uninstall_shadowsocksr
			;;
			4)
			service shadowsocks restart
			check_vpn_status 'service shadowsocks status' 'SSR' '重启'
			;;
			5)
			service shadowsocks stop
			;;
			6)
			service shadowsocks start
			check_vpn_status 'service shadowsocks status' 'SSR' '启动'
			;;
			7)
			check_vpn_status 'service shadowsocks status' 'SSR' '运行'
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
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
		letsencrypt_ip(){
			clear && cd /root/certificate
			sed -i 's#verify": true#verify": false#g' /root/certificate/config.json
			sed -i 's#hostname": true#hostname": false#g' /root/certificate/config.json
			ydomain=$(get_ip)
			echo -e "${Info}即将生成证书,输入假信息即可,任意键继续..."
			char=`get_char`
			openssl req -newkey rsa:2048 -nodes -keyout private.key -x509 -days 3650 -out fullchain.cer
		}
		letsencrypt_enc(){
			clear && cd /root
			if [ ! -e /root/test/acme ]; then
				curl https://raw.githubusercontent.com/Neilpang/acme.sh/master/acme.sh | INSTALLONLINE=1 sh
				/root/.acme.sh/acme.sh --upgrade --auto-upgrade
				touch /root/test/acme
			fi
			read -p "请输入已解析成功的域名：" ydomain
			if [[ -z $(lsof -i:80) ]]; then
				port=80 && add_firewall && firewall_restart
				/root/.acme.sh/acme.sh --issue -d ${ydomain} --standalone
			elif [[ -z $(lsof -i:443) ]]; then
				/root/.acme.sh/acme.sh --issue -d ${ydomain} --alpn
			else
				port=80 && add_firewall && firewall_restart
				command_array=($(lsof -i:80|sed '1d'|awk '{print $1}'|uniq))
				length=${#command_array[@]}
				for(( i = 0; i < ${length}; i++ ))
				do
					service ${command_array[$i]} stop
				done
				/root/.acme.sh/acme.sh --issue -d ${ydomain} --standalone
				for(( i = 0; i < ${length}; i++ ))
				do
					service ${command_array[$i]} restart
				done
			fi
			/root/.acme.sh/acme.sh --installcert -d ${ydomain} --fullchain-file /root/certificate/fullchain.cer --key-file /root/certificate/private.key
		}
		clear
		white_font "\n   Trojan证书管理脚本"
		white_font "	  -- 胖波比 --\n"
		yello_font '————————Trojan用户管理————————'
		green_font ' 1.' '  使用IP自签发证书'
		green_font ' 2.' '  使用acme.sh域名证书'
		yello_font '——————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  返回上页'
		green_font ' 4.' '  退出脚本'
		yello_font "——————————————————————————————\n"
		read -p "请输入数字[0-4](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			letsencrypt_ip
			;;
			2)
			letsencrypt_enc
			;;
			3)
			start_menu_trojan
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
			sleep 2s
			choose_letsencrypt
			;;
		esac
	}
	install_trojan(){
		if [ ! -e /root/test/trojan ]; then
			port=443
			until [[ -z $(lsof -i:${port}) ]]
			do
				port=$[${port}+1]
			done
			add_firewall
			firewall_restart
			mkdir -p /root/certificate
			echo $port > /root/test/trojan
		fi
		cd /usr/local
		VERSION=1.14.1
		DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v${VERSION}/trojan-${VERSION}-linux-amd64.tar.xz"
		wget --no-check-certificate "${DOWNLOADURL}"
		tar xf "trojan-$VERSION-linux-amd64.tar.xz"
		rm -f "trojan-$VERSION-linux-amd64.tar.xz"
		cd trojan
		chmod -R 755 /usr/local/trojan
		mv config.json /etc/trojan.json
		sed -i 's#local_port": 443#local_port": '${port}'#g' /etc/trojan.json
		password=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#password1#${password}#g" /etc/trojan.json
		password=$(cat /proc/sys/kernel/random/uuid)
		sed -i "s#password2#${password}#g" /etc/trojan.json
		sed -i 's#open": false#open": true#g' /etc/trojan.json
		cp examples/client.json-example /root/certificate/config.json
		sed -i 's#remote_port": 443#remote_port": '${port}'#g' /root/certificate/config.json
		sed -i 's#open": false#open": true#g' /root/certificate/config.json
		choose_letsencrypt
		cd /usr/local/trojan
		sed -i "s#/path/to/certificate.crt#/root/certificate/fullchain.cer#g" /etc/trojan.json
		sed -i "s#/path/to/private.key#/root/certificate/private.key#g" /etc/trojan.json
		sed -i "s#example.com#${ydomain}#g" /root/certificate/config.json
		sed -i 's#cert": "#cert": "fullchain.cer#g' /root/certificate/config.json
		sed -i "s#sni\": \"#sni\": \"${ydomain}#g" /root/certificate/config.json
		echo ${ydomain} >> /root/test/trojan
		base64 -d <<< W1VuaXRdDQpBZnRlcj1uZXR3b3JrLnRhcmdldCANCg0KW1NlcnZpY2VdDQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC90cm9qYW4vdHJvamFuIC1jIC9ldGMvdHJvamFuLmpzb24NClJlc3RhcnQ9YWx3YXlzDQoNCltJbnN0YWxsXQ0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQ=  > /etc/systemd/system/trojan.service
		systemctl daemon-reload
		systemctl enable trojan
		systemctl start trojan
		view_password '2'
		echo -e "${Tip}安装完成,如需设置伪装,请手动删除配置文件中监听的 ${port} 端口,否则会报错!!!"
		echo -e "${Tip}证书以及用户配置文件所在文件夹：/root/certificate"
		echo -e "${Info}任意键返回Trojan用户管理页..."
		char=`get_char`
		manage_user_trojan
	}
	uninstall_trojan(){
		systemctl stop trojan
		rm -rf /usr/local/trojan 
		rm -f /root/test/trojan /etc/trojan.json /etc/systemd/system/trojan.service
		systemctl daemon-reload
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
			view_password '2'
			white_font "       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  继续添加用户'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回Trojan用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
				sleep 2s
				add_user_trojan
				;;
			esac
		}
		add_trojan_multi(){
			clear
			read -p "请输入要添加的用户个数(默认:1)：" num
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
			view_password '1'
		}
		white_font "\n     ————胖波比————\n"
		yello_font '————————————————————————————'
		green_font ' 1.' '  逐个添加'
		green_font ' 2.' '  批量添加'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  返回Trojan用户管理页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-4](默认:2)：" num
		[ -z "${num}" ] && num=2
		case "$num" in
			0)
			start_menu_main
			;;
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
			echo -e "${Error}请输入正确数字 [0-4]"
			sleep 2s
			add_user_trojan
			;;
		esac
	}
	delete_user_trojan(){
		delete_trojan_single(){
			clear
			num=$(jq '.password | length' /etc/trojan.json)
			echo -e "\n${Info}当前用户总数：$(red_font $num)\n"
			unset i
			until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
			do
				read -p "请输入要删除的用户序号[1-${num}]：" i
			done
			i=$[${i}-1]
			cat /etc/trojan.json | jq 'del(.password['${i}'])' > /root/test/temp.json
			cp /root/test/temp.json /etc/trojan.json
			systemctl restart trojan
			view_password '2'
			white_font "       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  继续删除用户'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回Trojan用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-3](默认:2)：" num
			[ -z "${num}" ] && num=2
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
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
			echo -e "${Tip}Trojan至少要有一个用户，任意键添加用户..."
			char=`get_char`
			add_user_trojan
		}
		delete_trojan_menu(){
			clear
			white_font "\n       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  逐个删除'
			green_font ' 2.' '  全部删除'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回Trojan用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
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
			echo -e "\n${Info}当前用户总数：$(red_font $num)\n"
			unset i
			until [[ "${i}" -ge "1" && "${i}" -le "${num}" ]]
			do
				read -p "请输入要改密的用户序号 [1-${num}]:" i
			done
			i=$[${i}-1]
			password1=$(cat /etc/trojan.json | jq '.password['${i}']' | sed 's#"##g')
			password=$(cat /proc/sys/kernel/random/uuid)
			sed -i "s#${password1}#${password}#g" /etc/trojan.json
			systemctl restart trojan
			view_password '2'
			white_font "       ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  继续更改密码'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 2.' '  返回Trojan用户管理页'
			green_font ' 3.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-3](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-3]"
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
			view_password '1'
		}
		change_trojan_menu(){
			clear
			white_font "\n      ————胖波比————\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  逐个修改'
			green_font ' 2.' '  全部修改'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回Trojan用户管理页'
			green_font ' 4.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
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
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				change_trojan_menu
				;;
			esac
		}
		change_trojan_menu
	}
	view_password(){
		clear
		ipinfo=$(cat /root/test/trojan|sed -n '2p')
		port=$(cat /root/test/trojan|sed -n '1p')
		pw_trojan=$(jq '.password' /etc/trojan.json)
		length=$(jq '.password | length' /etc/trojan.json)
		tr_info="$(curl -s https://ipapi.co/country/)-%E6%88%91%E4%BB%AC%E7%88%B1%E4%B8%AD%E5%9B%BD"
		cat /root/certificate/config.json | jq 'del(.password[])' > /root/test/temp.json
		cp /root/test/temp.json /root/certificate/config.json
		for i in `seq 0 $[length-1]`
		do
			password=$(echo $pw_trojan | jq ".[$i]" | sed 's/"//g')
			#更新用户配置文件
			cat /root/certificate/config.json | jq '.password['${i}']="'${password}'"' > /root/test/temp.json
			cp /root/test/temp.json /root/certificate/config.json
			Trojanurl="trojan://${password}@${ipinfo}:${port}?allowInsecure=1&tfo=1#${tr_info}"
			echo -e "密码：$(red_font $password)"
			echo -e "Trojan链接：$(green_font $Trojanurl)\n"
		done
		echo -e "${Info}IP或域名：$(red_font ${ipinfo})"
		echo -e "${Info}端口：$(red_font ${port})"
		echo -e "${Info}当前用户总数：$(red_font ${length})\n"
		if [[ $1 == "1" ]]; then
			echo -e "${Info}任意键返回Trojan用户管理页..."
			char=`get_char`
			manage_user_trojan
		fi
	}
	manage_user_trojan(){
		clear
		white_font "\n   Trojan用户管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	    -- 胖波比 --'
		white_font "手动修改配置文件：vi /etc/trojan.json\n"
		yello_font '———————Trojan用户管理———————'
		green_font ' 1.' '  更改密码'
		green_font ' 2.' '  查看用户链接'
		yello_font '————————————————————————————'
		green_font ' 3.' '  添加用户'
		green_font ' 4.' '  删除用户'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 5.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-5](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			change_pw_trojan
			;;
			2)
			view_password '1'
			;;
			3)
			add_user_trojan
			;;
			4)
			delete_user_trojan
			;;
			5)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-5]"
			sleep 2s
			manage_user_trojan
			;;
		esac
	}
	start_menu_trojan(){
		clear
		white_font "\n Trojan一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "        -- 胖波比 --\n"
		yello_font '————————————————————————————'
		green_font ' 1.' '  管理Trojan用户'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装Trojan'
		green_font ' 3.' '  卸载Trojan'
		yello_font '————————————————————————————'
		green_font ' 4.' '  重启Trojan'
		green_font ' 5.' '  关闭Trojan'
		green_font ' 6.' '  启动Trojan'
		green_font ' 7.' '  查看Trojan状态'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			manage_user_trojan
			;;
			2)
			install_trojan
			;;
			3)
			uninstall_trojan
			;;
			4)
			systemctl restart trojan
			check_vpn_status 'systemctl status trojan' 'Trojan' '重启'
			;;
			5)
			systemctl stop trojan
			;;
			6)
			systemctl start trojan
			check_vpn_status 'systemctl status trojan' 'Trojan' '启动'
			;;
			7)
			check_vpn_status 'systemctl status trojan' 'Trojan' '运行'
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			start_menu_trojan
			;;
		esac
		start_menu_trojan
	}
	start_menu_trojan
}

#安装NaiveProxy
manage_naive(){
	install_dir='/opt/naiveproxy'
	install_naive(){
		mkdir -p ${install_dir}/caddy/html
		cd ${install_dir}/caddy/html
		wget https://raw.githubusercontent.com/AmuyangA/public/master/web.zip
		unzip web.zip && rm -f web.zip

		cd ..
		curl -OJ 'https://caddyserver.com/download/linux/amd64?plugins=http.forwardproxy&license=personal'
		tar xf ./caddy_*.tar.gz && rm -f ./caddy_*.tar.gz
		setcap cap_net_bind_service=+ep caddy
		base64 -d <<< eW91cl9kb21haW4NCnJvb3QgeW91cl93ZWJfcm9vdA0KdGxzIHlvdXJfZW1haWwNCmZvcndhcmRwcm94eSB7DQogIGJhc2ljYXV0aCB5b3VyX3VzZXIgeW91cl9wdw0KICBoaWRlX2lwDQogIGhpZGVfdmlhDQogIHByb2JlX3Jlc2lzdGFuY2Ugc2VjcmV0LmxvY2FsaG9zdA0KICB1cHN0cmVhbSBodHRwOi8vMTI3LjAuMC4xOnlvdXJfcG9ydA0KfQ== > Caddyfile

		clear && echo && read -p "请输入你的域名：" your_domain
		sed -i "s#your_domain#${your_domain}#g" Caddyfile
		sed -i "s#your_web_root#${install_dir}/caddy/html#g" Caddyfile
		yello_font '———————————————————————————————'
		green_font ' 1.' '  邮箱自动申请证书'
		green_font ' 2.' '  自定义已上传证书路径'
		yello_font '———————————————————————————————'
		unset TYPE && read -p "请输入数字[1-2](默认:1)：" TYPE
		case $TYPE in
			2)
			echo -e "${Info}请输入已上传$(green_font ${your_domain})证书和私钥的路径"
			domain_cert_path="${install_dir}/caddy/domain.crt ${install_dir}/caddy/domain.key"
			read -p "例如$(green_font '${domain_cert_path}')：" your_email
			;;
			*)
			read -p "请输入用来申请域名证书的可用邮箱(默认:hsxmuyang68@gmail.com)：" your_email
			[ -z $your_email ] && your_email='hsxmuyang68@gmail.com'
			;;
		esac
		sed -i "s#your_email#${your_email}#g" Caddyfile
		your_user=$(tr -dc 'A-Za-z' </dev/urandom | head -c8)
		sed -i "s#your_user#${your_user}#g" Caddyfile
		your_pw=$(tr -dc 'A-Za-z' </dev/urandom | head -c17)
		sed -i "s#your_pw#${your_pw}#g" Caddyfile
		
		your_port='8080'
		until [[ -z "$(lsof -i:${your_port})" ]]
		do
			your_port=$(shuf -i 8000-9000 -n1)
		done
		port=$your_port && add_firewall && echo $your_port > README.txt
		sed -i "s#your_port#${your_port}#g" Caddyfile
		hp_pt=80
		until [[ -z "$(lsof -i:${hp_pt})" ]]
		do
			hp_pt=$(shuf -i 85-110 -n1)
		done
		port=$hp_pt && add_firewall && echo $hp_pt >> README.txt
		hps_pt=443
		until [[ -z "$(lsof -i:${hps_pt})" ]]
		do
			hps_pt=$(shuf -i 450-500 -n1)
		done
		port=$hps_pt && add_firewall && echo $hps_pt >> README.txt
		firewall_restart
		
		if [[ $TYPE == '2' ]]; then
			echo 2 >> README.txt
			nohup ./caddy -host $your_domain -port $hps_pt |tee &
		else
			echo 1 >> README.txt
			if [[ $hp_pt != '80' ]]; then
				port=80 && add_firewall
				cmd_80=($(lsof -i:80|sed '1d'|awk '{print $1}'|uniq))
				length_80=${#cmd_80[@]}
				for(( i = 0; i < ${length_80}; i++ ))
				do
					service ${cmd_80[$i]} stop
				done
			fi
			if [[ $hps_pt != '443' ]]; then
				port=443 && add_firewall
				cmd_443=($(lsof -i:443|sed '1d'|awk '{print $1}'|uniq))
				length_443=${#cmd_443[@]}
				for(( i = 0; i < ${length_443}; i++ ))
				do
					service ${cmd_443[$i]} stop
				done
			fi
			firewall_restart
			clear && echo -e "${Tip}请耐心等待程序完成执行..."
			echo -e "${Tip}出现$(red_font 'Serving HTTP on port 80')之后，$(red_font 'Ctrl+C')进行下一步..."
			./caddy -agree -host $your_domain -email $your_email
			nohup ./caddy -agree -host $your_domain -http-port $hp_pt -https-port $hps_pt -email $your_email |tee &
			if [[ -n ${cmd_80[@]} ]]; then
				for(( i = 0; i < ${length_80}; i++ ))
				do
					service ${cmd_80[$i]} restart
				done
			fi
			if [[ -n ${cmd_443[@]} ]]; then
				for(( i = 0; i < ${length_443}; i++ ))
				do
					service ${cmd_443[$i]} restart
				done
			fi
		fi

		cd ..
		naive_ver='80.0.3987.87-3'
		DOWNLOADURL="https://github.com/klzgrad/naiveproxy/releases/download/v${naive_ver}/naiveproxy-v${naive_ver}-linux-x64.tar.xz"
		wget --no-check-certificate "${DOWNLOADURL}" && tar xf "naiveproxy-v${naive_ver}-linux-x64.tar.xz"
		mv "naiveproxy-v${naive_ver}-linux-x64" naive && rm -f naiveproxy-*tar.xz
		cd naive
		base64 -d <<< ew0KICAibGlzdGVuIjogImh0dHA6Ly8xMjcuMC4wLjE6eW91cl9wb3J0IiwNCiAgInBhZGRpbmciOiB0cnVlDQp9 > config.json
		sed -i "s#your_port#${your_port}#g" config.json
		nohup ./naive |tee &

		cd ${install_dir}/caddy/html
		base64 -d <<< ew0KICAibGlzdGVuIjogInNvY2tzOi8vMTI3LjAuMC4xOjEwODAiLA0KICAicHJveHkiOiAiaHR0cHM6Ly95b3VyX3VzZXI6eW91cl9wd0B5b3VyX2RvbWFpbiIsDQogICJwYWRkaW5nIjogdHJ1ZQ0KfQ== > config.json
		sed -i "s#your_user#${your_user}#g" config.json
		sed -i "s#your_pw#${your_pw}#g" config.json
		sed -i "s#your_domain#${your_domain}:${hps_pt}#g" config.json
		cd /root
		clear && echo -e "\n${Info}配置信息：$(red_font https://${your_user}:${your_pw}@${your_domain}:${hps_pt})"
		echo -e "${Info}客户端配置文件下载地址：$(green_font https://${your_domain}:${hps_pt}/config.json)"
		echo -e "\n${Info}任意键返回主页..."
		char=`get_char`
		start_menu_main
	}
	uninstall_naive(){
		port=$(cat ${install_dir}/caddy/README.txt|sed -n '1p')
		kill -9 $(lsof -i:${port}|grep naive|awk -F ' ' '{print $2}')
		delete_firewall
		port=$(cat ${install_dir}/caddy/README.txt|sed -n '3p')
		kill -9 $(lsof -i:${port}|grep caddy|awk -F ' ' '{print $2}')
		delete_firewall
		port=$(cat ${install_dir}/caddy/README.txt|sed -n '2p')
		delete_firewall && firewall_restart
		rm -rf $install_dir
	}
	stop_naive(){
		Caddy_port=$(cat ${install_dir}/caddy/README.txt|sed -n '3p')
		Navie_port=$(cat ${install_dir}/caddy/README.txt|sed -n '1p')
		if [[ -n $(lsof -i:${Caddy_port}) ]]; then
			kill -9 $(lsof -i:${Caddy_port}|grep caddy|awk -F ' ' '{print $2}')
		fi
		if [[ -n $(lsof -i:${Navie_port}) ]]; then
			kill -9 $(lsof -i:${Navie_port}|grep naive|awk -F ' ' '{print $2}')
		fi
	}
	start_naive(){
		cd ${install_dir}/caddy
		Caddy_port=$(cat README.txt|sed -n '3p')
		if [[ -z $(lsof -i:${Caddy_port}) ]]; then
			if [[ $(cat README.txt|sed -n '4p') == '2' ]]; then
				nohup ./caddy -host $(cat Caddyfile|sed -n '1p') -port $Caddy_port |tee &
			else
				nohup ./caddy -agree -host $(cat Caddyfile|sed -n '1p') -http-port $(cat README.txt|sed -n '2p') -https-port $Caddy_port -email $(cat Caddyfile|grep tls|awk '{print $2}') |tee &
			fi
		fi
		Navie_port=$(cat README.txt|sed -n '1p')
		if [[ -z $(lsof -i:${Navie_port}) ]]; then
			cd .. && cd naive
			nohup ./naive |tee &
		fi
		cd /root
	}

	clear
	if [[ -e "${install_dir}/caddy/README.txt" ]]; then
		yello_font "\n—————————————————————————"
		green_font ' 1.' '  卸载NaiveProxy'
		green_font ' 2.' '  重装NaiveProxy'
		green_font ' 3.' '  停止NaiveProxy'
		green_font ' 4.' '  启动NaiveProxy'
		green_font ' 5.' '  退出'
		yello_font '—————————————————————————'
		read -p "请输入数字[1-5](默认:1)：" num
		[ -z $num ] && num=1
		case $num in
			1)
			uninstall_naive
			;;
			2)
			uninstall_naive
			install_naive
			;;
			3)
			stop_naive
			;;
			4)
			start_naive
			;;
			*)
			exit 0
			;;
		esac
	else
		install_naive
	fi
}

#安装BBR或锐速
install_bbr(){
	github="raw.githubusercontent.com/chiakge/Linux-NetSpeed/master"
	#安装BBR内核
	installbbr(){
		kernel_version="4.11.8"
		if [[ ${release} == "centos" ]]; then
			if [[ ${version} -ge "8" ]]; then
				echo -e "${Error}暂不支持CentOS ${version}系统!!!任意键返回主页..."
				char=`get_char`
				start_menu_main
			fi
			rpm --import http://${github}/bbr/${release}/RPM-GPG-KEY-elrepo.org
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-${kernel_version}.rpm
			yum remove -y kernel-headers
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-headers-${kernel_version}.rpm
			yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-devel-${kernel_version}.rpm
		elif [[ ${release} == "debian" || ${release} == "ubuntu" ]]; then
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
		echo -e "${Tip}重启VPS后，请重新运行脚本开启$(red_font BBR/BBR魔改版)"
		read -p "需要重启VPS后，才能开启BBR/BBR魔改版，是否现在重启?[y/n](默认:y)：" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装BBRplus内核
	installbbrplus(){
		kernel_version="4.14.129-bbrplus"
		if [[ ${release} == "centos" ]]; then
			if [[ ${version} -ge "8" ]]; then
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
		elif [[ ${release} == "debian" || ${release} == "ubuntu" ]]; then
			mkdir bbrplus && cd bbrplus
			wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
			wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
			dpkg -i linux-headers-${kernel_version}.deb
			dpkg -i linux-image-${kernel_version}.deb
			cd .. && rm -rf bbrplus
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip}重启VPS后，请重新运行脚本开启$(red_font BBRplus)"
		read -p "需要重启VPS后，才能开启BBRplus，是否现在重启?[y/n](默认:y)：" yn
		[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
			echo -e "${Info} VPS 重启中..."
			reboot
		fi
	}

	#安装Lotserver内核
	installlot(){
		if [[ ${release} == "centos" ]]; then
			if [[ ${version} -ge "8" ]]; then
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
		elif [[ ${release} == "ubuntu" || ${release} == "debian" ]]; then
			bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
		fi
		detele_kernel
		BBR_grub
		echo -e "${Tip}重启VPS后，请重新运行脚本开启$(red_font Lotserver)"
		read -p "需要重启VPS后，才能开启Lotserver，是否现在重启?[y/n](默认:y)：" yn
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
		white_font "\n TCP加速一键安装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "          -- 胖波比 --\n"
		yello_font '————————————内核管理————————————'
		green_font ' 1.' '  安装 BBR/BBR魔改版内核'
		green_font ' 2.' '  安装 BBRplus版内核'
		green_font ' 3.' '  安装 Lotserver(锐速)内核'
		yello_font '————————————加速管理————————————'
		green_font ' 4.' '  使用BBR加速'
		green_font ' 5.' '  使用BBR魔改版加速'
		green_font ' 6.' '  使用暴力BBR魔改版加速(不支持部分系统)'
		green_font ' 7.' '  使用BBRplus版加速'
		green_font ' 8.' '  使用Lotserver(锐速)加速'
		yello_font '————————————杂项管理————————————'
		green_font ' 9.' '  卸载全部加速'
		green_font ' 10.' ' 系统配置优化'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 11.' ' 退出脚本'
		yello_font '————————————————————————————————'
		check_status
		if [[ ${kernel_status} == "noinstall" ]]; then
			echo -e "当前状态: $(green_font 未安装)加速内核，$(red_font 请先安装内核!)\n"
		else
			echo -e "当前状态: $(green_font "已安装 ${kernel_status}") 加速内核，$(green_font $run_status)\n"
			
		fi
		read -p "请输入数字[0-11](默认:2)：" num
		[ -z "${num}" ] && num=2
		case "$num" in
			0)
			start_menu_main
			;;
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-11]"
			sleep 2s
			start_menu_bbr
			;;
		esac
	}
	check_version_bbr
	start_menu_bbr
}

check_port(){
	unset port
	until [[ ${port} -ge "1" && ${port} -le "65535" ]]
	do
		clear
		echo && read -p "${webinfo}" port
		[ -z "${port}" ] && port=80
		if [[ -n "$(lsof -i:${port})" ]]; then
			echo -e "${Error}端口${port}已被占用！请输入新的端口!!!"
			sleep 2s && check_port
		fi
	done
}
set_fakeweb(){
	clear
	webinfo='请输入网站访问端口(未占用端口)(默认:80)：'
	check_port
	install_docker
	i=0
	until [[ $i -ge '1' && ! -d "${fakeweb}" ]]
	do
		i=$[$i+1] && fakeweb="/opt/fakeweb${i}"
	done
	mkdir -p ${fakeweb} && cd ${fakeweb}
	wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/nginx/dingyue.zip
	wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/nginx/docker-compose.yml
	unzip dingyue.zip
	sed -i "s#weburl#http://$(get_ip):${port}#g" ${fakeweb}/html/dingyue.html
	sed -i "s#de_port#${port}#g" docker-compose.yml
	echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成..."
	docker-compose up -d
}
#生成订阅链接
manage_dingyue(){
	install_dingyue(){
		if [ ! -e /root/test/dingyue ]; then
			set_fakeweb
			echo ${fakeweb} > /root/test/dingyue
			echo "${port}" >> /root/test/dingyue
		else
			port=$(cat /root/test/dingyue | tail -n 1)
			echo -e "${Info}你已安装订阅程序..."
		fi
		echo -e "\n${Info}首页地址： http://$(get_ip):${port}"
		echo -e "${Info}订阅地址： http://$(get_ip):${port}/dingyue.html"
		echo -e "${Tip}订阅地址主页在伪装网站首页的目录里..."
		echo -e "${Info}按任意键返回订阅链接管理页..."
		char=`get_char`
		start_menu_dingyue
	}
	uninstall_dingyue(){
		cd $(cat /root/test/dingyue | head -n 1)
		docker-compose down
		cd /root
		rm -rf $(cat /root/test/dingyue | head -n 1)
		rm -f /root/test/dingyue /root/test/dy*
	}
	manage_url_dingyue(){
		manage_dingyue_local(){
			dingyue_ssr(){
				clear
				urlsafe_base64(){
					date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
					echo -e "${date}"
				}
				protocol=$(jq -r '.protocol' /etc/shadowsocks.json)
				method=$(jq -r '.method' /etc/shadowsocks.json)
				obfs=$(jq -r '.obfs' /etc/shadowsocks.json)
				SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
				SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
				Remarksbase64=$(urlsafe_base64 "${myinfo}")
				Groupbase64=$(urlsafe_base64 "我们爱中国")
				rm -f $(cat /root/test/dingyue | head -n 1)/html/ssr.html
				jq '.port_password' /etc/shadowsocks.json | sed '1d' | sed '$d' | sed 's#"##g' | sed 's# ##g' | sed 's#,##g' > /root/test/ppj
				cat /root/test/ppj | while read line; do
					port=`echo $line|awk -F ':' '{print $1}'`
					password=`echo $line|awk -F ':' '{print $2}'`
					SSRPWDbase64=$(urlsafe_base64 "${password}")
					SSRbase64=$(urlsafe_base64 "$(get_ip):${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?remarks=${Remarksbase64}&group=${Groupbase64}")
					echo -e "ssr://${SSRbase64}" >> $(cat /root/test/dingyue | head -n 1)/html/ssr.html
				done
				base64 <<< $(cat $(cat /root/test/dingyue | head -n 1)/html/ssr.html) > $(cat /root/test/dingyue | head -n 1)/html/ssr.html
				touch /root/test/dyssr
				echo -e "\n${Info}SSR订阅链接已更新"
				echo -e "${Info}SSR订阅链接：http://$(get_ip):$(cat /root/test/dingyue | tail -n 1)/ssr.html"
				echo -e "${Info}按任意键返回订阅链接管理页..."
				char=`get_char`
				manage_dingyue_local
			}
			dingyue_v2ray(){
				sed -i "s#ps\":.*,#ps\": \"${myinfo}\",#g" $(cat /root/test/v2raypath)
				v2ray info | grep vmess | sed 's/.\{5\}//' | sed 's/.\{4\}$//' > $(cat /root/test/dingyue | head -n 1)/html/v2ray.html
				base64 <<< $(cat $(cat /root/test/dingyue | head -n 1)/html/v2ray.html) > $(cat /root/test/dingyue | head -n 1)/html/v2ray.html
				touch /root/test/dyv2ray
				echo -e "\n${Info}V2ray订阅链接已更新"
				echo -e "${Info}V2ray订阅链接：http://$(get_ip):$(cat /root/test/dingyue | tail -n 1)/v2ray.html"
				echo -e "${Info}按任意键返回订阅链接管理页..."
				char=`get_char`
				manage_dingyue_local
			}
			dingyue_trojan(){
				clear
				pw_trojan=$(jq '.password' /etc/trojan.json)
				length=$(jq '.password | length' /etc/trojan.json)
				tr_info="$(curl -s https://ipapi.co/country/)-%E6%88%91%E4%BB%AC%E7%88%B1%E4%B8%AD%E5%9B%BD"
				ipinfo=$(cat /root/test/trojan|sed -n '2p')
				port=$(cat /root/test/trojan|sed -n '1p')
				rm -f $(cat /root/test/dingyue | head -n 1)/html/trojan.html
				for i in `seq 0 $[length-1]`
				do
					password=$(echo $pw_trojan | jq ".[$i]" | sed 's/"//g')
					echo -e "trojan://${password}@${ipinfo}:${port}?allowInsecure=1&tfo=1#${tr_info}" >> $(cat /root/test/dingyue | head -n 1)/html/trojan.html
				done
				base64 <<< $(cat $(cat /root/test/dingyue | head -n 1)/html/trojan.html) > $(cat /root/test/dingyue | head -n 1)/html/trojan.html
				touch /root/test/dytrojan
				echo -e "\n${Info}Trojan订阅链接已更新"
				echo -e "${Info}Trojan订阅链接：http://$(get_ip):$(cat /root/test/dingyue | tail -n 1)/trojan.html"
				echo -e "${Info}按任意键返回订阅链接管理页..."
				char=`get_char`
				manage_dingyue_local
			}
			dingyue_all(){
				clear
				rm -f $(cat /root/test/dingyue | head -n 1)/html/all.html
				if [ -e /root/test/dyssr ]; then
					cat $(cat /root/test/dingyue | head -n 1)/html/ssr.html >> $(cat /root/test/dingyue | head -n 1)/html/all.html
				fi
				if [ -e /root/test/dyv2ray ]; then
					cat $(cat /root/test/dingyue | head -n 1)/html/v2ray.html >> $(cat /root/test/dingyue | head -n 1)/html/all.html
				fi
				if [ -e /root/test/dytrojan ]; then
					cat $(cat /root/test/dingyue | head -n 1)/html/trojan.html >> $(cat /root/test/dingyue | head -n 1)/html/all.html
				fi
				echo -e "\n${Info}总订阅链接已更新"
				echo -e "${Info}总订阅链接：http://$(get_ip):$(cat /root/test/dingyue | tail -n 1)/all.html"
				echo -e "${Info}按任意键返回订阅链接管理页..."
				char=`get_char`
				manage_dingyue_local
			}
			clear
			white_font "\n 订阅链接一键管理脚本 \c" && red_font "[v${sh_ver}]"
			white_font "        -- 胖波比 --\n"
			yello_font '————————————————————————————'
			green_font ' 1.' '  生成/更新SSR订阅'
			green_font ' 2.' '  生成/更新V2ray订阅'
			green_font ' 3.' '  生成/更新Trojan订阅'
			green_font ' 4.' '  生成/更新总订阅'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 5.' '  返回上页'
			green_font ' 6.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-6](默认:0)：" num
			[ -z "${num}" ] && num=0
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				dingyue_ssr
				;;
				2)
				dingyue_v2ray
				;;
				3)
				dingyue_trojan
				;;
				4)
				dingyue_all
				;;
				5)
				manage_url_dingyue
				;;
				6)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-6]"
				sleep 2s
				manage_dingyue_local
				;;
			esac
			manage_dingyue_local
		}
		manage_dingyue_remote(){
			clear
			echo -e "\n${Tip}使用此功能需要先在远程服务器生成对应的链接!!!"
			echo -e "${Tip}IP或密码输入错误将会导致订阅链接生成失败!\n"
			read -p "请输入远程服务器IP：" ipinfo
			read -p "请输入${ipinfo}的root用户密码：" password
			read -p "请输入${ipinfo}的SSH端口：" port
			yello_font '————————————————————————————'
			green_font ' 1.' '  生成/更新SSR订阅'
			green_font ' 2.' '  生成/更新V2ray订阅'
			green_font ' 3.' '  生成/更新Trojan订阅'
			green_font ' 4.' '  生成/更新总订阅'
			yello_font '————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 5.' '  返回上页'
			green_font ' 6.' '  退出脚本'
			yello_font "————————————————————————————\n"
			read -p "请输入数字[0-6](默认:0)：" num
			[ -z "${num}" ] && num=0
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				vpntype='ssr'
				;;
				2)
				vpntype='v2ray'
				;;
				3)
				vpntype='trojan'
				;;
				4)
				vpntype='all'
				;;
				5)
				manage_url_dingyue
				;;
				6)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-6]"
				sleep 2s
				manage_dingyue_remote
				;;
			esac
			sshpass -p ${password} scp -P ${port} root@${ipinfo}:/root/test/dingyue /root/test/dyremote
			sshpass -p ${password} scp -P ${port} root@${ipinfo}:$(cat /root/test/dyremote | head -n 1)/html/${vpntype}.html /root/test/dy${vpntype}
			yello_font '————————————————————'
			green_font ' 1.' '  覆盖链接'
			green_font ' 2.' '  追加链接'
			yello_font '————————————————————'
			choose_dytype(){
				read -p "请选择链接生成方式[1-2](默认:2)：" num
				[ -z "${num}" ] && num=2
				case "$num" in
					1)
					cat /root/test/dy${vpntype} > $(cat /root/test/dingyue | head -n 1)/html/${vpntype}.html
					;;
					2)
					cat /root/test/dy${vpntype} >> $(cat /root/test/dingyue | head -n 1)/html/${vpntype}.html
					;;
					*)
					clear
					echo -e "${Error}请输入正确数字 [1-2]"
					sleep 2s
					choose_dytype
					;;
				esac
			}
			choose_dytype
			echo -e "\n${Info}订阅链接已更新"
			echo -e "${Info}订阅链接：http://$(get_ip):$(cat /root/test/dingyue | tail -n 1)/${vpntype}.html"
			echo -e "${Info}按任意键返回订阅链接管理页..."
			char=`get_char`
			manage_url_dingyue
		}
		clear
		white_font "\n 订阅链接一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "        -- 胖波比 --\n"
		yello_font '————————————————————————————'
		green_font ' 1.' '  使用本地服务生成订阅'
		green_font ' 2.' '  使用远程服务生成订阅'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  返回上页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-4](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			manage_dingyue_local
			;;
			2)
			manage_dingyue_remote
			;;
			3)
			start_menu_dingyue
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
			sleep 2s
			manage_url_dingyue
			;;
		esac
		manage_url_dingyue
	}
	start_menu_dingyue(){
		clear
		white_font "\n 订阅链接一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "        -- 胖波比 --\n"
		yello_font '————————————————————————————'
		green_font ' 1.' '  管理订阅'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装订阅'
		green_font ' 3.' '  卸载订阅'
		yello_font '————————————————————————————'
		green_font ' 4.' '  重启订阅'
		green_font ' 5.' '  关闭订阅'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 6.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-6](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			manage_url_dingyue
			;;
			2)
			install_dingyue
			;;
			3)
			uninstall_dingyue
			;;
			4)
			cd $(cat /root/test/dingyue | head -n 1)
			docker-compose restart
			;;
			5)
			cd $(cat /root/test/dingyue | head -n 1)
			docker-compose kill
			;;
			6)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-6]"
			sleep 2s
			start_menu_dingyue
			;;
		esac
		start_menu_dingyue
	}
	start_menu_dingyue
}

#生成字符二维码
manage_qrcode(){
	clear
	echo && read -p "请输入生成二维码的链接：" num
	qrencode -o - -t ANSI "${num}"
	white_font "\n   -- 胖波比 --\n"
	yello_font '—————二维码生成——————'
	green_font ' 1.' '  继续生成'
	yello_font '—————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 2.' '  退出脚本'
	yello_font "—————————————————————\n"
	read -p "请输入数字[0-2](默认:0)：" num
	[ -z "${num}" ] && num=0
	case "$num" in
		0)
		start_menu_main
		;;
		1)
		manage_qrcode
		;;
		2)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-2]"
		sleep 2s
		manage_qrcode
		;;
	esac
}

#安装宝塔面板
manage_btpanel(){
	set_btpanel(){
		clear
		bt
		echo -e "${Info}按任意键继续..."
		char=`get_char`
	}
	install_btpanel(){
		wget -O bt_install.sh https://raw.githubusercontent.com/AmuyangA/public/master/panel/btpanel/bt_install.sh && chmod +x bt_install.sh && ./bt_install.sh
		start_menu_main
	}
	start_menu_btpanel(){
		clear
		white_font "\n BT-PANEL一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '———————BT-PANEL管理—————————'
		green_font ' 1.' '  管理BT-PANEL'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装BT-PANEL'
		green_font ' 3.' '  卸载BT-PANEL'
		green_font ' 4.' '  解除拉黑,解锁文件'
		yello_font '————————————————————————————'
		green_font ' 5.' '  重启BT-PANEL'
		green_font ' 6.' '  关闭BT-PANEL'
		green_font ' 7.' '  启动BT-PANEL'
		green_font ' 8.' '  查看BT-PANEL状态'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 9.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-9](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			set_btpanel
			;;
			2)
			install_btpanel
			;;
			3)
			wget -O bt_uninstall.sh https://raw.githubusercontent.com/AmuyangA/public/master/panel/btpanel/bt_uninstall.sh && chmod +x bt_uninstall.sh && ./bt_uninstall.sh
			;;
			4)
			wget -O waf.sh https://raw.githubusercontent.com/AmuyangA/public/master/panel/btpanel/waf.sh && chmod +x waf.sh && ./waf.sh
			;;
			5)
			bt restart
			check_vpn_status 'bt status' '宝塔面板' '重启'
			;;
			6)
			bt stop
			;;
			7)
			bt start
			check_vpn_status 'bt status' '宝塔面板' '启动'
			;;
			8)
			check_vpn_status 'bt status' '宝塔面板' '运行'
			;;
			9)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-9]"
			sleep 2s
			start_menu_btpanel
			;;
		esac
		start_menu_btpanel
	}
	start_menu_btpanel
}

#安装Forsaken Mail
manage_forsakenmail(){
	clear
	white_font "\n     ————胖波比————\n"
	yello_font '——————————————————————————'
	green_font ' 1.' '  安装Forsaken Mail'
	green_font ' 2.' '  卸载Forsaken Mail'
	yello_font "——————————————————————————\n"
	read -p "请输入数字[1-2](默认:1)：" num
	[ -z "${num}" ] && num=1
	if [[ $num == '1' ]]; then
		echo -e "\n${Tip}请先将域名做好 A记录 和 MX记录 并解析到本机"
		echo -e "${Tip}否则临时邮箱后缀将是本机IP地址..."
		echo -e "${Info}按任意键继续..."
		char=`get_char`
		#开放25,3000端口的防火墙
		port=25
		add_firewall
		port=3000
		if [[ -n "$(lsof -i:${port})" ]]; then
			echo -e "${Error}端口${port}已被占用！请输入新的端口!!!"
			exit 1
		fi
		add_firewall
		firewall_restart
		#安装NPM
		if [[ ${release} == "centos" ]]; then
			curl -sL https://rpm.nodesource.com/setup_10.x | bash -
		else
			curl -sL https://deb.nodesource.com/setup_10.x | bash -
		fi 
		#安装Forsaken Mail
		mkdir -p /opt && cd /opt
		git clone https://github.com/denghongcai/forsaken-mail.git
		cd forsaken-mail
		npm install pm2@latest -g
		npm install
		pm2 start bin/www
		pm2 startup
		pm2 save
		cd /root
		echo -e "\n${Info}首页地址：http://$(get_ip):${port} 或者 http://域名:${port}"
		echo -e "${Info}按任意键返回首页..."
		char=`get_char`
	elif [[ $num == '2' ]]; then
		chattr -i /opt/forsaken-mail/public/.user.ini
		rm -rf /opt/forsaken-mail
	else
		manage_forsakenmail
	fi
}

#安装ZFAKA
manage_zfaka(){
	install_zfaka(){
		install_docker
		mkdir -p /opt/zfaka && cd /opt/zfaka
		rm -f docker-compose.yml
		wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/zfaka/docker-compose.yml
		check_port
		sed -i "s#de_port#${port}#g" docker-compose.yml
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成..."
		docker-compose up -d
		echo -e "\n${Info}首页地址： http://$(get_ip):${port}"
		echo -e "${Tip}打开网站安装数据库时请修改如下信息"
		echo -e "${Tip}请将数据库127.0.0.1改为：mysql"
		echo -e "${Tip}请将数据库密码改为：baiyue.one"
		echo -e "${Info}phpMyAdmin地址：http://$(get_ip):602"
		echo -e "${Info}phpMyAdmin用户名：root"
		echo -e "${Info}phpMyAdmin密码：baiyue.one"
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
		white_font "\nZFAKA一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '——————ZFAKA管理——————'
		green_font ' 1.' '  安装ZFAKA'
		green_font ' 2.' '  卸载ZFAKA'
		green_font ' 3.' '  重启ZFAKA'
		green_font ' 4.' '  停止ZFAKA'
		yello_font '—————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 5.' '  退出脚本'
		yello_font "—————————————————————\n"
		read -p "请输入数字[0-5](默认:0):" num
		[ -z "${num}" ] && num=0
		case "$num" in
			0)
			start_menu_main
			;;
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-5]"
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
				mkdir -p /opt/sspanel && cd /opt/sspanel
				rm -f docker-compose.yml
				wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/ssrpanel/docker-compose.yml
				check_port
				sed -i "s#de_port#${port}#g" docker-compose.yml
				sed -i "s/sspanel_type/${sspaneltype}/g" docker-compose.yml
				echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成..."
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
					cd /root
					wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/ssrpanel/msp.sh
					chmod +x msp.sh
				fi
				echo -e "\n${Info}网站首页：http://$(get_ip):${port}"
				echo -e "${Info}Kodexplorer：http://$(get_ip):604"
				echo -e "${Info}网站地址：/opt/sspanel/code"
				echo -e "\n${Info}即将同步数据库并创建管理员账户..."
				echo -e "${Info}请输入：./msp.sh"
				echo -e "\n${Info}任意键继续..."
				char=`get_char`
				exit 1
			fi
		}
		select_sspanel_type(){
			clear
			echo -e "\n${Tip}SS-PANEL前端只需要安装在面板机！！！"
			white_font "	-- 胖波比 --\n"
			yello_font '—————————————————————'
			green_font ' 1.' '  安装开发版'
			green_font ' 2.' '  卸载稳定版'
			yello_font '—————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回上页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				sspaneltype="dev"
				install_sspanel
				;;
				2)
				sspaneltype="master"
				install_sspanel
				;;
				3)
				sspanel_start_menu
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
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
			read -p "请输入面板创建的节点序号(例如:3)：" nodeid
			if [ ! -e /root/test/spdb ]; then
				read -p "请输入面板机域名或IP(默认本机IP)：" mysqldomain
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
			read -p "请输入面板创建的节点序号(例如:3)：" nodeid
			if [ ! -e /root/test/spwa ]; then
				read -p "请输入面板机域名或IP(默认本机IP)：" mysqldomain
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
			white_font "\nSS-PANEL_UIM 后端对接一键脚本 \c" && red_font "[v${sh_ver}]"
			white_font "	-- 胖波比 --\n"
			yello_font '—————————————————————'
			green_font ' 1.' '  Database对接'
			green_font ' 2.' '  WebApi对接'
			yello_font '—————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回上页'
			green_font ' 4.' '  退出脚本'
			yello_font "—————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=4
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				node_database
				;;
				2)
				node_webapi
				;;
				3)
				sspanel_start_menu
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
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
		white_font "\nSS-PANEL_UIM 一键设置脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	-- 胖波比 --'
		white_font "修改网站配置文件：vi /opt/sspanel/code/config/.config.php\n"
		yello_font '————————————————————————————————'
		green_font ' 1.' '  安装SS-PANEL前端'
		green_font ' 2.' '  安装SS-PANEL后端'
		green_font ' 3.' '  卸载SS-PANEL'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		read -p "请输入数字[0-4](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
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
			check_port
			echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成..."
			docker run -d -p ${port}:80 --name kodexplorer -v /opt/kodcloud:/code baiyuetribe/kodexplorer
			touch /root/test/ko
			echo -e "\n${Info}首页地址：http://$(get_ip):${port}"
			echo -e "${Info}默认宿主机目录：/opt/kodcloud"
			echo -e "\n${Info}按任意键返回主页..."
			char=`get_char`
			start_menu_main
		fi
	}
	start_menu_kodexplorer(){
		clear
		white_font "\nKodexplorer一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	   -- 胖波比 --\n"
		yello_font '—————Kodexplorer管理—————'
		green_font ' 1.' '  安装Kodexplorer'
		green_font ' 2.' '  卸载Kodexplorer'
		green_font ' 3.' '  重启Kodexplorer'
		green_font ' 4.' '  停止Kodexplorer'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 5.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-5](默认:0):" num
		[ -z "${num}" ] && num=0
		case "$num" in
			0)
			start_menu_main
			;;
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-5]"
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
		install_docker
		mkdir -p /opt/wordpress && cd /opt/wordpress
		rm -f docker-compose.yml
		wget https://raw.githubusercontent.com/AmuyangA/public/master/panel/wordpress/docker-compose.yml
		check_port
		sed -i "s#de_port#${port}#g" docker-compose.yml
		echo -e "${Info}首次启动会拉取镜像，国内速度比较慢，请耐心等待完成..."
		docker-compose up -d
		echo -e "\n${Info}首页地址：http://$(get_ip):${port}"
		echo -e "${Info}phpMyAdmin地址：http://$(get_ip):605"
		echo -e "${Info}phpMyAdmin用户名：root"
		echo -e "${Info}phpMyAdmin密码：pangbobi"
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
		white_font "\nWordPress一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '————WordPress管理————'
		green_font ' 1.' '  安装WordPress'
		green_font ' 2.' '  卸载WordPress'
		green_font ' 3.' '  重启WordPress'
		green_font ' 4.' '  停止WordPress'
		yello_font '—————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 5.' '  退出脚本'
		yello_font "—————————————————————\n"
		read -p "请输入数字[0-5](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-5]"
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
		echo -e "${Info}按任意键返回主页..."
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
		white_font "\n Docker一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	   -- 胖波比 --\n"
		yello_font '————————Docker管理———————'
		green_font ' 1.' '  安装Docker'
		green_font ' 2.' '  卸载Docker'
		yello_font '—————————————————————————'
		green_font ' 3.' '  安装海鸥Docker管理器'
		green_font ' 4.' '  删除所有Docker镜像,容器,卷'
		yello_font '—————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 5.' '  退出脚本'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-5](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			install_docker
			;;
			2)
			uninstall_docker
			;;
			3)
			install_seagull
			;;
			4)
			uninstall_docker_all
			;;
			5)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-5]"
			sleep 2s
			start_menu_docker
			;;
		esac
	}
	start_menu_docker
}

#安装Caddy
install_caddy(){
	file="/usr/local/caddy"
	caddy_file="/usr/local/caddy/caddy"
	caddy_conf_file="/usr/local/caddy/Caddyfile"

	check_installed_status(){
		[[ ! -e ${caddy_file} ]] && echo -e "${Error}Caddy 没有安装，请检查 !" && install_caddy
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
		bit=`uname -m`
		if [[ ${bit} == "x86_64" ]]; then
			wget --no-check-certificate -O "caddy_linux.tar.gz" "https://caddyserver.com/download/linux/amd64${extension_all}"
		elif [[ ${bit} == "i386" || ${bit} == "i686" ]]; then
			wget --no-check-certificate -O "caddy_linux.tar.gz" "https://caddyserver.com/download/linux/386${extension_all}"
		elif [[ ${bit} == "armv7l" ]]; then
			wget --no-check-certificate -O "caddy_linux.tar.gz" "https://caddyserver.com/download/linux/arm7${extension_all}"
		else
			echo -e "${Error}不支持 ${bit}!" && exit 1
		fi
		[[ ! -e "caddy_linux.tar.gz" ]] && echo -e "${Error}Caddy 下载失败 !" && exit 1
		tar zxf "caddy_linux.tar.gz"
		rm -rf "caddy_linux.tar.gz"
		[[ ! -e ${caddy_file} ]] && echo -e "${Error}Caddy 解压失败或压缩文件错误 !" && exit 1
		rm -rf LICENSES.txt
		rm -rf README.txt 
		rm -rf CHANGES.txt
		rm -rf "init/"
		chmod +x caddy
	}
	Service_caddy(){
		if [[ ${release} = "centos" ]]; then
			if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/caddy_centos -O /etc/init.d/caddy; then
				echo -e "${Error}Caddy服务 管理脚本下载失败 !" && exit 1
			fi
			chmod +x /etc/init.d/caddy
			chkconfig --add caddy
			chkconfig caddy on
		else
			if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/caddy_debian -O /etc/init.d/caddy; then
				echo -e "${Error}Caddy服务 管理脚本下载失败 !" && exit 1
			fi
			chmod +x /etc/init.d/caddy
			update-rc.d -f caddy defaults
		fi
	}
	caddy_install(){
		if [ ! -e /root/test/fakeweb ]; then
			if [[ -e ${caddy_file} ]]; then
				echo && echo -e "${Info}检测到 Caddy 已安装，是否继续安装(覆盖更新)？[y/n]"
				read -e -p "(默认:n)：" yn
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
			fakesite='/opt/fakeweb'
			if [ ! -d "${fakesite}" ]; then
				mkdir -p ${fakesite} && cd ${fakesite}
				wget https://raw.githubusercontent.com/AmuyangA/public/master/web.zip
				unzip web.zip
			fi
			base64 -d <<< aG9zdF9uYW1lOmRlX3BvcnQgew0KICAgIGd6aXANCiAgICByb290IC9vcHQvZmFrZXdlYg0KfQ== > $caddy_conf_file
			webinfo='请输入网站访问端口(未占用端口)(默认:80)：'
			check_port
			add_firewall
			firewall_restart
			sed -i "s#de_port#${port}#g" $caddy_conf_file
			sed -i "s#host_name#$(get_ip)#g" $caddy_conf_file
			service caddy restart
			touch /root/test/fakeweb
			echo -e "\n${Info}Caddy安装完成！任意键进入Caddy配置页..."
			echo -e "${Info}首页地址：http://$(get_ip):${port}"
			char=`get_char`
			manage_caddy
		else
			echo -e "${Info}你已安装且并未卸载过伪装，任意键返回主页..."
			char=`get_char`
			start_menu_main
		fi
	}
	caddy_uninstall(){
		check_installed_status
		echo && echo "确定要卸载 Caddy ? [y/n]："
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
			#删除Caddy监听地址文件夹
			rm -rf ${file} /etc/init.d/caddy
			rm -f /root/test/fakeweb
			[[ ! -e ${caddy_file} ]] && echo && echo -e "${Info}Caddy 卸载完成 !" && echo && exit 1
			echo && echo -e "${Error}Caddy 卸载失败 !" && echo
		else
			echo && echo "卸载已取消..."
			sleep 2s
			start_menu_caddy
		fi
	}
	manage_caddy(){
		manage_caddy_success(){
			cat $caddy_conf_file |tr -d "\r" > /root/test/temp
			cp /root/test/temp $caddy_conf_file
			service caddy restart
			echo -e "${Info}修改并成功重启Caddy，2秒后回到配置管理页..."
			sleep 2s
			manage_caddy
		}
		choose_hosttype(){
			hosttype=$1
			caddy_back_core(){
				yello_font '——————————————————————————————'
				green_font ' 1.' '  本机作为代理目标网站'
				green_font ' 2.' '  外站作为代理目标网站'
				yello_font "——————————————————————————————\n"
				read -p "请输入数字[1-2](默认:2)：" num
				[ -z "${num}" ] && num=2
				if [ ${num} == '2' ]; then
					read -p "请输入代理目标网站[请输入完整网址](默认:https://www.bilibili.com)：" ddomain
					[ -z "${ddomain}" ] && ddomain='https://www.bilibili.com'
				elif [ ${num} == '1' ]; then
					read -p "请输入本机网站端口：" port
					ddomain="localhost:${port}"
				else
					caddy_back_core
				fi
				line=$(grep -n '/opt/fakeweb' ${caddy_conf_file} |tail -1 |awk -F ':'  '{print $1}')
				sed -i "${line}s#root /opt/fakeweb#proxy / ${ddomain}#" $caddy_conf_file
			}
			caddy_ip(){
				base64 -d <<< aG9zdF9uYW1lOmRlX3BvcnQgew0KICAgIGd6aXANCiAgICByb290IC9vcHQvZmFrZXdlYg0KfQ== >> $caddy_conf_file
				ydomain=$(get_ip)
				if [ ${hosttype} == '2' ]; then
					caddy_back_core
				fi
			}
			caddy_domain(){
				clear && echo
				read -p "请输入已解析到本机的域名：" ydomain
				caddy_domain_http(){
					clear && echo
					base64 -d <<< aG9zdF9uYW1lOmRlX3BvcnQgew0KICAgIGd6aXANCiAgICByb290IC9vcHQvZmFrZXdlYg0KfQ== >> $caddy_conf_file
					webinfo='请输入监听端口(未占用端口)(默认:80)：'
					check_port
					sed -i "s#host_name#host_name:${port}#g" $caddy_conf_file
					if [ ${hosttype} == '2' ]; then
						caddy_back_core
					fi
				}
				caddy_domain_https(){
					clear && echo
					if [[ -n "$(lsof -i:443)" ]]; then
						echo -e "${Error}端口443已被占用！无法使用HTTPS!"
						sleep 2s && caddy_domain
					elif [[ -n "$(lsof -i:80)" ]]; then
						echo -e "${Error}端口80已被占用！无法自动申请SSL证书!"
						sleep 2s && caddy_domain
					else
						read -p "请输入用来申请证书的邮箱：" yemail
						base64 -d <<< aG9zdF9uYW1lIHsNCiAgICBnemlwDQogICAgdGxzIHVzZXJfZW1haWwNCiAgICByb290IC9vcHQvZmFrZXdlYg0KfQ== >> $caddy_conf_file
						sed -i "s#user_email#${yemail}#g" $caddy_conf_file
						if [ ${hosttype} == '2' ]; then
							caddy_back_core
						fi
						crt_position='/.caddy/acme/acme-v02.api.letsencrypt.org/sites'
						echo -e "\n${Info}证书及密钥位置：${crt_position}"
						echo -e "${Tip}证书：${crt_position}/${ydomain}.crt"
						echo -e "${Tip}密钥：${crt_position}/${ydomain}.key"
						echo -e "${Info}按任意键继续..."
						char=`get_char`
					fi
				}
				white_font "\n	  -- 胖波比 --\n"
				yello_font '——————————————————————————————'
				green_font ' 1.' '  使用HTTP'
				green_font ' 2.' '  使用HTTPS'
				yello_font '——————————————————————————————'
				green_font ' 0.' '  回到主页'
				green_font ' 3.' '  返回上页'
				green_font ' 4.' '  退出脚本'
				yello_font "——————————————————————————————\n"
				read -p "请输入数字[0-4](默认:1)：" num
				[ -z "${num}" ] && num=1
				case "$num" in
					0)
					start_menu_main
					;;
					1)
					caddy_domain_http
					;;
					2)
					caddy_domain_https
					;;
					3)
					choose_hosttype
					;;
					4)
					exit 1
					;;
					*)
					clear
					echo -e "${Error}请输入正确数字 [0-4]"
					sleep 2s
					caddy_domain
					;;
				esac
			}
			clear
			white_font "\n	  -- 胖波比 --\n"
			yello_font '——————————————————————————————'
			green_font ' 1.' '  使用本机IP'
			green_font ' 2.' '  使用解析到本机的域名'
			yello_font '——————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 3.' '  返回上页'
			green_font ' 4.' '  退出脚本'
			yello_font "——————————————————————————————\n"
			read -p "请输入数字[0-4](默认:1)：" num
			[ -z "${num}" ] && num=1
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				caddy_ip
				;;
				2)
				caddy_domain
				;;
				3)
				manage_caddy
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				choose_hosttype
				;;
			esac
			sed -i "s#host_name#${ydomain}#g" $caddy_conf_file
		}
		add_caddy(){
			choose_hosttype '1'
		}
		delete_caddy(){
			clear
			echo -e "\n${Info}懒得写了，自己手动设置，谢谢.."
			echo -e "${Info}按任意键继续..."
			char=`get_char`
			vi ${caddy_conf_file}
		}
		caddy_back(){
			choose_hosttype '2'
		}
		clear
		white_font "\n Caddy配置管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font '	  -- 胖波比 --'
		white_font "手动修改配置文件：vi ${caddy_conf_file}\n"
		yello_font '——————————Caddy配置管理—————————'
		green_font ' 1.' '  添加监听端口'
		green_font ' 2.' '  删除监听端口'
		green_font ' 3.' '  反向代理'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		read -p "请输入数字[0-4](默认:0)：" num
		[ -z "${num}" ] && num=0
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			add_caddy
			;;
			2)
			delete_caddy
			;;
			3)
			caddy_back
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
			sleep 2s
			manage_caddy
			;;
		esac
		manage_caddy_success
		manage_caddy
	}
	#开始菜单
	start_menu_caddy(){
		clear
		white_font "\n Caddy一键安装脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '—————————Caddy管理——————————'
		green_font ' 1.' '  配置Caddy'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装Caddy'
		green_font ' 3.' '  卸载Caddy'
		yello_font '————————————————————————————'
		green_font ' 4.' '  重启Caddy'
		green_font ' 5.' '  关闭Caddy'
		green_font ' 6.' '  启动Caddy'
		green_font ' 7.' '  查看Caddy状态'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			manage_caddy
			;;
			2)
			caddy_install
			;;
			3)
			caddy_uninstall
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			start_menu_caddy
			;;
		esac
		start_menu_caddy
	}
	extension=$2
	start_menu_caddy
}

#安装Nginx
install_nginx(){
	nginx_install(){
		if [ ! -e /root/test/fakeweb ]; then
			if [[ ${release} == "centos" ]]; then
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
			elif [[ ${release} == "debian" ]]; then
				echo "deb http://nginx.org/packages/debian/ stretch nginx" >> /etc/apt/sources.list
				echo "deb-src http://nginx.org/packages/debian/ stretch nginx" >> /etc/apt/sources.list
				wget http://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
				apt-key add nginx_signing.key >/dev/null 2>&1
				apt-get update
				apt-get -y install nginx
				rm -rf add nginx_signing.key >/dev/null 2>&1
			elif [[ ${release} == "ubuntu" ]]; then
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
			fakesite='/opt/fakeweb'
			if [ ! -d "${fakesite}" ]; then
				mkdir -p ${fakesite} && cd ${fakesite}
				wget https://raw.githubusercontent.com/AmuyangA/public/master/web.zip
				unzip web.zip
			fi
			base64 -d <<< c2VydmVyIHsNCiAgICBsaXN0ZW4gZGVfcG9ydDsNCiAgICBzZXJ2ZXJfbmFtZSBsb2NhbGhvc3Q7DQogICAgbG9jYXRpb24gLyB7DQogICAgICAgIHJvb3QgICAvb3B0L2Zha2V3ZWI7DQogICAgICAgIGluZGV4ICBpbmRleC5odG1sIGluZGV4Lmh0bTsNCiAgICB9DQogICAgZXJyb3JfcGFnZSAgIDUwMCA1MDIgNTAzIDUwNCAgLzUweC5odG1sOw0KICAgIGxvY2F0aW9uID0gLzUweC5odG1sIHsNCiAgICAgICAgcm9vdCAgIC9vcHQvZmFrZXdlYjsNCiAgICB9DQp9 > /etc/nginx/conf.d/default.conf
			webinfo='请输入网站访问端口(未占用端口)(默认:80)：'
			check_port
			add_firewall
			firewall_restart
			sed -i "s#de_port#${port}#g" /etc/nginx/conf.d/default.conf
			systemctl start nginx.service
			touch /root/test/fakeweb
			echo -e "\n${Info}Nginx安装完成！任意键进入Nginx配置页..."
			echo -e "${Info}首页地址：http://$(get_ip):${port}"
			char=`get_char`
			set_nginx
		else
			echo -e "${Info}你已安装且并未卸载过伪装，任意键返回主页..."
			char=`get_char`
			start_menu_main
		fi
	}
	nginx_uninstall(){
		if [[ ${release} == 'centos' ]]; then
			yum remove nginx
		else
			apt-get --purge remove nginx
		fi
		rm -f /root/test/fakeweb
	}
	#配置Nginx
	set_nginx(){
		#配置结尾
		set_nginx_success(){
			systemctl restart nginx.service
			echo -e "${Info}修改并成功重启Nginx，2秒后回到配置管理页..."
			sleep 2s
			set_nginx_menu
		}
		#添加监听端口
		add_nginx(){
			webinfo='请输入监听端口[1-65535](默认:80)：'
			check_port
			add_firewall
			firewall_restart
			sed -i "2i listen ${port};" /etc/nginx/conf.d/default.conf
			sed -i "2s/^/    /" /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#删除监听端口
		delete_nginx(){
			clear 
			echo -e "\n{Info}已监听端口有：$(grep listen /etc/nginx/conf.d/default.conf |sed 's# ##g' |sed 's#;##g' |awk -F 'n' '{print $2}' |xargs)"
			read -p "请输入端口[1-65535]中已监听端口：" port
			if [ `grep -c "listen ${port}" /etc/nginx/conf.d/default.conf` -eq '1' ]; then
				sed -i "/listen ${port}/d" /etc/nginx/conf.d/default.conf
				delete_firewall
				firewall_restart
				set_nginx_success
			else
				echo -e "${Error}端口${port}并未被监听，请输入屏幕显示的已监听端口..."
				sleep 2s
				delete_nginx
			fi
		}
		#反向代理
		nginx_back(){
			webinfo='请输入被代理端口[1-65535](默认:80)：'
			check_port
			add_firewall
			firewall_restart
			read -p "请输入已解析到本机的域名(默认本机IP)：" ydomain
			[ -z "${ydomain}" ] && ydomain='localhost'
			read -p "请输入代理目标网站[请输入完整网址](默认:https://www.bilibili.com)：" ddomain
			[ -z "${ddomain}" ] && ddomain='https://www.bilibili.com'
			base64 -d <<< c2VydmVyIHsNCiAgICBsaXN0ZW4gZGVfcG9ydDsNCiAgICBzZXJ2ZXJfbmFtZSAgaG9zdF9uYW1lOw0KICAgIGxvY2F0aW9uIC8gew0KICAgICAgICBwcm94eV9wYXNzIGRlc3RpbmF0aW9uX25hbWU7DQogICAgfQ0KfQ== >> /etc/nginx/conf.d/default.conf
			sed -i "s#de_port#${port}#g" /etc/nginx/conf.d/default.conf
			sed -i "s#host_name#${ydomain}#g" /etc/nginx/conf.d/default.conf
			sed -i "s#destination_name#${ddomain}#g" /etc/nginx/conf.d/default.conf
			set_nginx_success
		}
		#配置方式选择
		set_nginx_menu(){
			clear
			white_font "\n Nginx配置管理脚本 \c" && red_font "[v${sh_ver}]"
			white_font '	  -- 胖波比 --'
			white_font "手动修改配置文件：vi /etc/nginx/conf.d/default.conf\n"
			yello_font '——————————Nginx配置管理—————————'
			green_font ' 1.' '  添加监听端口'
			green_font ' 2.' '  删除监听端口'
			green_font ' 3.' '  反向代理'
			yello_font '————————————————————————————————'
			green_font ' 0.' '  回到主页'
			green_font ' 4.' '  退出脚本'
			yello_font "————————————————————————————————\n"
			read -p "请输入数字[0-4](默认:0)：" num
			[ -z "${num}" ] && num=0
			case "$num" in
				0)
				start_menu_main
				;;
				1)
				add_nginx
				;;
				2)
				delete_nginx
				;;
				3)
				nginx_back
				;;
				4)
				exit 1
				;;
				*)
				clear
				echo -e "${Error}请输入正确数字 [0-4]"
				sleep 2s
				set_nginx_menu
				;;
			esac
			set_nginx_menu
		}
		set_nginx_menu
	}
	#Nginx管理
	manage_nginx(){
		clear
		white_font "\n Nginx一键管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '—————————Nginx管理——————————'
		green_font ' 1.' '  配置Nginx'
		yello_font '————————————————————————————'
		green_font ' 2.' '  安装Nginx'
		green_font ' 3.' '  卸载Nginx'
		yello_font '————————————————————————————'
		green_font ' 4.' '  重启Nginx'
		green_font ' 5.' '  关闭Nginx'
		green_font ' 6.' '  启动Nginx'
		green_font ' 7.' '  查看Nginx状态'
		yello_font '————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————\n"
		read -p "请输入数字[0-8](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			set_nginx
			;;
			2)
			nginx_install
			;;
			3)
			nginx_uninstall
			;;
			4)
			systemctl restart nginx.service
			;;
			5)
			systemctl stop nginx.service
			;;
			6)
			systemctl start nginx.service
			;;
			7)
			systemctl status nginx.service
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			manage_nginx
			;;
		esac
		manage_nginx
	}
	manage_nginx
}

#设置SSH端口
set_ssh(){
	clear
	ssh_port=$(cat /etc/ssh/sshd_config |grep 'Port ' |awk -F ' ' '{print $2}')
	while :; do echo
		read -p "请输入要修改为的SSH端口(默认:$ssh_port)：" SSH_PORT
		[ -z "$SSH_PORT" ] && SSH_PORT=$ssh_port
		if [ $SSH_PORT -eq 22 >/dev/null 2>&1 -o $SSH_PORT -gt 1024 >/dev/null 2>&1 -a $SSH_PORT -lt 65535 >/dev/null 2>&1 ];then
			break
		else
			echo "${Error}input error! Input range: 22,1025~65534${CEND}"
		fi
	done
	if [[ ${SSH_PORT} != "${ssh_port}" ]]; then
		#开放安全权限
		if type sestatus >/dev/null 2>&1 && [ $(getenforce) != "Disabled" ]; then
			if type semanage >/dev/null 2>&1 && [ ${release} == "centos" ]; then
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
		if type semanage >/dev/null 2>&1 && [ ${ssh_port} != '22' ]; then
			semanage port -d -t ssh_port_t -p tcp ${ssh_port}
		fi
		echo -e "${Info}SSH防火墙已重启！"
	fi
	echo -e "${Info}已将SSH端口修改为：$(red_font $SSH_PORT)"
	echo -e "\n${Info}按任意键返回主页..."
	char=`get_char`
	start_menu_main
}

#设置Root密码
set_root(){
	clear
	white_font "\n     ————胖波比————\n"
	yello_font '——————————————————————————'
	green_font ' 1.' '  使用高强度随机密码'
	green_font ' 2.' '  输入自定义密码'
	yello_font '——————————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 3.' '  退出脚本'
	yello_font "——————————————————————————\n"
	read -p "请输入数字[0-3](默认:1)：" num
	[ -z "${num}" ] && num=1
	case "$num" in
		0)
		start_menu_main
		;;
		1)
		pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom | head -c 17)
		;;
		2)
		read -p "请设置密码(默认:pangbobi)：" pw
		[ -z "${pw}" ] && pw="pangbobi"
		;;
		3)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-3]"
		sleep 2s
		set_root
		;;
	esac
	echo root:${pw} | chpasswd
	# 启用root密码登陆
	sed -i '1,/PermitRootLogin/{s/.*PermitRootLogin.*/PermitRootLogin yes/}' /etc/ssh/sshd_config
	sed -i '1,/PasswordAuthentication/{s/.*PasswordAuthentication.*/PasswordAuthentication yes/}' /etc/ssh/sshd_config
	# 重启ssh服务
	if [[ ${release} == "centos" ]]; then
		service sshd restart
	else
		service ssh restart
	fi
	echo -e "\n${Info}您的密码是：$(red_font $pw)"
	echo -e "${Tip}请务必记录您的密码！然后任意键返回主页"
	char=`get_char`
	start_menu_main
}

#系统性能测试
test_sys(){
	#千影大佬的脚本
	qybench(){
		wget --no-check-certificate -qO- https://raw.githubusercontent.com/chiakge/Linux-Server-Bench-Test/master/linuxtest.sh && chmod +x linuxtest.sh
		clear
		white_font "\n 系统性能一键测试综合脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '————————————性能测试————————————'
		green_font ' 1.' '  运行(不含UnixBench)'
		green_font ' 2.' '  运行(含UnixBench)'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 3.' '  返回上页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		read -p "请输入数字[0-4](默认:4)：" num
		[ -z "${num}" ] && num=4
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			bash linuxtest.sh
			;;
			2)
			bash linuxtest.sh a
			;;
			3)
			start_menu_bench
			;;
			4)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
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
			echo " ========================================================= "
			echo " \                 Superbench.sh  Script                 / "
			echo " \       Basic system info, I/O test and speedtest       / "
			echo " \                   v1.1.5 (14 Jun 2019)                / "
			echo " \                   Created by Pangbobi                 / "
			echo " ========================================================= "
			echo -e "\n ${RED}Happy New Year!${PLAIN}\n"
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
		white_font "\n 系统性能一键测试脚本 \c" && red_font "[v${sh_ver}]"
		white_font "	-- 胖波比 --\n"
		yello_font '————————————性能测试————————————'
		green_font ' 1.' '  执行全局测试'
		green_font ' 2.' '  执行国际测试'
		green_font ' 3.' '  执行国内三网测试'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 4.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		read -p "请输入数字[0-4](默认:2)：" num
		[ -z "${num}" ] && num=2
		case "$num" in
			0)
			start_menu_main
			;;
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
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-4]"
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
		if [[ ${release} == "centos" ]]; then
			yum install -y xz openssl gawk file
		elif [[ ${release} == "debian" || ${release} == "ubuntu" ]]; then
			apt-get update
			apt-get install -y xz-utils openssl gawk file	
		fi
	}
	# 安装系统
	InstallOS(){
		clear
		TYPE=$1
		echo -e "\n${Info}重装系统需要时间,请耐心等待..."
		echo -e "${Tip}重装完成后,请用root身份从22端口连接服务器！\n"
		white_font '     ————胖波比————'
		yello_font '—————————————————————————'
		green_font ' 0.' '  返回主页'
		green_font ' 1.' '  使用高强度随机密码'
		green_font ' 2.' '  输入自定义密码'
		yello_font "—————————————————————————\n"
		read -p "请输入数字[0-2](默认:1)：" num
		[ -z "${num}" ] && num=1
		case "$num" in
			0)
			start_menu_main
			;;
			1)
			pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom | head -c 17)
			;;
			2)
			read -p "请设置密码(默认:pangbobi)：" pw
			[ -z "${pw}" ] && pw="pangbobi"
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-2]"
			sleep 2s
			reinstall_sys
			;;
		esac
		echo -e "\n${Info}您的密码是：$(red_font $pw)"
		echo -e "${Tip}请务必记录您的密码！然后任意键继续..."
		char=`get_char`
		if [[ ${model} == "自动" ]]; then
			model="a"
		else 
			model="m"
		fi
		if [[ ${country} == "国外" ]]; then
			country=""
		else 
			if [[ ${os} == "c" ]]; then
				country="--mirror https://mirrors.tuna.tsinghua.edu.cn/centos/"
			elif [[ ${os} == "u" ]]; then
				country="--mirror https://mirrors.tuna.tsinghua.edu.cn/ubuntu/"
			elif [[ ${os} == "d" ]]; then
				country="--mirror https://mirrors.tuna.tsinghua.edu.cn/debian/"
			fi
		fi
		wget --no-check-certificate https://${github}/InstallNET.sh && chmod +x InstallNET.sh
		bash InstallNET.sh -${os} ${TYPE} -v ${vbit} -${model} -p ${pw} ${country}
	}
	# 安装系统
	installadvanced(){
		read -p "请设置参数：" advanced
		wget --no-check-certificate https://${github}/InstallNET.sh && chmod +x InstallNET.sh
		bash InstallNET.sh $advanced
	}

	# 切换位数
	switchbit(){
		if [[ ${vbit} == "64" ]]; then
			vbit="32"
		else
			vbit="64"
		fi
	}
	# 切换模式
	switchmodel(){
		if [[ ${model} == "自动" ]]; then
			model="手动"
		else
			model="自动"
		fi
	}
	# 切换国家
	switchcountry(){
		if [[ ${country} == "国外" ]]; then
			country="国内"
		else
			country="国外"
		fi
	}

	#安装CentOS
	installCentos(){
		clear
		os="c"
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————选择版本————————————'
		green_font ' 1.' '  安装 CentOS6.8系统'
		green_font ' 2.' '  安装 CentOS6.9系统'
		yello_font '————————————切换模式————————————'
		green_font ' 3.' '  切换安装位数'
		green_font ' 4.' '  切换安装模式'
		green_font ' 5.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 6.' '  返回上页'
		green_font ' 7.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-7](默认:6)：" num
		[ -z "${num}" ] && num=6
		case "$num" in
			0)
			start_menu_main
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
			6)
			start_menu_resys
			;;
			7)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-7]"
			sleep 2s
			installCentos
			;;
		esac
	}
	#安装Debian
	installDebian(){
		clear
		os="d"
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————选择版本————————————'
		green_font ' 1.' '  安装 Debian7系统'
		green_font ' 2.' '  安装 Debian8系统'
		green_font ' 3.' '  安装 Debian9系统'
		yello_font '————————————切换模式————————————'
		green_font ' 4.' '  切换安装位数'
		green_font ' 5.' '  切换安装模式'
		green_font ' 6.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 7.' '  返回上页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-8](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			0)
			start_menu_main
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
			7)
			start_menu_resys
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			installCentos
			;;
		esac
	}
	#安装Ubuntu
	installUbuntu(){
		clear
		os="u"
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————选择版本————————————'
		green_font ' 1.' '  安装 Ubuntu14系统'
		green_font ' 2.' '  安装 Ubuntu16系统'
		green_font ' 3.' '  安装 Ubuntu18系统'
		yello_font '————————————切换模式————————————'
		green_font ' 4.' '  切换安装位数'
		green_font ' 5.' '  切换安装模式'
		green_font ' 6.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 7.' '  返回上页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-8](默认:3)：" num
		[ -z "${num}" ] && num=3
		case "$num" in
			0)
			start_menu_main
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
			7)
			start_menu_resys
			;;
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
			sleep 2s
			installCentos
			;;
		esac
	}

	#开始菜单
	start_menu_resys(){
		clear
		white_font "\n 一键网络重装管理脚本 \c" && red_font "[v${sh_ver}]"
		white_font "		  -- 胖波比 --\n"
		yello_font '————————————重装系统————————————'
		green_font ' 1.' '  安装 CentOS系统'
		green_font ' 2.' '  安装 Debian系统'
		green_font ' 3.' '  安装 Ubuntu系统'
		green_font ' 4.' '  高级模式(自定义参数)'
		yello_font '————————————切换模式————————————'
		green_font ' 5.' '  切换安装位数'
		green_font ' 6.' '  切换安装模式'
		green_font ' 7.' '  切换镜像源'
		yello_font '————————————————————————————————'
		green_font ' 0.' '  回到主页'
		green_font ' 8.' '  退出脚本'
		yello_font "————————————————————————————————\n"
		echo -e "当前模式: 安装$(red_font $vbit)位系统,$(red_font $model)模式,$(red_font $country)镜像源.\n"
		read -p "请输入数字[0-8](默认:2)：" num
		[ -z "${num}" ] && num=2
		case "$num" in
			0)
			start_menu_main
			;;
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
			8)
			exit 1
			;;
			*)
			clear
			echo -e "${Error}请输入正确数字 [0-8]"
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
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			echo && read -p "请输入端口号[1-65535]：" port
		done
		add_firewall
		firewall_restart
	}
	delete_firewall_single(){
		until [[ "${port}" -ge "1" && "${port}" -le "65535" ]]
		do
			echo && read -p "请输入端口号[1-65535]：" port
		done
		delete_firewall
		firewall_restart
	}
	delete_firewall_free(){
		if [[ ${release} == "centos" &&  ${version} -ge "7" ]]; then
			port_array=($(firewall-cmd --zone=public --list-ports|sed 's# #\n#g'|grep tcp|sed 's#/tcp##g'))
			length=${#port_array[@]}
			for(( i = 0; i < ${length}; i++ ))
			do
				[[ -z $(lsof -i:${port_array[$i]}) ]] &&  firewall-cmd --zone=public --remove-port=${port_array[$i]}/tcp --remove-port=${port_array[$i]}/udp --permanent >/dev/null 2>&1
			done
		else
			clean_iptables_free(){
				TYPE=$1
				LINE_ARRAY=($(iptables -nvL $TYPE --line-number|grep :|awk -F ':' '{print $2"  " $1}'|awk '{print $2" "$1}'|awk -F ' ' '{print $1}'))
				port_array=($(iptables -nvL $TYPE --line-number|grep :|awk -F ':' '{print $2"  " $1}'|awk '{print $2" "$1}'|awk -F ' ' '{print $2}'))
				length=${#LINE_ARRAY[@]} && t=0
				for(( i = 0; i < ${length}; i++ ))
				do
					if [[ -z $(lsof -i:${port_array[$i]}) ]]; then
						LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$t]
						iptables -D $TYPE ${LINE_ARRAY[$i]}
						t=$[${t}+1]
					fi
				done
			}
			clean_iptables_free INPUT
			clean_iptables_free OUTPUT
			if [ -e /root/test/ipv6 ]; then
				clean_ip6tables_free(){
					TYPE=$1
					LINE_ARRAY=($(ip6tables -nvL $TYPE --line-number|grep :|awk '{printf "%s %s\n",$1,$NF}'|awk -F ' ' '{print $1}'))
					port_array=($(ip6tables -nvL $TYPE --line-number|grep :|awk '{printf "%s %s\n",$1,$NF}'|awk -F ':' '{print $2}'))
					length=${#LINE_ARRAY[@]} && t=0
					for(( i = 0; i < ${length}; i++ ))
					do
						if [[ -z $(lsof -i:${port_array[$i]}) ]]; then
							LINE_ARRAY[$i]=$[${LINE_ARRAY[$i]}-$t]
							ip6tables -D $TYPE ${LINE_ARRAY[$i]}
							t=$[${t}+1]
						fi
					done
				}
				clean_ip6tables_free INPUT
				clean_ip6tables_free OUTPUT
			fi
		fi
		firewall_restart
	}
	delete_firewall_all(){
		echo -e "${Info}开始设置防火墙..."
		if [[ ${release} == "centos" && ${version} -ge "7" ]]; then
			firewall-cmd --zone=public --remove-port=1-65535/tcp --remove-port=1-65535/udp --permanent >/dev/null 2>&1
		else
			iptables -P INPUT ACCEPT
			iptables -F
			iptables -X
			if [ -e /root/test/ipv6 ]; then
				ip6tables -P INPUT ACCEPT
				ip6tables -F
				ip6tables -X
			fi
		fi
		add_firewall_base
		firewall_restart
	}
	clear
	unset port
	white_font "\n Firewall一键管理脚本 \c" && red_font "[v${sh_ver}]"
	white_font "	-- 胖波比 --\n"
	yello_font '————————Firewall管理————————'
	green_font ' 1.' '  开放防火墙端口'
	green_font ' 2.' '  关闭防火墙端口'
	green_font ' 3.' '  关闭空闲端口'
	green_font ' 4.' '  开放所有防火墙'
	green_font ' 5.' '  关闭所有防火墙'
	yello_font '————————————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 6.' '  退出脚本'
	yello_font "————————————————————————————\n"
	read -p "请输入数字[0-6](默认:1)：" num
	[ -z "${num}" ] && num=1
	clear
	case "$num" in
		0)
		start_menu_main
		;;
		1)
		add_firewall_single
		;;
		2)
		delete_firewall_single
		;;
		3)
		delete_firewall_free
		;;
		4)
		add_firewall_all
		;;
		5)
		delete_firewall_all
		;;
		6)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-6]"
		sleep 2s
		set_firewall
		;;
	esac
	set_firewall
}

#远程服务器管理
remote_vps(){
	view_vps(){
		if [ ! -e /root/test/vps_list ]; then
			echo -e "\n${Error}没有添加远程服务器，按任意键添加..."
			char=`get_char`
			add_vps
		fi
		echo '序号 IP地址 SSH端口 用户 登录密码 备注' > /root/test/temp
		cat /root/test/vps_list >> /root/test/temp
		cat /root/test/temp|awk '{print "\033[32m\033[01m"$1"\033[0m","\033[35m\033[01m"$2"\033[0m","\033[33m\033[01m"$3"\033[0m","\033[34m\033[01m"$4"\033[0m","\033[31m\033[01m"$5"\033[0m","\033[37m\033[01m"$6"\033[0m"}'|column -t
		echo && length=$(sed -n '$=' /root/test/vps_list)
		if [[ $1 == '1' ]]; then
			unset line
			until [[ ${line} -ge '1' && ${line} -le "${length}" ]]
			do
				read -p "请输入数字序号[1-${length}]：" line
			done
		fi
	}
	add_vps(){
		if [ -e /root/test/vps_list ]; then
			view_vps '2'
			number=$[${length}+1]
			result=$(cat /root/test/vps_list)
		else
			number=1
			wget -qO sshcopy https://github.com/Jrohy/sshcopy/releases/download/v1.4/sshcopy_linux_386 && chmod +x sshcopy
		fi
		read -p "请输入远程服务器的IP地址：" IP
		if [[ $result =~ "$IP" ]]; then
			echo -e "${Tip}已添加过 ${IP}"
			yello_font '————————————————————'
			green_font ' 1.' '  直接连接'
			green_font ' 2.' '  修改信息'
			yello_font '————————————————————'
			read -p "请选择要对 ${IP} 进行的操作[1-2](默认:1)：" num
			[ -z "${num}" ] && num=1
			clear
			if [[ $num == '2' ]]; then
				modify_vps
			else
				connect_vps
			fi
		fi
		read -p "请输入 ${IP} 的SSH端口：" ssh_port
		read -p "请输入 ${IP} 的登录用户：" user
		read -p "请输入 ${IP} 的登录密码：" passward
		read -p "请添加 ${IP} 的备注：" tips
		./sshcopy -ip $IP -user $user -port $ssh_port -pass $passward
		echo -e "$number $IP $ssh_port $user $passward $tips" >> /root/test/vps_list
	}
	delete_vps(){
		view_vps '1'
		sed -i "${line}d" /root/test/vps_list
	}
	modify_vps(){
		view_vps '1'
		old_info=$(sed -n "${line}p" /root/test/vps_list)
		vps_array=($old_info)
		yello_font '————————————————————'
		green_font ' 1.' '  修改IP地址'
		green_font ' 2.' '  修改SSH端口'
		green_font ' 3.' '  修改用户'
		green_font ' 4.' '  修改密码'
		green_font ' 5.' '  修改备注'
		yello_font '————————————————————'
		read -p "请选择要修改的类别[1-5](默认:1)：" num
		[ -z "${num}" ] && num=1
		read -p "要修改 ${vps_array[$num]} 为：" new_info
		vps_array[$num]=$new_info
		new_info=$(echo ${vps_array[@]})
		sed -i "s/${old_info}/${new_info}/g" /root/test/vps_list
		if [[ $num != '5' ]]; then
			IP=${vps_array[1]}
			ssh_port=${vps_array[2]}
			user=${vps_array[3]}
			passward=${vps_array[4]}
			./sshcopy -ip $IP -user $user -port $ssh_port -pass $passward
		fi
		yello_font '————————————————————'
		green_font ' 1.' '  继续修改'
		green_font ' 2.' '  返回上页'
		yello_font '————————————————————'
		read -p "请输入数字[1-2](默认:1)：" num
		if [[ $num != '2' ]]; then
			clear
			modify_vps
		else
			remote_vps
		fi
	}
	connect_vps(){
		view_vps '1'
		echo -e "${Info}输入命令 exit 退出远程服务器，按任意键继续..."
		char=`get_char`
		vps_array=($(sed -n "${line}p" /root/test/vps_list))
		IP=${vps_array[1]}
		ssh_port=${vps_array[2]}
		user=${vps_array[3]}
		ssh -p $ssh_port ${user}@${IP}
	}
	clear
	white_font "\n远程服务器一键管理脚本 \c" && red_font "[v${sh_ver}]"
	white_font "	-- 胖波比 --\n"
	yello_font '———————远程服务器管理———————'
	green_font ' 1.' '  连接远程服务器'
	yello_font '————————————————————————————'
	green_font ' 2.' '  添加远程服务器'
	green_font ' 3.' '  删除远程服务器'
	green_font ' 4.' '  修改远程服务器'
	yello_font '————————————————————————————'
	green_font ' 0.' '  回到主页'
	green_font ' 5.' '  退出脚本'
	yello_font "————————————————————————————\n"
	read -p "请输入数字[0-5](默认:1)：" num
	[ -z "${num}" ] && num=1
	clear
	case "$num" in
		0)
		start_menu_main
		;;
		1)
		connect_vps
		;;
		2)
		add_vps
		;;
		3)
		delete_vps
		;;
		4)
		modify_vps
		;;
		5)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [0-5]"
		sleep 2s
		remote_vps
		;;
	esac
	remote_vps
}

#管理脚本自启
manage_shell(){
	clear
	white_font "\n     ————胖波比————\n"
	yello_font '——————————————————————————'
	green_font ' 1.' '  开启脚本自启'
	green_font ' 2.' '  关闭脚本自启'
	yello_font "——————————————————————————\n"
	read -p "请输入数字[1-2](默认:1)：" num
	[ -z "${num}" ] && num=1
	if [[ $num == '1' ]]; then
		if [[ `grep -c "./sv.sh" .bash_profile` -eq '0' ]]; then
			echo "./sv.sh" >> /root/.bash_profile
		fi
	elif [[ $num == '2' ]]; then
		sed -i "/sv.sh/d" .bash_profile
	else
		manage_shell
	fi
}

#开始菜单
start_menu_main(){
	clear
	white_font "\n   超级VPN一键设置脚本 \c" && red_font "[v${sh_ver}]"
	white_font '	  -- 胖波比 --'
	white_font '	执行脚本：./sv.sh'
	white_font "   终止正在进行的操作：Ctrl+C\n"
	yello_font '—————————————VPN搭建——————————————'
	green_font ' 1.' '  V2Ray安装管理'
	green_font ' 2.' '  SSR安装管理'
	green_font ' 3.' '  Trojan安装管理'
	green_font ' 4.' '  Naive安装管理'
	yello_font '—————————————节点相关—————————————'
	green_font ' 5.' '  BBR/Lotserver安装管理'
	green_font ' 6.' '  生成订阅链接'
	green_font ' 7.' '  生成链接二维码'
	yello_font '—————————————控制面板—————————————'
	green_font ' 8.' '  宝塔面板安装管理'
	green_font ' 9.' '  临时邮箱安装管理'
	green_font ' 10.' ' ZFAKA安装管理'
	green_font ' 11.' ' SS-Panel安装管理'
	green_font ' 12.' ' Kodexplorer安装管理'
	green_font ' 13.' ' WordPress安装管理'
	green_font ' 14.' ' Docker安装管理'
	yello_font '———————————设置伪装(二选一)———————'
	green_font ' 15.' ' Caddy安装管理'
	green_font ' 16.' ' Nginx安装管理'
	yello_font '—————————————系统设置—————————————'
	green_font ' 17.' ' 设置SSH端口'
	green_font ' 18.' ' 设置root密码'
	green_font ' 19.' ' 系统性能测试'
	green_font ' 20.' ' 重装VPS系统'
	green_font ' 21.' ' 设置防火墙'
	green_font ' 22.' ' 远程服务器管理'
	yello_font '—————————————脚本设置—————————————'
	green_font ' 23.' ' 脚本自启管理'
	green_font ' 24.' ' 退出脚本'
	yello_font "——————————————————————————————————\n"
	read -p "请输入数字[1-24](默认:1)：" num
	[ -z $num ] && num=1
	case $num in
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
		manage_naive
		;;
		5)
		install_bbr
		;;
		6)
		manage_dingyue
		;;
		7)
		manage_qrcode
		;;
		8)
		manage_btpanel
		;;
		9)
		manage_forsakenmail
		;;
		10)
		manage_zfaka
		;;
		11)
		manage_sspanel
		;;
		12)
		manage_kodexplorer
		;;
		13)
		manage_wordpress
		;;
		14)
		manage_docker
		;;
		15)
		install_caddy
		;;
		16)
		install_nginx
		;;
		17)
		set_ssh
		;;
		18)
		set_root
		;;
		19)
		test_sys
		;;
		20)
		reinstall_sys
		;;
		21)
		set_firewall
		;;
		22)
		remote_vps
		;;
		23)
		manage_shell
		;;
		24)
		exit 1
		;;
		*)
		clear
		echo -e "${Error}请输入正确数字 [1-24]"
		sleep 2s
		start_menu_main
		;;
	esac
	start_menu_main
}

check_sys
test ! -e /root/test/de || start_menu_main
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error}本脚本不支持当前系统！" && exit 1
#判断是否支持IPV6
[ ! -z $(wget -qO- -t1 -T2 ipv6.icanhazip.com) ] && echo $(wget -qO- -t1 -T2 ipv6.icanhazip.com) > /root/test/ipv6
if [[ ${release} == 'centos' ]]; then
	if [[ ${version} -ge '7' ]]; then
		systemctl start firewalld
		systemctl enable firewalld
	else
		service iptables save
		chkconfig --level 2345 iptables on
		if [ -e /root/test/ipv6 ]; then
			service ip6tables save
			chkconfig --level 2345 ip6tables on
		fi
	fi
else
	mkdir -p /etc/network/if-pre-up.d
	iptables-save > /etc/iptables.up.rules
	echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
	if [ -e /root/test/ipv6 ]; then
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '/sbin/ip6tables-restore < /etc/ip6tables.up.rules' >> /etc/network/if-pre-up.d/iptables
	fi
	chmod +x /etc/network/if-pre-up.d/iptables
fi
echo 'export LANG="en_US.UTF-8"' >> /root/.bash_profile
add_firewall_base
#是阿里云则卸载云盾
org=$(wget -qO- -t1 -T2 https://ipapi.co/org)
if [[ ${org} =~ 'Alibaba' ]]; then
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
${PM} update
${PM} -y install jq qrencode sshpass nodejs openssl git bash curl wget zip unzip gcc automake autoconf make libtool ca-certificates vim
if [[ ${release} == 'centos' ]]; then
	yum -y install libnss3.so epel-release python36 openssl-devel
	if [[ ${version} == '8' ]]; then
		yum -y install python-pip
	else
		yum -y install python3-pip
	fi
else
	apt --fix-broken install
	apt -y install libnss3 python python-pip python-setuptools libssl-dev
fi
mkdir -p /root/test && touch /root/test/de
#添加地区信息
country=$(curl -s https://ipapi.co/country/)
sed -i "s#${myinfo}#${country}-${myinfo}#g" sv.sh
if [[ `pwd` != '/root' ]]; then
	cp sv.sh /root/sv.sh
	chmod +x /root/sv.sh
fi
exec ./sv.sh