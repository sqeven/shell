yum -y update
yum -y install wget screen curl python zsh git socat gcc python-devel python-pip
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
wget --no-check-certificate https://github.com/sqeven/shell/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh