#!/usr/bin/env bash
yum -y update
# step 1: 安装必要的一些系统工具
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
# Step 2: 添加软件源信息
sudo yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
# Step 3: 更新并安装 Docker-CE
sudo yum makecache fast
sudo yum -y install docker-ce
# Step 4: 开启Docker服务
sudo service docker start
sleep 3
#配置镜像加速器
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": ["https://snnzfpin.mirror.aliyuncs.com"]
}
EOF
#防止虚拟机重启docker网络异常
sudo tee /etc/sysctl.conf <<-'EOF'
net.ipv4.ip_forward=1
EOF
systemctl restart network
sleep 10
#重启docker 服务
sudo systemctl daemon-reload
sleep 3
sudo systemctl restart docker
sleep 15
#下载pxc镜像
docker pull percona/percona-xtradb-cluster
#改名
docker tag percona/percona-xtradb-cluster pxc
#创建网段
docker network create --subnet=172.168.0.0/16 net-pxc
#创建数据卷
docker volume create --name v1
docker volume create --name v2
docker volume create --name v3
docker volume create --name v4
docker volume create --name v5
#创建mysql备份数据卷
docker volume create --name backup
#启动节点node1
sleep 5
docker run -d -p 3306:3306 -v v1:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=root -e CLUSTER_NAME=pxc -e XTRABACKUP_PASSWORD=root --privileged --name=node1 --net=net-pxc --ip=172.168.0.2 pxc
sleep 120
docker run -d -p 3307:3306 -v v2:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=root -e CLUSTER_NAME=pxc -e XTRABACKUP_PASSWORD=root -e CLUSTER_JOIN=node1 --privileged --name=node2 --net=net-pxc --ip=172.168.0.3 pxc
sleep 30
docker run -d -p 3308:3306 -v v3:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=root -e CLUSTER_NAME=pxc -e XTRABACKUP_PASSWORD=root -e CLUSTER_JOIN=node1 --privileged --name=node3 --net=net-pxc --ip=172.168.0.4 pxc
sleep 30
docker run -d -p 3309:3306 -v v4:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=root -e CLUSTER_NAME=pxc -e XTRABACKUP_PASSWORD=root -e CLUSTER_JOIN=node1 --privileged --name=node4 --net=net-pxc --ip=172.168.0.5 pxc
sleep 30
docker run -d -p 3310:3306 -v v5:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=root -e CLUSTER_NAME=pxc -e XTRABACKUP_PASSWORD=root -e CLUSTER_JOIN=node1 --privileged --name=node5 --net=net-pxc --ip=172.168.0.6 pxc

