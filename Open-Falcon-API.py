#!/usr/bin/python
#coding:utf-8

import re
import os
import json
import time
import logging
import requests

class OFALCON_API(object):

    def __init__(self, host, port, username, password):
        """
            host：Open-Falcon的主机IP或域名
        username：用户名
        password：密码
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.log()
        self.token()

    def log(self,logdir="/var/log", level=None, console=True):
        """
        初始化日志
        日志等级：
            DEBUG,INFO,WARNING,ERROR,CRITICAL
        """
        #初始化日志句柄，并设置全局日志等级
        self.logger = logging.getLogger('TSpace')
        self.logger.setLevel(logging.DEBUG)
        #设置日志等级，位置，格式
        level = eval("logging.%s" % level) if level else eval("logging.%s" % "DEBUG")
        logfile = logdir if not os.path.isdir(logdir) else os.path.join(logdir,"Open-Falcon-API.log")
        formatter = logging.Formatter(fmt="%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s - %(message)s")
        #是否控制台打印
        if console:
            console = logging.StreamHandler()
            console.setLevel(level)
            console.setFormatter(formatter)
            self.logger.addHandler(console)
        #保存到日志文件
        filehandler = logging.FileHandler(logfile)
        filehandler.setLevel(level)
        filehandler.setFormatter(formatter)
        self.logger.addHandler(filehandler)

        return self
    
    def request(self, uri, data, method="POST", is_token=False):
        header = {}
        if not is_token:
            header = {"Apitoken":json.dumps({"name":self.username,"sig":self.__token})}
        uri = uri.strip("/")
        url = "http://{ip}:{port}/{uri}".format(ip=self.host,port=self.port,uri=uri)
        base = {
                 'headers': header,
                 'timeout': 30,
                 'url': url,
                 'params': data
                }
        try:
            if method == "GET":
                response = requests.get(**base)
            else:
                response = requests.post(**base)
            msg = json.loads(response.text)
        except BaseException as e:
            msg = e
        return {"msg":msg}
            
    def token(self):
        """
        根据用户名和密码获取token
        """
        uri = "api/v1/user/login"
        data = {"name":self.username,"password":self.password}
        ret = self.request(uri,data,is_token=True)
        try:
            self.__token = ret["msg"]["sig"]
        except:
            self.logger.debug({"method":"token","info":ret["msg"]})

    def get_endpointid_by_ip_or_endpoint(self,endpoint_or_ip):
        """
        通过ip或者endpoint获取endpointid
        注意：该接口endpoint_or_ip参数支持模糊匹配，但不建议进行模糊查询
        """
        uri = "api/v1/graph/endpoint"
        data = {"q":endpoint_or_ip}
        ret = self.request(uri, data, "GET")
	try:
            return ret["msg"][0]
        except:
            self.logger.debug({"method":"get_endpointid_by_ip_or_endpoint","info":ret["msg"]})

    def get_endpoint_counter_by_endpointid(self,endpointid):
        """
        通过endpointid获取该endpoint所有监控项(counter)
        """
        uri = "api/v1/graph/endpoint_counter"
        data = {"eid":endpointid}
        ret = self.request(uri,data,"GET")
        try:
            return ret["msg"]
        except:
            self.logger.debug({"method":"get_endpoint_counter_by_endpointid","info":ret["msg"]})

    def get_history_by_counters_and_endpoints_or_ips(self, counters, endpoints_or_ips, stime, etime, consol_fun="AVERAGE", step=60):
        """
        通过endpoints(或者ip)和counters获取stime到etime之间的监控数据，间隔为step，其中，endpoints(或者ip)为列表，可以为多个，counters为列表，可以为多个
        """
        endpoints = []
        if not isinstance(endpoints_or_ips,list):
            endpoints_or_ips = [endpoints_or_ips]
        cIP = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        for each in endpoints_or_ips:
            if cIP.match(each):
                endpoints.append(self.get_endpointid_by_ip_or_endpoint(each)["endpoint"])
            else:
                endpoints.append(each)
        uri = "api/v1/graph/history"
        data = {
               "Step": step,
               "StartTime": stime,
               "EndTime": etime,
               "HostNames": endpoints,
               "Counters": counters,
               "ConsolFun": consol_fun,
               }
        ret = self.request(uri,data)
        try:
            return ret["msg"]
        except:
            self.logger.debug({"method":"get_history_by_counters_and_endpoints_or_ips","info":ret["msg"]})

if __name__ == "__main__":
    ofalcon = OFALCON_API("192.168.183.130", "8080", "TSpace", "yourpassword")
    endpointinfo = ofalcon.get_endpointid_by_ip_or_endpoint("OFacon")
    #print(endpointinfo)
    endpointid = endpointinfo["id"]
    #print(endpointid)
    endpoint_counter = ofalcon.get_endpoint_counter_by_endpointid(endpointid)
    #print(endpoint_counter)
    history_graph = ofalcon.get_history_by_counters_and_endpoints_or_ips(["agent.alive","cpu.busy"],["server","127.0.0.1"],etime=1537323834, stime=1537320276)
    from pprint import pprint
    pprint(history_graph)
