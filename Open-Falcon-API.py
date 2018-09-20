#!/usr/bin/python
#coding:utf-8

import re
import os
import json
import time
import logging
import requests

def log(logdir="/var/log", level=None, console=True):
    """
    初始化日志
    日志等级：
        DEBUG,INFO,WARNING,ERROR,CRITICAL
    """
    #初始化日志句柄，并设置全局日志等级
    logger = logging.getLogger('TSpace')
    logger.setLevel(logging.DEBUG)
    #设置日志等级，位置，格式
    level = eval("logging.%s" % level) if level else eval("logging.%s" % "DEBUG")
    logfile = logdir if not os.path.isdir(logdir) else os.path.join(logdir,"Open-Falcon-API.log")
    formatter = logging.Formatter(fmt="%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s - %(message)s")
    #是否控制台打印
    if console:
        console = logging.StreamHandler()
        console.setLevel(level)
        console.setFormatter(formatter)
        logger.addHandler(console)
    #保存到日志文件
    filehandler = logging.FileHandler(logfile)
    filehandler.setLevel(level)
    filehandler.setFormatter(formatter)
    logger.addHandler(filehandler)
    return logger

def wap(fun):
    def wrapper(*args,**kw):
        ret = fun(*args, **kw)
        if ret["code"] != 200:
            logger.debug({"method":"%s()" % fun.__name__,"info":ret["msg"]})
        else:
            return ret["msg"]
    return wrapper

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
        self.token()

    def request(self, uri, data, request_method, is_token=False):
        header = {}
        if not is_token:
            try:
                header = {"Apitoken":json.dumps({"name":self.username,"sig":self.__token})}
            except BaseException as e:
                logger.debug({"method":"request()","info":e})
        uri = uri.strip("/")
        url = "http://{ip}:{port}/{uri}".format(ip=self.host,port=self.port,uri=uri)
        base = {
                 'headers': header,
                 'timeout': 30,
                 'url': url,
                 'params': data
                }
        try:
            if request_method == "GET":
                response = requests.get(**base)
            elif request_method == "POST":
                response = requests.post(**base)
            else:
                return {"code": 400, "msg":u"Argument request_method should be POST or GET"}
            msg = json.loads(response.text)
            code = response.status_code
        except BaseException as e:
            msg = e
            code = 400
        return {"code": code, "msg": msg}
            
    def token(self):
        """
        根据用户名和密码获取token
        """
        uri = "api/v1/user/login"
        data = {"name":self.username,"password":self.password}
        ret = self.request(uri,data,"POST",is_token=True)
        try:
            self.__token = ret["msg"]["sig"]
        except:
            logger.debug({"method":"token","info":ret["msg"]})
    @wap
    def get_endpointid_by_ip_or_endpoint(self,endpoint_or_ip):
        """
        通过ip或者endpoint获取endpointid
        注意：该接口endpoint_or_ip参数支持模糊匹配，但不建议进行模糊查询
        """
        uri = "api/v1/graph/endpoint"
        data = {"q":endpoint_or_ip}
        return self.request(uri, data, "GET")

    @wap
    def get_endpoint_counter_by_endpointid(self,endpointid):
        """
        通过endpointid获取该endpoint所有监控项(counter)
        """
        uri = "api/v1/graph/endpoint_counter"
        data = {"eid":endpointid}
        return self.request(uri,data,"GET")
    
    @wap
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
                endpoints.append(self.get_endpointid_by_ip_or_endpoint(each)[0]["endpoint"])
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
        return self.request(uri,data,"POST")

    @wap
    def add_hostgroup(self,hostgroup):
        """
        增加主机组
        """
        uri = "api/v1/hostgroup"
        data = {"Name":hostgroup}
        return self.request(uri,data,"POST1")

    @wap
    def add_host_to_hostgroup(self, hosts, hostgroup_id):
        """
        增加主机到主机组,hosts为列表,注意：Hosts每次都会覆盖该HostGroup内现有的Host List，而且使用者不是Admin的话只能对创建的hostgroup做操作
        """
        uri = "api/v1/hostgroup/host"
        data = {"Hosts": hosts, "HostGroupID":hostgroup_id}
        return self.request(uri,data,"POST")

    @wap
    def get_hostgrouplist(self,):
        """
        获取主机组列表，内含主机组ID信息
        """
        uri = "api/v1/hostgroup"
        data = {}
        return self.request(uri,data,"GET")
    
    @wap
    def get_hostgroupinfo_by_id(self,hostgroupid):
        """
        通过主机组ID获取该主机组信息，内含主机组下所有主机
        """
        uri = "api/v1/hostgroup/{hostgroupid}".format(hostgroupid=str(hostgroupid))
        data = {}
        return self.request(uri,data,"GET")
    
    @wap
    def add_template(self,templatename,parent_id=0):
        """
        增加模板，templatename为模板名，parent_id为父模板ID，默认0表示无父模板
        """
        uri = "api/v1/template"
        data = {"Name": templatename, "ParentID": parent_id}
        return self.request(uri, data, "POST")

    @wap
    def get_templatelist(self):
        """
        获取所有模板的列表
        """
        uri = "api/v1/template"
        data = {}
        return self.request(uri, data, "GET")

    @wap 
    def add_strategy_to_template_by_templateid(self, templateid, metric, op, right_value, func, priority=1, max_step=3, note="", tags="", run_begin="00:00", run_end="24:00"):
        """
        为一个模板添加告警项
        """
        uri = "api/v1/strategy"
        data = {"TplId": templateid, "Tags": tags, "RunEnd": run_end, "RunBegin": run_begin, "RightValue": right_value, "Priority": priority, "Op": op, "Note": note, "Metric": metric, "MaxStep": max_step, "Func": func}
        return self.request(uri, data, "POST")

    @wap
    def add_template_to_hostgroup(self,templateid, hostgroupid):
        """
        给hostgroup绑定一个template
        """
        uri = "api/v1/hostgroup/template"
        data = {"TplId": templateid, "GrpId": hostgroupid}
        return self.request(uri, data, "POST")

    @wap
    def add_team(self,team_name, users, resume=""):
        """
        team_name: string，用户组名
            users:   list，用户
           resume: string, 描述信息，对于该用户组的描述，默认为空 
        """
        uri = "api/v1/team"
        data = {"Name": team_name, "UserIDs": users, "Resume": resume}
        return self.request(uri, data, "POST")

    @wap
    def get_current_userinfo(self):
        """
        获取当前token所指的用户信息
        """
        uri = "api/v1/user/current"
        data = {}
        return self.request(uri, data, "GET")

if __name__ == "__main__":
    logger = log()
    ofalcon = OFALCON_API("192.168.183.130", "8080", "TSpace", "duoyi")
    #endpointinfo = ofalcon.get_endpointid_by_ip_or_endpoint("OFacon")
    #print(endpointinfo)
    #endpointid = endpointinfo[0]["id"]
    #print(endpointid)
    #endpoint_counter = ofalcon.get_endpoint_counter_by_endpointid(endpointid)
    #print(endpoint_counter)
    #history_graph = ofalcon.get_history_by_counters_and_endpoints_or_ips(["agent.alive","cpu.busy"],["server","127.0.0.1"],etime=1537323834, stime=1537320276)
    #from pprint import pprint
    #pprint(history_graph)
    #hostgroup = ofalcon.add_hostgroup("testhostgroup")
    #print(hostgroup)
    #print(ofalcon.add_host_to_hostgroup(["OFacon","server"],1))
    #print(ofalcon.get_hostgrouplist())
    #print(ofalcon.get_hostgroupinfo_by_id(1))
    #print(ofalcon.add_template("testtemplate1",1))
    #print(ofalcon.get_templatelist())
    #print(ofalcon.add_strategy_to_template_by_templateid(2,"cpu.free",">=","40","all(#3)",1,3,"this is test","","01:00","23:00")) 
    #print(ofalcon.add_template_to_hostgroup(2,1))
    print(ofalcon.add_team("test4userteam",[1],"I'm descript"))
    #print(ofalcon.get_current_userinfo())
