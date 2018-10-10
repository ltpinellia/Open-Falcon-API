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
        self.logger = self.log()
        wap = self.wap()
        self.token()

    def log(self,logdir="/var/log", level=None, console=True):
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
        logger = logging.getLogger('TSpace')
        def wrapper(*args,**kw):
            ret = fun(*args, **kw)
            if ret["code"] != 200:
                logger.debug({"method":"%s()" % fun.__name__,"info":ret["msg"]})
            else:
                return ret["msg"]
        return wrapper

    def request(self, uri, data, request_method, is_token=False, trans="params"):
        header = {}
        if not is_token:
            try:
                header = {"Apitoken":json.dumps({"name":self.username,"sig":self.__token})}
            except BaseException as e:
                self.logger.debug({"method":"request()","info":e})
        uri = uri.strip("/")
        url = "http://{ip}:{port}/{uri}".format(ip=self.host,port=self.port,uri=uri)
        base = {
                 'headers': header,
                 'timeout': 30,
                 'url': url,
                 trans: data,
                }
        
        try:
            if request_method == "GET":
                response = requests.get(**base)
            elif request_method == "POST":
                response = requests.post(**base)
            elif request_method == "PATCH":
                response = requests.patch(**base)
            elif request_method == "DELETE":
                response = requests.delete(**base)
            elif request_method == "PUT":
                response = requests.put(**base)
            else:
                return {"code": 400, "msg":u"Argument request_method should be POST, GET, PATCH or PUT"}
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
            self.logger.debug({"method":"token()","info":ret["msg"]})
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
                try:
                    endpoints.append(self.get_endpointid_by_ip_or_endpoint(each)[0]["endpoint"])
                except:
                    endpoints = endpoints
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
        return self.request(uri,data,"POST")

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
        metric：监控项名                     string
        op："==","!=","<","<=",">",">="      string
        right_value：阈值                    string
        func：函数，all(#3等等               string
        priority：告警等级                   int
        max_step：                           int
        note：告警信息                       string
        tags：标记                           string
        run_begin：告警时间                  string
        run_end：告警时间                    string
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

    @wap
    def get_eventcases_list(self,endTime=None,limit=None,process_status=None,startTime=None,status=None,endpoints=None,strategy_id=None,template_id=None):
        """
        获取EventCases List
        注意:
            参数不可以全部为空
        参数:
            endTime: 结束时间,int类型,例如int(time.time())
            limit: 限制返回数据个数,int类型
            process_status: string类型,共有三种状态,resolved,ignored,unresolved。默认值为unresolved。该状态为告警管理预留字段，该功能目前还没上线。所以该字段一定为默认值unresolved，不会变化。
            startTime: 开始时间,int类型,例如int(time.time())
            status: 状态值，共有两种：PROBLEM,OK。string类型
            endpoints: 节点,list类型，例如["endpoint1","endpoint2"]
            strategy_id: 告警项ID，int类型
            template_id: 模板ID，int类型
        示例:
            data = {"startTime":0,"endTime":1538190980}  获取这个时间段内所有的告警
            data = {"template_id":5}  获取该模板的所有相关告警
            data = {"template_id":5,"startTime":0,"endTime":1538190980,"endpoints":["5351"],"limit":5}   获取这个时间段的这个endpoint的这个模板的相关告警，最多只显示5个 """
        uri = "api/v1/alarm/eventcases"
        data = {"endTime":endTime,"limit":limit,"process_status":process_status,"startTime":startTime,"status":status,"endpoints":endpoints,"strategy_id":strategy_id,"template_id":template_id}
        return self.request(uri, data, "POST")

    @wap
    def get_eventcases_by_id(self,event_id):
        """
        通过event_id获取eventcases信息
        """
        uri = "api/v1/alarm/eventcases"
        data = {"event_id":event_id}
        return self.request(uri, data, "GET")

    @wap
    def get_eventnote_by_time_or_eventid(self,endTime=None,startTime=None,event_id=None,status=None,limit=None,page=None):
        """
        通过时间段或者eventID获取eventnote
        注意：
        event_id和time相关字段可为空但不可都为空
        参数：
        startTime: 开始区间
        endTime: 结束区间
        status: 告警状态,如果该参数不为空，则表示取与该参数相关的eventnote信息 ["in progress", "unresolved", "resolved", "ignored", "comment"]
        event_id: 对应某一单向告警id
        limit: 设定返回上限 [预设及最大上线值:50]
        page: 后端分页页数
        """
        uri = "api/v1/alarm/event_note"
        data = {"event_id":event_id,"startTime":startTime,"endTime":endTime,"limit":10}
        return self.request(uri, data, "GET")

    @wap
    def create_eventnote(self,event_id,note,status,case_id=None):
        """
        使用者可以对告警留言并人工切换状态
        status: 人工判定告警状态 [“in progress”, “unresolved”, “resolved”, “ignored”, “comment”], comment之外的留言会改变event_case的process_status状态
        note: 对于告警留言
        case_id: 填入外部对应的系统公单号
        """
        uri = "api/v1/alarm/event_note"
        data = {"event_id":event_id,"note":note,"status":status,"case_id":case_id}
        return self.request(uri, data, "POST")

    @wap
    def get_event(self,event_id ,startTime=None,endTime=None):
        """
        获取该event_id对应告警项的所有告警时的状态值
        """
        uri = "api/v1/alarm/events"
        data = {"event_id":event_id, "startTime": startTime, "endTime": endTime}
        return self.request(uri, data, "POST")
    
    @wap
    def update_hosts_in_hostgroup(self,hostgroupid,action,hostslist):
        """
        更新已存主机组内主机
        hostgroupid：主机组ID
        action：两种,add，remove
        hostslist：需要新增进该主机组或者从该主机组里移除的主机列表
        """
        uri = "api/v1/hostgroup/{hostgroupid}/host".format(hostgroupid=str(hostgroupid))
        data = {"Action":action, "Hosts": hostslist}
        return self.request(uri, data, "PATCH")

    @wap
    def update_user(self,cnname,email,im=None,phone=None,qq=None):
        """
        更新当前用户信息
        """
        uri = "api/v1/user/update"
        data = {"Cnname":cnname, "Email":email,"im":im, "phone":phone, "qq": qq}
        return self.request(uri, data, "PUT")

    @wap
    def logout(self):
        """
        登出当前用户
        """
        uri = "api/v1/user/logout"
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_userlist(self):
        """
        获取用户列表
        """
        uri = "api/v1/user/users"
        data = {} 
        return self.request(uri, data, "GET")

    @wap
    def check_user_in_teams(self,userid,teams):
        """
        判断用户是否在某个组内
        """
        if isinstance(teams,list):
            teams = ",".join(teams)
        uri = "api/v1/user/u/{userid}/in_teams".format(userid=str(userid))
        data = {"team_names":teams}
        return self.request(uri, data, "GET")

    @wap
    def get_user_teams(self, userid):
        """
        获取该用户所在的组
        """
        uri = "api/v1/user/u/{userid}/teams".format(userid=str(userid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_user_info_by_name(self, username):
        """
        通过用户名获取用户信息
        """
        uri = "/api/v1/user/name/{user_name}".format(user_name=username)
        data = {}
        return self.request(uri, data, "GET")
 
    @wap
    def get_user_info_by_id(self, userid):
        """
        通过用户ID获取用户信息
        """
        uri = "/api/v1/user/u/{user_id}".format(user_id=userid)
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def create_user(self, name, password, cnname, email, im=None, phone=None, qq=None):
        """
        创建新用户
        """
        uri = "api/v1/user/create"
        data = {"Name":name,"Passwd":password,"Cnname":cnname,"Email":email, "IM":im, "Phone": phone, "QQ": qq}
        return self.request(uri, data, "POST")

    @wap
    def change_user_passwd(self, old_passwd, new_passwd):
        """
        修改当前用户密码
        """
        uri = "/api/v1/user/cgpasswd"
        data = {"old_password":old_passwd,"new_password":new_passwd}
        return self.request(uri, data, "PUT")

    @wap
    def update_template_by_tmpid(self, tpl_id, name, parent_id=0):
        """
        通过tpl_id更新template名或者父模板ID
        """
        uri = "api/v1/template"
        data = {"tpl_id":tpl_id, "name": name, "parent_id": parent_id}
        return self.request(uri, data, "PUT")

    @wap
    def get_templateinfo_by_tmpid(self, tpl_id):
        """
        通过tpl_id获取template信息,包括监控项配置等等
        """
        uri = "api/v1/template/{template_id}".format(template_id=tpl_id)
        data = {}
        return self.request(uri, data, "GET")

    @wap 
    def get_hostgrouplist_by_tmpid(self, tpl_id):
        """
        通过tpl_id获取某一模板绑定的主机组
        """
        uri = "api/v1/template/{template_id}/hostgroup".format(template_id=tpl_id)
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def delete_template(self, tpl_id):
        """
        通过tpl_id删除该模板
        """
        uri = "api/v1/template/{template_id}".format(template_id=tpl_id)
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def create_template_action(self,tpl_id,uic,url="",callback=0,before_callback_sms=0,before_callback_mail=0,after_callback_sms=0,after_callback_mail=0):
        """
        创建模板动作
        tpl_id：模板ID
        uic：需要告警的组,string类型，如果有多个则用逗号分割
        callback：是否启用回调，1 启用，0 不启用
        url：回调调用的url
        before_callback_sms：回调之前发送sms，1 启用，0 不启用
        before_calllback_mail：回调之前发送邮件
        after_callback_sms：回调之后发送sms
        after_callback_mail：回调之后发送邮件
        """
        uri = "api/v1/template/action"
        if isinstance(uic,list):
            uic = ",".join(uic)
        data = {"TplId":tpl_id,"UIC":uic,"Callback":callback,"URL":url,"BeforeCallbackSMS":before_callback_sms,"BeforeCallbackMail":before_callback_mail,"AfterCallbackSMS":after_callback_sms,"AfterCallbackMail":after_callback_mail}
        return self.request(uri, data, "POST")

    @wap
    def update_template_action(self,actionid,uic,url,callback,before_callback_sms,before_callback_mail,after_callback_sms,after_callback_mail):
        """
        通过actionid更新action，actionid可以通在模板详细信息中获取
        """
        uri = "api/v1/template/action"
        if isinstance(uic,list):
            uic = ",".join(uic)
        data = {"ID":actionid,"UIC":uic,"Callback":callback,"URL":url,"BeforeCallbackSMS":before_callback_sms,"BeforeCallbackMail":before_callback_mail,"AfterCallbackSMS":after_callback_sms,"AfterCallbackMail":after_callback_mail}
        return self.request(uri, data, "PUT")
        
    @wap
    def update_team(self,team_id,name,resume,users):
        """
        更新team信息
        users: 属於该群组的user id list, user id 为int类型
        resume: team的描述
        name: team的名字
        除Admin外, 使用者只能更新自己创建的team
        """    
        uri = "api/v1/team"
        data = {"team_id":team_id,"name":name,"resume":resume,"users":users}
        return self.request(uri, data, "PUT")

    @wap
    def get_team_list(self,team_name):
        """
        获取team信息，支持模糊搜索
        q: 使用 regex 查询字符, 查询team name, .+ 表示查询所有
        """
        uri = "api/v1/team"
        data = {"q":team_name}
        return self.request(uri, data, "GET")

    @wap
    def get_teaminfo_by_name(self,team_name):
        """
        根据team_name获取teaminfo
        """
        uri = "api/v1/team/name/{team_name}".format(team_name=team_name)
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_teaminfo_by_teamid(self, team_id):
        """
        根据team id 获取teaminfo
        """
        uri = "api/v1/team/t/{team_id}".format(team_id=str(team_id))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def delete_team_by_teamid(self, team_id):
        """
        通过teamid删除team
        除Admin外, 使用者只能更新自己创建的team
        """
        uri = "api/v1/team/{team_id}".format(team_id=str(team_id))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def update_strategy(self, strategyid, tags, run_end, run_begin, right_value, priority, op, note, metric, max_step, func ):
        """
        通过strategyid更新该strategy信息
        metric：监控项名                     string
        op："==","!=","<","<=",">",">="      string
        right_value：阈值                    string
        func：函数，all(#3等等               string
        priority：告警等级                   int
        max_step：                           int
        note：告警信息                       string
        tags：标记                           string
        run_begin：告警时间                  string
        run_end：告警时间                    string
        """
        uri = "api/v1/strategy"
        data = {"ID":strategyid, "Tags":tags, "RunEnd":run_end, "RunBegin":run_begin, "right_value":right_value, "Priority":priority,"Op":op,"Note":note,"Metric":metric,"max_step":max_step,"Func":func}
        return self.request(uri, data, "PUT")

    @wap
    def get_strategy_list(self,tid):
        """
        通过template id获取该模板下所有strategy
        """
        uri = "api/v1/strategy"
        data = {"tid":tid}
        return self.request(uri, data, "GET")

    @wap
    def get_strategyinfo_by_id(self,strategyid):
        """
        通过strategyid获取该strategy信息
        """
        uri = "api/v1/strategy/{strategy_id}".format(strategy_id=str(strategyid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def delete_strategy(self,strategyid):
        """
        通过strategyid删除该strategy
        """
        uri = "api/v1/strategy/{strategy_id}".format(strategy_id=str(strategyid))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def get_default_metriclist(self):
        """
        获取内置的监控项列表,基于./data/metric文件
        """
        uri = "api/v1/metric/default_list"
        data = {}
        return self.request(uri, data, "GET")
     
    @wap
    def get_pluginlist_by_hostgroupid(self,hostgroupid):
        """
        通过hostgroup id 获取绑定的plugins列表
        """   
        uri = "api/v1/hostgroup/{hostgroup_id}/plugins".format(hostgroup_id=str(hostgroupid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def create_plugin(self, hostgroupid, plugin_dir):
        """
        为一个主机组创建plugin
        plugin_dir：代表plugin所在的目录路径
        """
        uri = "api/v1/plugin"
        data = {"GrpId":hostgroupid,"DirPath":plugin_dir}
        return self.request(uri, data, "POST")

    @wap
    def delete_plugin(self, plugin_id):
        """
        通过plugin id 删除该plugin
        """
        uri = "api/v1/plugin/{plugin_id}".format(plugin_id=plugin_id)
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def create_nodata(self,tags,step,obj_type,obj,name,mock,metric,dstype="GAUGE"):
        """
        创建nodata
        name: nodata名
        obj_type: 有三种，"group","other","host"
        obj：主机组或者主机或者其他的列表，例如：主机组，["grp1","grp2"],主机，["host1","host2"],其他，["10.32.64.12:9000","192.168.1.2:9000"]
        metric：监控项
        tags：标签
        dstype：计算方式，目前只有一种，GAUGE
        step：周期
        mock：数据上报中断时，补发该值
        """
        uri = "api/v1/nodata"
        if isinstance(obj,list):
            obj = "\n".join(obj)
        data = {"Tags":tags,"Step":step,"ObjType":obj_type,"Obj":obj,"Name":name,"Mock":mock,"Metric":metric,"DsType":dstype}
        return self.request(uri, data, "POST")
    
    @wap
    def update_nodata(self,nodataid,tags,step,obj_type,obj,mock,metric,dstype="GAUGE"):
        """
        创建nodata
        nodataid: nodataid
        obj_type: 有三种，"group","other","host"
        obj：主机组或者主机或者其他的列表，例如：主机组，["grp1","grp2"],主机，["host1","host2"],其他，["10.32.64.12:9000","192.168.1.2:9000"]
        metric：监控项
        tags：标签
        dstype：计算方式，目前只有一种，GAUGE
        step：周期
        mock：数据上报中断时，补发该值
        """
        uri = "api/v1/nodata"
        if isinstance(obj,list):
            obj = "\n".join(obj)
        data = {"Tags":tags,"Step":step,"obj_type":obj_type,"Obj":obj,"ID":nodataid,"Mock":mock,"Metric":metric,"DsType":dstype}
        return self.request(uri, data, "PUT")
    
    @wap
    def get_nodata_list(self):
        """
        获取nodata列表
        """
        uri = "api/v1/nodata"
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_nodata_info_by_nodataid(self,nodataid):
        """
        通过nodataid获取nodata信息
        """
        uri = "api/v1/nodata/{nodata_id}".format(nodata_id=str(nodataid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def delete_nodata_by_nodataid(self,nodataid):
        """
        通过nodataid删除nodata
        """
        uri = "api/v1/nodata/{nodata_id}".format(nodata_id=str(nodataid))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def update_hostgroup(self,grpid,name):
        """
        通过hostfgroupid更新hostgroup信息
        """
        uri = "api/v1/hostgroup"
        data = {"ID":grpid,"NameAAA":name}
        return self.request(uri, data, "PUT",trans="json")

    @wap
    def unbind_host_on_hostgroup(self,hostgroupid,hostid):
        """
        将host从hostgroup解绑
        """
        uri = "api/v1/hostgroup/host"
        data = {"hostgroup_id":hostgroupid,"host_id":hostid}
        return self.request(uri, data, "PUT")
    
    @wap
    def unbind_template_on_hostgroup(self,hostgroupid,templateid):
        """
        将template从hostgroup解绑
        """
        uri = "api/v1/hostgroup/template"
        data = {"grp_id":hostgroupid,"tpl_id":templateid}
        return self.request(uri, data, "PUT")

    @wap
    def get_templatelist_of_hostgroup(self,hostgroupid):
        """
        通过该主机组id获取该主机组绑定的模板
        """
        uri = "api/v1/hostgroup/{hostgroup_id}/template".format(hostgroup_id=str(hostgroupid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def delete_hostgroup(self,hostgroupid):
        """
        通过hostgroupid删除该主机组
        """
        uri = "api/v1/hostgroup/{hostgroup_id}".format(hostgroup_id=str(hostgroupid))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def set_maintain_by_ids_or_hostnames(self,hosts_or_ids,stype,maintain_begin,maintain_end):
        """
        设置维修时间
        hosts_or_ids：主机名或者主机ID组成的列表,注意，该ID为数据库的host表里的ID，而不是endpointid(即通过该接口ofalcon.get_endpointid_by_ip_or_endpoint(".+")获取到的ID是不适用的)
        stype：0或者1,0表示使用主机名组成的列表，1表示使用主机ID组成的列表
        maintain_begin：维修开始
        maintain_end：维修结束
        """
        uri = "api/v1/host/maintain"
        if stype:
            data = {"Ids":hosts_or_ids,"Begin":maintain_begin,"End":maintain_end}
        else:
            data = {"Hosts":hosts_or_ids,"Begin":maintain_begin,"End":maintain_end}
        return self.request(uri, data, "POST")

    @wap
    def delete_maintain_by_ids_or_hostnames(self,hosts_or_ids,stype):
        """
        设置维修时间
        hosts_or_ids：主机名或者主机ID组成的列表,注意，该ID为数据库的host表里的ID，而不是endpointid(即通过该接口ofalcon.get_endpointid_by_ip_or_endpoint(".+")获取到的ID是不适用的)
        stype：0或者1,0表示使用主机名组成的列表，1表示使用主机ID组成的列表
        """
        uri = "api/v1/host/maintain"
        if stype:
            data = {"Ids":hosts_or_ids}
        else:
            data = {"Hosts":hosts_or_ids}
        return self.request(uri, data, "DELETE")

    @wap
    def get_related_hostgroup_of_host(self,hostid):
        """
        获取该主机所在的组
        """
        uri = "api/v1/host/{host_id}/hostgroup".format(host_id=str(hostid))
        data = {}
        return self.request(uri, data, "GET")
    

    @wap
    def get_bind_template_of_host(self,hostid):
        """
        获取该主机所绑定的模板
        """
        uri = "api/v1/host/{host_id}/template".format(host_id=str(hostid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def create_expression(self,expression,right_value,priority,pause,op,note,max_step,func,uic,url="",callback=1,before_callback_sms=0,before_callback_mail=0,after_callback_sms=0,after_callback_mail=0):
        """
        创建一个expression
        expression：expression名
        right_value：阈值
        priority：告警等级
        pause：是否暂停,0表示不暂停，1表示暂停
        op："==",">","<"等等
        note：补充信息
        max_step：最大告警次数
        func：告警函数
        url：callback url
        uic：告警组，列表
        callback：是否启用回调，1 启用，0 不启用
        before_callback_sms：回调之前发送sms，1 启用，0 不启用
        before_calllback_mail：回调之前发送邮件
        after_callback_sms：回调之后发送sms
        after_callback_mail：回调之后发送邮件
        """
        uri = "api/v1/expression"
        data = {"Expression":expression,"RightValue":right_value,"Priority":priority,"Pause":pause,"Op":op,"Note":note,"MaxStep":max_step,"Func":func,"UIC":uic,"URL":url,"Callback":callback,"BeforeCallbackSMS":before_callback_sms,"BeforeCallbackMail":before_callback_mail,"AfterCallbackSMS":after_callback_sms,"AfterCallbackMail":after_callback_mail}
        return self.request(uri, data, "POST")

    @wap
    def delete_expression(self,expression_id):
        """
        通过expression_id删除该expression
        """
        uri = "api/v1/expression/{expression_id}".format(expression_id=str(expression_id))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def get_expression_list(self):
        """
        获取expression列表
        """
        uri = "api/v1/expression"
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_expression_info_by_id(self,expression_id):
        """
        通过expression_id获取该expression信息
        """
        uri = "api/v1/expression/{expression_id}".format(expression_id=str(expression_id))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def update_expression(self,expression_id,expression,right_value,priority,pause,op,note,max_step,func,uic,url="",callback=1,before_callback_sms=0,before_callback_mail=0,after_callback_sms=0,after_callback_mail=0):
        """
        创建一个expression
        expression_id：ID
        expression：expression名
        right_value：阈值
        priority：告警等级
        pause：是否暂停,0表示不暂停，1表示暂停
        op："==",">","<"等等
        note：补充信息
        max_step：最大告警次数
        func：告警函数
        url：callback url
        uic：告警组，列表
        callback：是否启用回调，1 启用，0 不启用
        before_callback_sms：回调之前发送sms，1 启用，0 不启用
        before_calllback_mail：回调之前发送邮件
        after_callback_sms：回调之后发送sms
        after_callback_mail：回调之后发送邮件
        """
        uri = "api/v1/expression"
        data = {"ID":expression_id,"Expression":expression,"RightValue":right_value,"Priority":priority,"Pause":pause,"Op":op,"Note":note,"MaxStep":max_step,"Func":func,"UIC":uic,"URL":url,"Callback":callback,"BeforeCallbackSMS":before_callback_sms,"BeforeCallbackMail":before_callback_mail,"AfterCallbackSMS":after_callback_sms,"AfterCallbackMail":after_callback_mail}
        return self.request(uri, data, "PUT", trans="data")

    @wap
    def auth_session(self):
        """
        验证session是否有效
        """
        uri = "api/v1/user/auth_session"
        data = {}
        return self.request(uri, data, "GET")
 
    @wap
    def change_user_role(self,user_id,admin):
        """
        该函数只适用于admin用户
        admin：是否设置为管理员，yes或者no
        """
        uri = "api/v1/admin/change_user_role"
        data = {"user_id":user_id,"admin":admin}
        return self.request(uri, data, "PUT")

    @wap
    def change_user_pwd(self,user_id,newpassword):
        """
        该函数只适用于admin用户
        """
        uri = "api/v1/admin/change_user_passwd"
        data = {"user_id":user_id,"password":newpassword}
        return self.request(uri, data, "PUT")

    @wap
    def delete_user(self,user_id):
        """
        该函数只适用于admin用户
        删除用户
        """
        uri = "api/v1/admin/delete_user"
        data = {"UserID":user_id}
        return self.request(uri, data, "DELETE")

    @wap
    def create_aggregator_to_hostgroup(self,endpoint,metric,tag,step,hostgroup_id,numerator,denominator):
        """
        为一个主机组创建aggregator
        numerator:分子
        denominator:分母
        step:汇报周期,int值
        """

        uri = "api/v1/aggregator"
        data = {"Endpoint":endpoint,"Metric":metric,"Tags":tag,"Step":step,"GrpId":hostgroup_id,"Numerator":numerator,"Denominator":denominator}
        return self.request(uri,data,"POST")

    @wap
    def get_aggregator_by_hostgroupid(self,hostgroupid):
        """
        获取一个主机组内的aggregator
        """
        uri = "api/v1/hostgroup/{hostgroup_id}/aggregators".format(hostgroup_id=hostgroupid)
        data = {}
        return self.request(uri,data,"GET")

    @wap
    def update_aggregator_by_aggregatorid(self,aggregatorid,endpoint,metric,tag,step,numerator,denominator):
        """
        为一个主机组创建aggregator
        numerator:分子
        denominator:分母
        step:汇报周期,int值
        """

        uri = "api/v1/aggregator"
        data = {"ID":aggregatorid,"Endpoint":endpoint,"Metric":metric,"Tags":tag,"Step":step,"Numerator":numerator,"Denominator":denominator}
        return self.request(uri,data,"PUT")

    @wap
    def get_aggregator_by_aggregatorid(self,aggregatorid):
        """
        通过aggregatorid获取该aggregator信息
        """
        uri = "api/v1/aggregator/{aggregatorid}".format(aggregatorid=aggregatorid)
        data = {}
        return self.request(uri,data,"GET")

    @wap
    def delete_aggregator_by_aggregatorid(self,aggregatorid):
        """
        通过aggregatorid删除该aggregator
        """
        uri = "api/v1/aggregator/{aggregatorid}".format(aggregatorid=aggregatorid)
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def create_dashboardscreen(self,name,pid):
        """
        创建dashboardscreen
        pid：父模板ID，0表示第一级screen
        """
        uri = "api/v1/dashboard/screen"
        data = {"name":name,"pid":pid}
        return self.request(uri, data, "POST", trans="data")

    @wap
    def get_dashboardscreen_list(self):
        """
        获取所有的dashboardscreen
        """
        uri = "api/v1/dashboard/screens"
        data = {}
        return self.request(uri,data,"GET")

    @wap
    def get_dashboardscreen_by_pid(self,pid):
        """
        根据dashboardscreen的父id获取所有子screen
        pid：表示父模板ID
        """
        uri = "api/v1/dashboard/screens/pid/{pid}".format(pid=str(pid))
        data = {}
        return self.request(uri, data, "GET")
  
    @wap
    def get_dashboardscreen_by_screenid(self,screenid):
        """
        根据dashboardscreen_screenid获取该dashboardscreen
        screenid：表示screen ID
        """
        uri = "api/v1/dashboard/screen/{screen_pid}".format(screen_pid=str(screenid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def delete_dashboardscreen_by_screenid(self,screenid):
        """
        根据dashboardscreen_screenid删除该dashboardscreen
        screenid：表示screen ID
        """
        uri = "api/v1/dashboard/screen/{screen_pid}".format(screen_pid=str(screenid))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def update_dashboardscreen_by_screenid(self,screenid, name, pid):
        """
        根据dashboardscreen_screenid更新该dashboardscreen
        screenid：表示screen ID
        """
        uri = "api/v1/dashboard/screen/{screen_pid}".format(screen_pid=str(screenid))
        data = {"name":name,"pid":pid}
        return self.request(uri, data, "PUT", trans="data")

    @wap
    def create_tmpgraph(self,endpoints,counters):
        """
        为screen创建一个tmpgraph
        endpoints：list类型
        counters：list类型
        """
        uri = "api/v1/dashboard/tmpgraph"
        data = {"Endpoints":endpoints,"Counters":counters}
        return self.request(uri, data, "POST")

    @wap
    def create_graph_to_screen(self,screen_id,title,endpoints,counters,timespan,graph_type,method,position,falcon_tags):
        """
        为screen创建一个graph
        screen_id：screen ID
        title：graph名
        endpoints：list
        counters：list
        timespan：时间区段
        graph_type：视角，h（endpoint视角）,k（counter视角），a（combo视角）
        method：SUM或者NULL
        position：排序，预设值为0
        falcon_tags：string
        """
        uri = "api/v1/dashboard/graph"
        data = {"ScreenId":screen_id,"Title":title,"Endpoints":endpoints,"Counters":counters,"Timespan":timespan,"GraphType":graph_type,"Method":method,"Position":position,"FalconTags":falcon_tags}
        return self.request(uri, data, "POST")

    @wap
    def delete_graph(self,graphid):
        """
        根据graphid删除该graph
        """
        uri = "api/v1/dashboard/graph/{graphid}".format(graphid=str(graphid))
        data = {}
        return self.request(uri, data, "DELETE")

    @wap
    def get_dashboardgraph_by_id(self,graphid):
        """
        根据什么graphid获取graph信息
        """
        uri = "api/v1/dashboard/graph/{graphid}".format(graphid=str(graphid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_tmpgraph_by_id(self, tmpid):
        """
        根据tmpid获取tmpgraph信息
        """
        uri = "api/v1/dashboard/tmpgraph/{tmpid}".format(tmpid=str(tmpid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def get_graph_by_screenid(self, screenid):
        """
        获取该screen下所有的graph
        """
        uri = "api/v1/dashboard/graphs/screen/{screenid}".format(screenid=str(screenid))
        data = {}
        return self.request(uri, data, "GET")

    @wap
    def update_dashboardgraph_by_graphid(self,graphid,counters,falcon_tags):
        """
        通过graphid更新该dashboardgraph
        """
        uri = "api/v1/dashboard/graph/{graphid}".format(graphid=str(graphid))
        data = {"Counters":counters,"FalconTags":falcon_tags}
        return self.request(uri, data, "PUT")
        

if __name__ == "__main__":
    ofalcon = OFALCON_API("192.168.183.130", "8080", "root", "duoyi") 
    ##通过graphid更新该dashboardgraph
    #print(ofalcon.update_dashboardgraph_by_graphid(2,["t1","t2"],"haha"))
    ##获取该screen下所有的graph
    #print(ofalcon.get_graph_by_screenid(569))
    ##根据什么graphid获取graph信息
    #print(ofalcon.get_dashboardgraph_by_id(2))
    ##根据tmpid获取tmpgraph信息
    #print(ofalcon.get_tmpgraph_by_id(569))
    ##删除一个graph
    #print(ofalcon.delete_graph(1))
    ##创建一个graph
    #print(ofalcon.create_graph_to_screen(7,"test_graph1",["docker1","docker2"],["c1","c2"],1800,"h","AVG",0,"haha"))
    ##为screen创建一个tmpgraph
    #print(ofalcon.create_tmpgraph(["docker1","docker2"],["c1","c2"]))
    ##根据dashboardscreen_screenid更新该dashboardscreen
    #print(ofalcon.update_dashboardscreen_by_screenid(6,"rename3",0))
    ##根据dashboardscreen_screenid删除该dashboardscreen
    #print(ofalcon.delete_dashboardscreen_by_screenid(4))
    ##根据dashboardscreen_pid获取所有子dashboardscreen
    #print(ofalcon.get_dashboardscreen_by_pid(0))
    ##根据dashboardscreen_screenid获取该dashboardscreen
    #print(ofalcon.get_dashboardscreen_by_screenid(4))
    ##获取所有的dashboardscreen
    #print(ofalcon.get_dashboardscreen_list())
    ##创建dashboardscreen
    #print(ofalcon.create_dashboardscreen("haha2",0))
    ##获取一个主机组内的aggregator
    #print(ofalcon.get_aggregator_by_hostgroupid(17))
    ##通过aggregatorid删除该aggregator
    #print(ofalcon.delete_aggregator_by_aggregatorid(1))
    ##通过aggregatorid获取该aggregator信息
    #print(ofalcon.get_aggregator_by_aggregatorid(2))
    ##为一个主机组更新aggregator
    #print(ofalcon.update_aggregator_by_aggregatorid(2,"testenp_rename","test.idle_rename","tag_rename",190,"fdsa_rename","8"))
    ##为一个主机组创建aggregator
    #print(ofalcon.create_aggregator_to_hostgroup("testenp1","test.idle","tag",80,"17","fdsa","2"))
    ##删除用户
    #print(ofalcon.delete_user(1))
    ##修改用户密码
    #print(ofalcon.change_user_pwd(1,"duoyi"))
    ##验证session
    #print(ofalcon.auth_session())
    ##修改用户权限
    #print(ofalcon.change_user_role(1,"no"))
    ##获取所有expression列表
    #print(ofalcon.get_expression_list())
    ##通过expression_id获取该expression信息
    #print(ofalcon.get_expression_info_by_id(1))
    ##通过expression_id删除该expression
    #print(ofalcon.delete_expression(1))
    ##根据expression_id升级expression
    #print(ofalcon.update_expression(2,"each(metric=agent.alive endpoint=docker)","2",3,0,"==","this is note",4,"all(#4)",["root","TSpace"],"http://2.3.4.5/haha",1,1,1,1,1))
    ##创建一个expression
    #print(ofalcon.create_expression("each(metric=agent.alive endpoint=docker)","2",3,1,"==","this is note",4,"all(#4)",["root","TSpace"],"http://2.3.4.5/haha",1,1,1,1,1))
    ##获取该主机所在的组
    #print(ofalcon.get_related_hostgroup_of_host(24))
    ##获取该主机所绑定的模板
    #print(ofalcon.get_bind_template_of_host(24))
    ##取消维修
    #print(ofalcon.delete_maintain_by_ids_or_hostnames(["server","test3"],0))
    #print(ofalcon.delete_maintain_by_ids_or_hostnames([24,2],1))
    ##设置维修时间
    #print(ofalcon.set_maintain_by_ids_or_hostnames(["server","test3"],0,1539065935,1539067935))
    #print(ofalcon.set_maintain_by_ids_or_hostnames([24,2],1,1539065935,1539067935))
    ##通过hostgroupid删除该主机组
    #print(ofalcon.delete_hostgroup(35))
    ##将template从hostgroup解绑
    #print(ofalcon.unbind_template_on_hostgroup(35,11))
    ##通过该主机组id获取该主机组绑定的模板
    #print(ofalcon.get_templatelist_of_hostgroup(35))
    ##将host从hostgroup解绑
    #print(ofalcon.unbind_host_on_hostgroup(35,23))

    ##通过hostgroupid更新hostgroup信息
    #print(ofalcon.update_hostgroup(17,"testt"))

    ##通过nodataid删除nodata
    #print(ofalcon.delete_nodata_by_nodataid(10))
    ##通过nodataid获取nodata信息
    #print(ofalcon.get_nodata_info_by_nodataid(10))
    ##通过nodataid更新nodata
    #print(ofalcon.update_nodata(10,"tagtag",80,"group",["docker1","docker2","docker3"],-2,"test.metric.1","GAUGE"))
    ##获取nodata列表
    #print(ofalcon.get_nodata_list())
    ##创建nodata
    #print(ofalcon.create_nodata("tag",60,"host",["docker-agent1","docker-agent2","docker-agent3"],"test4nodata",-1,"test.metric","GAUGE"))
    ##为一个主机组创建plugin
    #print(ofalcon.create_plugin(35,"pp/tt"))
    ##通过hostgroup id 获取绑定的plugins列表
    #print(ofalcon.get_pluginlist_by_hostgroupid(35))
    ##通过plugin id 删除该plugin
    #print(ofalcon.delete_plugin(2))
    ##获取内置的监控项列表,基于./data/metric文件
    #print(ofalcon.get_default_metriclist())
    ##通过strategyid更新该strategy信息
    #print(ofalcon.update_strategy(16,"woshitags","24:00","01:00","3",4,"<","woshinote","cpu.busy1",2,"all(#2)"))
    ##通过template id获取strategy列表
    #print(ofalcon.get_strategy_list(12))
    ##通过strategyid获取该strategy信息
    #print(ofalcon.get_strategyinfo_by_id(16))
    ##通过strategyid删除该strategy
    #print(ofalcon.delete_strategy(21))
    ##更新team信息
    #print(ofalcon.update_team(21,"tttt","wo shi shui",[1,3]))
    ##获取team列表
    #print(ofalcon.get_team_list(".+"))
    ##根据team名获取team详细信息
    #print(ofalcon.get_teaminfo_by_name("test"))
    ##根据team_id获取team相信信息
    #print(ofalcon.get_teaminfo_by_teamid(21))
    ##根据team_id删除team
    #print(ofalcon.delete_team_by_teamid(22))
    ##根据actionid更新action行为
    #print(ofalcon.update_template_action(15,["test","test2",],"http://127.0.0.1/haha1",1,0,0,0,0))
    ##创建模板action
    #print(ofalcon.create_template_action(12,["test","test2","testhostgroup"],"http://127.0.0.1/haha",0,1,1,1,1))
    ##通过tpl_id删除该模板
    #print(ofalcon.delete_template(13))
    ##通过tpl_id获取某一模板绑定的主机组
    #print(ofalcon.get_hostgrouplist_by_tmpid(11))
    ##通过tpl_id获取template信息
    #print(ofalcon.get_templateinfo_by_tmpid(12))
    ##通过tpl_id更新template名或者父模板ID
    #print(ofalcon.update_template_by_tmpid(11,"testrename",16))
    ##修改当前用户密码
    #print(ofalcon.change_user_passwd("duoyi","duoyiduoyi"))
    ##创建新用户
    #print(ofalcon.create_user("tt1","duoyi","你猜","123@qq.com","1","2","3"))
    ##通过用户名获取用户信息
    #print(ofalcon.get_user_info_by_name("TSpace"))
    ##通过用户ID获取用户信息
    #print(ofalcon.get_user_info_by_id(1))
    ##获取该用户所在的组
    #print(ofalcon.get_user_teams("3"))
    ##判断用户是否在某个组内
    #print(ofalcon.check_user_in_teams(3,["test","test4userteam"]))
    ##登出
    #print(ofalcon.logout())
    ##获取用户列表
    #print(ofalcon.get_userlist())
    ##更新当前用户信息
    #print(ofalcon.update_user(cnname="希望1", email="1@qq.com", im="2", phone="3", qq= "4" ))
    ##获取endpoint信息，包括endpoint id,传入.+参数时，获取所有主机信息
    #endpointinfo = ofalcon.get_endpointid_by_ip_or_endpoint("server")
    #endpointinfo = ofalcon.get_endpointid_by_ip_or_endpoint(".+")
    #print(endpointinfo)
    #endpointid = endpointinfo[0]["id"]
    #print(endpointid)
    ##获取endpoint的所有监控项目
    #endpoint_counter = ofalcon.get_endpoint_counter_by_endpointid(endpointid)
    #print(endpoint_counter)
    ##获取某个监控项目的历史数据
    #history_graph = ofalcon.get_history_by_counters_and_endpoints_or_ips(["agent.alive","cpu.busy"],["server","127.0.0.1"],etime=1537323834, stime=1537320276)
    #from pprint import pprint
    #pprint(history_graph)
    ##创建主机组
    #hostgroup = ofalcon.add_hostgroup("test2")
    #print(hostgroup)
    ##将主机添加到主机组
    #print(ofalcon.add_host_to_hostgroup(["OFacon","server"],17))
    ##获取所有主机组信息
    #print(ofalcon.get_hostgrouplist())
    ##根据主机组ID获取特定主机组信息
    #print(ofalcon.get_hostgroupinfo_by_id(35))
    ##创建模板
    #print(ofalcon.add_template("testtemplate2",1))
    ##获取模板列表
    #print(ofalcon.get_templatelist())
    ##为模板增加监控项
    #print(ofalcon.add_strategy_to_template_by_templateid(2,"cpu.free",">=","40","all(#3)",1,3,"this is test","","01:00","23:00")) 
    ##将模板关联到主机组
    #print(ofalcon.add_template_to_hostgroup(2,1))
    ##增加用户组，同时可关联用户
    #print(ofalcon.add_team("test4userteam",[1],"I'm descript"))
    ##获取当前token代表的用户信息
    #print(ofalcon.get_current_userinfo())
    ##获取告警case列表
    #print(ofalcon.get_eventcases_list(startTime=0,endTime=int(time.time()),process_status="unresolved",limit=10))
    ##根据event_id获取eventcase信息
    #print(ofalcon.get_eventcases_by_id("s_15_d7c33411cffbd4f4ca0a0db6c4c32805"))
    ##通过时间段或者eventID获取eventnote
    #print(ofalcon.get_eventnote_by_time_or_eventid(event_id="s_15_d7c33411cffbd4f4ca0a0db6c4c32805"))
    ##为某个事件创建eventnote
    #print(ofalcon.create_eventnote("s_15_d7c33411cffbd4f4ca0a0db6c4c32805","111111","comment"))
    ##获取某个事件ID对应的告警时的所有告警状态值
    #print(ofalcon.get_event("s_13_1d83ccd1aa9d3eaed1d944afa92f3870"))
    ##为某个主机组更新主机信息
    #print(ofalcon.update_hosts_in_hostgroup(17,"add",["test3","test4"]))
